# Cracked passwords bloomfilter: Yogesh Mundada (yhm@cc.gatech.edu)
#
# It will create a huge passwords bloom filter.
# However, will do so intelligently. It will split the 50 GB of
# bloomfilter array into files of 1MB each.
# It will generate a file only if at least one bit is set in that
# file. 
#
# It will also add a version at the top of each file.
# Thus when a new cracked password DB is added to the file, the
# version is changed. This way the extension would know that the
# password bloomfilter is updated and request the latest files.
#
# To resume a particular pwd processing, the file when interrupted
# should after each successful iteration:
# 1. Name of the pwd file being processed
# 2. sha1sum of the file
# 3. Index of password processed
# 4. Total passwords present
# 5. Percentage completion
# 6. is_version_updated
# 7. total time spent so far
#
# When resuming work, it will continue from same position.
# However, if sha1sum of the original file is changed, then
# it will discard all this information and start from the beginning.

import pdb
import json
import socket
import struct
import datetime
import hashlib
import math
import os
import subprocess
from optparse import OptionParser
import re
import datetime
import time
import multiprocessing
from Queue import Empty

comm_mgr = multiprocessing.Manager()

shared_bits_dict = comm_mgr.dict()
number_bits_dict = comm_mgr.dict()
# The following queue is such that a disk-writer 
# process knows what keys are present in the shared
# shared_bits_dict. This is so that you don't have
# to run shared_bits_dict.keys() since this dict
# will keep changing as writers will delete the keys
# after flushing files to the disk.
queued_files = multiprocessing.Queue()
tot_files_to_flush = multiprocessing.Value('d', 0)
# Following lock is a mutex for all above three shared
# variables. If one wants to change any value in above 
# three, first get the following lock.
lk_bits_dict = multiprocessing.Lock()

lk_dir_create = multiprocessing.Lock()

# Default number of threads
NUM_THREADS = 8

pwdq = multiprocessing.Queue()
ev_cont_read_pwd = multiprocessing.Event()
ev_flush_bits = multiprocessing.Event()
ev_terminate = multiprocessing.Event()
ev_error = multiprocessing.Event()

# Flush the bits in the bit_vector after number of
# entries are greater than MAX_PWDS_TO_PROCESS_AT_A_TIME
MAX_PWDS_TO_PROCESS_AT_A_TIME = 10000
MAX_FILES_TO_FLUSH = MAX_PWDS_TO_PROCESS_AT_A_TIME * 5

bit_vector = []

# 50GB at the server
BLOOMFILTER_SIZE = (2**30) * 50

# Total bloomfilter bits in those 50GB
TOTAL_BITS = (BLOOMFILTER_SIZE * 8) 


ERR_FILE_LOCK = comm_mgr.Lock()
ERR_FILE = "errors.txt"

# File size in bytes (10K)
FILE_SIZE = (2**10) * 10

# Bloomfilter bits in each file
BITS_PER_FILE = FILE_SIZE * 8

# Total files in each directory.
FILES_PER_DIR = 5120

# Total directories
TOT_DIR = 1024

# Expected false positives for bloomfilter 50GB long,
# 10 hash functions and 400 million cracked passwords
# m = 429496729600
# n = 400,000,000
# k = 10
# P(fp) = (1 - e^[-kn/m])^k
# P(fp): 4.545514287009533e-21
BF_SUBDIR = "bloomfilters/"

BLOOMFILTER_METADATA = "metadata.bloomfilter"

DEFAULT_FNAME = BF_SUBDIR + "default"

metadata = {}

epoch_number = 10
# I assume that the bloom filter is array of bits rather than bytes.
# Thus it will be stored in littel-endian way (Least significant byte at a lowest address).
# However, inside an individual byte, I also assume that least-significant-bit is stored
# at a least-significant-address (visually from left-to-right).
# Thus, the 8th bit is least-significant-address. So if we want to set 8th bit then
# we OR it with 128.
bit_set_lookup = [
    128,
    64,
    32,
    16,
    8,
    4,
    2,
    1
]

# While processing a cracked-pwd-db, it is possible that a particular file
# gets updated more than once. In such a case, we just want to change the
# version string only once. This data-structure maintains that info.
is_version_updated = {}
lk_is_version_updated = multiprocessing.Lock()

# Returns 10 hash values from 10 hash-functions
# Check: http://www.eecs.harvard.edu/~kirsch/pubs/bbbf/rsa.pdf
def get_hashed_values(data):
    rc = []
    h1 = hashlib.sha1(data).hexdigest()
    h2 = hashlib.sha256(data).hexdigest()
    for i in range(10):
        fh = hashlib.sha256("%s%s%s" % (h1, i, h2)).hexdigest()
        rc.append(fh)
    return rc

# Accepts hashes as input and returns a dictionary with
# key as each hash-value and data as
# "fname" : "dirXYZ/bloomfilter"
# "position" : index of bit position
def get_bit_positions(hashes):
    hash_locations = {}
    for i in range(len(hashes)):
        # bit_number will range from ZERO to (TOTAL_BITS-1)
        bit_number = int(hashes[i], 16) % TOTAL_BITS

        # File numbers range from 0 to 51199
        file_number = int(math.ceil((bit_number + 1.0) / BITS_PER_FILE)) - 1

        bit_position = bit_number % BITS_PER_FILE

        # Directory numbers range from 0 to 511
        dir_number = int(math.ceil((file_number + 1.0) / FILES_PER_DIR)) - 1
        hash_locations[hashes[i]] = {
            "fname": str(file_number),
            "dname": str(dir_number),
            "bitpos": bit_position,
            }
    return hash_locations

# Accepts a dictionary with
# key as each hash-value and data as
# "fname" : "dirXYZ/bloomfilter"
# "dname" : "dirXYZ"
# "bitpos" : index of bit position
# All the bitpositions correspond to one single password.
#
# It will first check if the directory exists, if not, it will create it
# It will check if file exists, if not, it will create it and add a version '0.0.1'
# If file exists, then it will read the version string and increment it from 'x.y.z' to 'x.y.z+1'
# Read the already number of set bits and increment it
# Set the actual bit and write the file to the disk
# Also write a gzipped version of the file to the disk
def set_bit_positions(positions, resuming_from_partial_run):
    existing_pwd = True
    tot_new_bits = 0
    tot_new_files = 0
    tot_files_written_to = 0
    for p in positions:
        dname = BF_SUBDIR + positions[p]["dname"]
        fname = dname + "/" + positions[p]["fname"]
        bitpos = positions[p]["bitpos"]
        if not os.path.isdir(dname):
            os.makedirs(dname)

        fbuf = None
        version = None
        setbits = None
        if not os.path.isfile(fname):
            fbuf = [0] * FILE_SIZE
            version = "0.0.0"
            setbits = 0
            tot_new_files += 1
        else:
            fd = open(fname, "r")
            fdata = fd.read()
            lines = fdata.split("\n")
            if "<version>" not in lines[0] or "</version>" not in lines[0]:
                print "Error: Version information corrupt for: %s" % (fname)
                exit(-1)
            version = lines[0].split("<version>")[1].split("</version>")[0]

            if "<setbits>" not in lines[1] or "</setbits>" not in lines[1]:
                print "Error: Setbits information corrupt for: %s" % (fname)
                exit(-1)
            setbits = int(lines[1].split("<setbits>")[1].split("</setbits>")[0])

            if "<bits>" not in lines[2] or "</bits>" not in lines[2]:
                print "Error: Bit data not present for: %s" % (fname)
                exit(-1)
            bits = lines[2].split("<bits>")[1].split("</bits>")[0]
            fbuf = list(struct.unpack("<%dB" % (FILE_SIZE), bits))

        byte_number = int(math.ceil((bitpos + 1.0)/ 8)) - 1
        bitpos_inside_byte = bitpos % 8

        rc = set_bit_in_array(fbuf, byte_number, bitpos_inside_byte)
        if rc == False:
            # We probably set an already set bit. No change. 
            # Do not write the file to the disk.
            if resuming_from_partial_run:
                existing_pwd = False
                tot_new_bits += 1
                if fname in is_version_updated:
                    pass
                else:
                    # update the version
                    tot_files_written_to += 1
                    version_triples_str = version.split(".")
                    version_triples = map(lambda x: int(x), version_triples_str)
                    version_triples[-1] += 1
                    version = "%d.%d.%d" % (version_triples[0], version_triples[1], version_triples[2])
                    is_version_updated[fname] = True
                    write_file_to_disk(fname, version, setbits, fbuf)
            continue
        else:
            # This means at the least one bit is different in this password.
            # Thus we have not seen this password before
            existing_pwd = False
            tot_new_bits += 1
            # Array is modified. Need to flush it to disk.
            # Check whether we need to update the version string as well.
            setbits += 1
            # Check if we need to increment version for this file or if
            # has been already incremented
            if fname in is_version_updated:
                # Do nothing, just write the file back
                pass
            else:
                # update the version
                tot_files_written_to += 1
                version_triples_str = version.split(".")
                version_triples = map(lambda x: int(x), version_triples_str)
                version_triples[-1] += 1
                version = "%d.%d.%d" % (version_triples[0], version_triples[1], version_triples[2])
                is_version_updated[fname] = True
            write_file_to_disk(fname, version, setbits, fbuf)
    return existing_pwd, tot_new_bits, tot_new_files, tot_files_written_to


### Using multiprocessing to speed-up -- START

def set_multiple_bits_in_array(fbuf, bitpos_list):
    tot_modified = 0
    for p in range(len(bitpos_list)):
        byte_number = int(math.ceil((bitpos_list[p] + 1.0)/ 8)) - 1
        bitpos_inside_byte = bitpos_list[p] % 8
        orig_byte = fbuf[byte_number]
        fbuf[byte_number] = orig_byte | bit_set_lookup[bitpos_inside_byte]
        if fbuf[byte_number] != orig_byte:
            tot_modified += 1
    return tot_modified

def write_multiple_bits_to_file(dname, fname, bitpos_list, pwd_list):
    with lk_dir_create:
        if not os.path.isdir(dname):
            os.makedirs(dname)

    fbuf = None
    version = None
    setbits = None
    if not os.path.isfile(fname):
        fbuf = [0] * FILE_SIZE
        version = "0.0.0"
        setbits = 0
    else:
        fd = open(fname, "r")
        fdata = fd.read()
        lines = fdata.split("\n")
        if "<version>" not in lines[0] or "</version>" not in lines[0]:
            print "Error: Version information corrupt for: %s" % (fname)
            with ERR_FILE_LOCK:
                efd = open(ERR_FILE, "a")
                efd.write("Error: Version information corrupt for: %s, pwd_list: %s, bitpos_list: %s\n" % \
                              (fname, str(pwd_list), str(bitpos_list)))
                efd.close()
            ev_error.set()
            exit(-1)
        version = lines[0].split("<version>")[1].split("</version>")[0]

        if "<setbits>" not in lines[1] or "</setbits>" not in lines[1]:
            print "Error: Setbits information corrupt for: %s" % (fname)
            with ERR_FILE_LOCK:
                efd = open(ERR_FILE, "a")
                efd.write("Error: Setbits information corrupt for: %s, pwd_list: %s, bitpos_list: %s\n" % \
                              (fname, str(pwd_list), str(bitpos_list)))
                efd.close()
            ev_error.set()
            exit(-1)
        setbits = int(lines[1].split("<setbits>")[1].split("</setbits>")[0])

        if "<bits>" not in lines[2] or "</bits>" not in lines[2]:
            print "Error: Bit data not present for: %s" % (fname)
            with ERR_FILE_LOCK:
                efd = open(ERR_FILE, "a")
                efd.write("Error: Bit data not present for: %s, pwd_list: %s, bitpos_list: %s\n" % \
                              (fname, str(pwd_list), str(bitpos_list)))
                efd.close()
            ev_error.set()
            exit(-1)
        bits = lines[2].split("<bits>")[1].split("</bits>")[0]
        fbuf = list(struct.unpack("<%dB" % (FILE_SIZE), bits))

    tot_modified = set_multiple_bits_in_array(fbuf, bitpos_list)

    if tot_modified == 0:
        # We probably set an already set bit. No change. 
        # Do not write the file to the disk.
        # if resuming_from_partial_run:
        #     existing_pwd = False
        #     tot_new_bits += 1
        #     if fname in is_version_updated:
        #         pass
        #     else:
        #         # update the version
        #         tot_files_written_to += 1
        #         version_triples_str = version.split(".")
        #         version_triples = map(lambda x: int(x), version_triples_str)
        #         version_triples[-1] += 1
        #         version = "%d.%d.%d" % (version_triples[0], version_triples[1], version_triples[2])
        #         is_version_updated[fname] = True
        #         write_file_to_disk(fname, version, setbits, fbuf)
        #         continue
        pass
    else:
        # This means at the least one bit is different in this password.
        # Thus we have not seen this password before
        # existing_pwd = False
        # tot_new_bits += 1

        # Array is modified. Need to flush it to disk.
        # Check whether we need to update the version string as well.
        setbits += tot_modified

        # Check if we need to increment version for this file or if
        # has been already incremented
        with lk_is_version_updated:
            if fname in is_version_updated:
                # Do nothing, just write the file back
                pass
            else:
                # update the version
                version_triples_str = version.split(".")
                version_triples = map(lambda x: int(x), version_triples_str)
                version_triples[-1] += 1
                version = "%d.%d.%d" % (version_triples[0], version_triples[1], version_triples[2])
                is_version_updated[fname] = True
        write_file_to_disk(fname, version, setbits, fbuf)


def flush_bits_to_disk(my_num, tot_files_to_flush):
    FILE_LOCKS = {}
    pool = multiprocessing.Pool(processes=50)
    while True:
        rc = ev_flush_bits.wait(1)
        if rc != True:
            if queued_files.qsize() == 0:
                if ev_terminate.is_set():
                    print "flush_bits_to_disk(%d): Exiting as terminate is set" % (my_num) 
                    pool.close()
                    pool.join()
                    exit(0)
                if ev_error.is_set():
                    print "flush_bits_to_disk(%d): Exiting as error is set" % (my_num) 
                    pool.close()
                    pool.join()
                    exit(-1)
            continue
        try:
            # print "flush_bits_to_disk(%d): Trying to get file from queue, files to flush: %d, Qsize: %d" % \
            #     (my_num, tot_files_to_flush.value, queued_files.qsize())
            fname = queued_files.get(True, 1)
            # print "flush_bits_to_disk(%d): Got the file, now going to get lock" % \
            #     (my_num)
            with lk_bits_dict:
                dname = shared_bits_dict[fname]["dname"]
                pwd_list = shared_bits_dict[fname]["pwd_list"]
                bitpos_list = shared_bits_dict[fname]["bitpos_list"]
                del shared_bits_dict[fname]
                if fname not in FILE_LOCKS:
                    FILE_LOCKS[fname] = comm_mgr.Lock()
                tot_files_to_flush.value -= 1
                if tot_files_to_flush.value == 0:
                    ev_flush_bits.clear()
                    ev_cont_read_pwd.set()

            if len(pwd_list) == 0 or len(bitpos_list) == 0:
                ev_error.set()
                print "flush_bits_to_disk(%d): Terminating as no pwd_list or bitpos_list" % (my_num)
                exit(-1)

            if len(bitpos_list) > 1:
                print "flush_bits_to_disk(%d): (files to flush: %d) Got a pending file: %s, pwd_list: %s, bitpos_list: %s" % \
                    (my_num, tot_files_to_flush.value, str(fname), str(pwd_list), str(bitpos_list))

            with FILE_LOCKS[fname]:
                pool.apply_async(write_multiple_bits_to_file, (dname, fname, bitpos_list, pwd_list))
                #p = multiprocessing.Process(target=write_multiple_bits_to_file, args=([dname, fname, bitpos_list, pwd_list]))
                #p.start()
            # write_multiple_bits_to_file(dname, fname, bitpos_list)
        except Empty:
            # print "flush_bits_to_disk(%d): No files found: %d" % (my_num, tot_files_to_flush.value)
            continue
        except Exception as e:
            print "flush_bits_to_disk(%d): Exception occurred: %s" % (my_num, str(e))
            ev_error.set()
            print "flush_bits_to_disk(%d): Exiting due to error" % (my_num)
            exit(-1)

def calculate_hashes(my_num, tot_files_to_flush):
    while True:
        try:
            pw = pwdq.get(True, 1)
            #print "calculate_hashes(%d): Got a password: %s" % (my_num, pw)
            hashes = get_hashed_values(pw)
            bit_positions = get_bit_positions(hashes)
            with lk_bits_dict:
                for p in bit_positions:
                    dname = BF_SUBDIR + bit_positions[p]["dname"]
                    fname = dname + "/" + bit_positions[p]["fname"]
                    bitpos = bit_positions[p]["bitpos"]
                    if fname not in shared_bits_dict:
                        nd = comm_mgr.dict()
                        pwd_list = comm_mgr.list()
                        bitpos_list = comm_mgr.list()
                        nd["dname"] = dname
                        nd["pwd_list"] = pwd_list
                        nd["bitpos_list"] = bitpos_list
                        shared_bits_dict[fname] = nd
                        queued_files.put(fname)
                        tot_files_to_flush.value += 1
                        if tot_files_to_flush.value > MAX_FILES_TO_FLUSH:
                            ev_flush_bits.set()
                        # print "calculate_hashes(%d): Adding new file to file queue: %s" % \
                        #     (my_num, fname)
                    
                    nd = shared_bits_dict[fname]
                    pwd_list = nd["pwd_list"]
                    bitpos_list = nd["bitpos_list"]

                    pwd_list.append(pw)
                    bitpos_list.append(bitpos)

                    nd["pwd_list"] = pwd_list
                    nd["bitpos_list"] = bitpos_list
                    shared_bits_dict[fname] = nd
                    # print "Here here: Pwd_list value: %s, %s" % (pw, str(shared_bits_dict[fname]['pwd_list']))
                    # print "Here here: Bitpos_list value: %s, %s" % (pw, str(shared_bits_dict[fname]['bitpos_list']))
                    # print "calculate_hashes(%d): Calculated bits(passwd=%s, fname=%s), Dict entry: %s" % \
                    #     (my_num, pw, fname, str(shared_bits_dict[fname]))
        except Empty:
            if ev_terminate.is_set():
                print "calculate_hashes(%d): Exiting as terminate is set" % (my_num) 
                ev_flush_bits.set()
                exit(0)
            if ev_error.is_set():
                print "calculate_hashes(%d): Exiting as error is set" % (my_num) 
                ev_flush_bits.set()
                exit(-1)
            print "calculate_hashes(%d): Nothing read from the Queue" % (my_num)
            continue
        except Exception as e:
            print "calculate_hashes(%d): Exception occurred: %s" % (my_num, str(e))
            ev_error.set()
            print "calculate_hashes(%d): Exiting due to error" % (my_num)
            exit(-1)


def read_pwds(cracked_pwd_file):
    tot_read_pwds = 0
    all_pwds = {}
    with open(cracked_pwd_file, "r") as cpf:
        for line in cpf:
            if line[-1] == '\n':
                line = line[:-1]
            pwd = line.rstrip()    
            if pwd not in all_pwds:
                all_pwds[pwd] = True
                pwdq.put(pwd)
                tot_read_pwds += 1
            # print "read_pwds(): Read %d passwords, Total files to flush: %d" % \
            #     (tot_read_pwds, tot_files_to_flush.value)

            if tot_files_to_flush.value > MAX_FILES_TO_FLUSH or \
                    (tot_read_pwds * 10) > (MAX_FILES_TO_FLUSH):
                print "read_pwds(): Read %d passwords, Total files to flush: %d, going to sleep" % \
                    (tot_read_pwds, tot_files_to_flush.value)
                ev_cont_read_pwd.wait()
                print "$$$$$$$$$$$$$$ Signal to read more pwds"
                tot_read_pwds = 0
                ev_cont_read_pwd.clear()
    print "Read all passwords, setting terminate: %d" % (tot_read_pwds)
    ev_terminate.set()
    return

### Using multiprocessing to speed-up -- END
# Construct a special file for those files that do not exist.
# Whenever we do not find any file, we send this file.
# This will contain no bits set and version is "0.0.0"
def create_default_bloomfilter_file():
    if not os.path.isfile(DEFAULT_FNAME):
        fbuf = [0] * FILE_SIZE
        version = "0.0.0"
        setbits = 0
        write_file_to_disk(DEFAULT_FNAME, version, setbits, fbuf)

# Write the bloom filter to disk
def write_file_to_disk(fname, version, setbits, fbuf):
    fname_tmp = fname + "_tmp"
    fd = open(fname_tmp, "w+")
    fd.write("<version>%s</version>\n" % version)
    fd.write("<setbits>%s</setbits>\n" % setbits)
    fdata = struct.pack("<%dB" % (FILE_SIZE), *fbuf)
    fd.write("<bits>%s</bits>\n" % fdata)
    fd.close()
    os.rename(fname_tmp, fname)
    rc = convert_to_zip(fname)
    if rc != 0:
        print "Error: Converting file to ZIP: %s" % (fname)
        exit(-1)

    rc = convert_to_base64(fname)
    if rc != 0:
        print "Error: Converting file to base64: %s" % (fname)
        exit(-1)

    return True

def convert_to_zip(fname):
    try:
        DEVNULL = open(os.devnull, "w")
        rc = subprocess.call(["/usr/bin/zip", "%s.zip" % (fname), fname], stdout=DEVNULL)
        DEVNULL.close()
    except subprocess.CalledProcessError, e:
        print "Error: Problem zipping file: %s" % (fname)
        exit(-1)

    if rc != 0:
        return -1
    return 0


def convert_to_base64(fname):
    try:
        rc = subprocess.call(["/usr/local/bin/node", "./base64_converter.js", "%s.zip" % (fname)])
    except subprocess.CalledProcessError, e:
        print "Error: Problem converting to base64: %s" % (fname)
        exit(-1)

    if rc != 0:
        return -1

    return 0


# Returns whether the array is modified or not
def set_bit_in_array(fbuf, byte_number, bitpos_inside_byte):
    orig_byte = fbuf[byte_number]
    fbuf[byte_number] = orig_byte | bit_set_lookup[bitpos_inside_byte]
    if fbuf[byte_number] == orig_byte:
        return False
    return True


def get_resume_filename(cracked_pwd_file):
    fields = cracked_pwd_file.split("/")
    fields[-1] = "resume." + fields[-1]
    fname = "/".join(fields)
    return fname


# Process json file
def process_resume_file(cracked_pwd_file, extra_check=True):
    if extra_check == True:
        fname = get_resume_filename(cracked_pwd_file)
    else:
        fname = cracked_pwd_file

    with open(fname, "r") as rcpf:
        pi = json.load(rcpf)
        
    try:
        rc = subprocess.check_output(["/usr/bin/sha1sum", cracked_pwd_file])    
    except subprocess.CalledProcessError, e:
        print "Error: Problem calculating sha1sum: %s" % (str(e))
        exit(-1)
    sha1sum = rc.split(' ')[0]

    if extra_check == False:
        return pi

    if pi["name"] != cracked_pwd_file:
        print "Error: Name mismatch (%s, %s)" % (pi["name"], cracked_pwd_file)
        exit(-1)
    if pi["sha1sum"] != sha1sum:
        print "Error: Sha1sum mismatch (%s, %s)" % (pi["sha1sum"], sha1sum)
        exit(-1)
    return pi


def create_resume_file(cracked_pwd_file, processed_info):
    processed_info["name"] = cracked_pwd_file
    try:
        rc = subprocess.check_output(["/usr/bin/sha1sum", cracked_pwd_file])    
    except subprocess.CalledProcessError, e:
        print "Error: Problem calculating sha1sum: %s" % (str(e))
        exit(-1)

    processed_info["sha1sum"] = rc.split(' ')[0]

    try:
        rc = subprocess.check_output(["/usr/bin/wc", "-l", cracked_pwd_file])    
    except subprocess.CalledProcessError, e:
        print "Error: Problem counting passwords: %s" % (str(e))
        exit(-1)

    processed_info["tot_pwds"] = int(rc.split(' ')[0])

    return


# Dump the json structure
def update_resume_file(cracked_pwd_file, processed_info):
    fname = get_resume_filename(cracked_pwd_file)
    with open(fname, "w+") as rcpf:
        json.dump(processed_info, rcpf)
    return


# Runs over all bloom filter files and checks if <setbits> matches
# with actual number of bits set.
# Also prints which bit numbers are set in each file.
def cross_check_bloom_filters():
    metadata = get_meta_information()
    tot_files_skipped = 0
    tot_dir_skipped = 0
    tot_correct_files = 0
    tot_corrupt_files = 0
    tot_bits_set = 0
    tot_dir = 0
    tot_files = 0
    for i in range(TOT_DIR):
        start_file = i * FILES_PER_DIR
        end_file = i * FILES_PER_DIR + FILES_PER_DIR
        for j in range(start_file, end_file):
            dname = BF_SUBDIR + str(i)
            fname = dname + "/" + str(j)
            
            if not os.path.isdir(dname):
                tot_dir_skipped += 1
                tot_files_skipped += FILES_PER_DIR
                break
            
            if not os.path.isfile(fname):
                tot_files_skipped += 1
                continue

            fd = open(fname, "r")
            fdata = fd.read()
            lines = fdata.split("\n")
            if "<version>" not in lines[0] or "</version>" not in lines[0]:
                print "Error: Version information corrupt for: %s" % (fname)
                exit(-1)
            version = lines[0].split("<version>")[1].split("</version>")[0]

            if "<setbits>" not in lines[1] or "</setbits>" not in lines[1]:
                print "Error: Setbits information corrupt for: %s" % (fname)
                exit(-1)
            setbits = int(lines[1].split("<setbits>")[1].split("</setbits>")[0])

            if "<bits>" not in lines[2] or "</bits>" not in lines[2]:
                print "Error: Bit data not present for: %s" % (fname)
                exit(-1)
            bits = lines[2].split("<bits>")[1].split("</bits>")[0]
            fbuf = list(struct.unpack("<%dB" % (FILE_SIZE), bits))

            tot_bits = 0
            for k in xrange(len(fbuf)):
                byte = fbuf[k]
                for m in range(8):
                    if (byte & bit_set_lookup[m]) != 0:
                        tot_bits += 1

            tot_files += 1
            tot_bits_set += tot_bits
            if tot_bits != setbits:
                print "Error: Corrupt file found (file: %d, counted: %d): %s" % \
                    (setbits, tot_bits, fname)
                tot_corrupt_files += 1
            else:
                tot_correct_files += 1
                
            print "Processed file: %s" % (fname)
    print "Total directories skipped cause they don't exist: %d" % (tot_dir_skipped)
    print "Total files skipped cause they don't exist: %d" % (tot_files_skipped)
    print "Total files checked: %d" % (tot_files)
    print "Total corrupt files: %d" % (tot_corrupt_files)
    print "Total valid files: %d" % (tot_correct_files)
    if metadata["tot_bits_set"] != tot_bits_set:
        print "Error: Total bits set do not match (metadata: %d, counted: %d)" % \
            (metadata["tot_bits_set"], tot_bits_set)
    else:
        print "Counted bits match with metadata bits: GOOD"

    return


def checkdir(dirname):
    for i in range(TOT_DIR):
        start_file = i * FILES_PER_DIR
        end_file = i * FILES_PER_DIR + FILES_PER_DIR
        for j in range(start_file, end_file):
            dname = dirname + "/" + str(i)
            fname = dname + "/" + str(j)

            if not os.path.isdir(dname):
                break
            
            if not os.path.isfile(fname):
                continue

            checkfile(fname)
    return

def checkfile(fname):
    fd = open(fname, "r")
    fdata = fd.read()
    lines = fdata.split("\n")
    if "<version>" not in lines[0] or "</version>" not in lines[0]:
        print "Error: Version information corrupt for: %s" % (fname)
        exit(-1)
        
    version = lines[0].split("<version>")[1].split("</version>")[0]
        
    if "<setbits>" not in lines[1] or "</setbits>" not in lines[1]:
        print "Error: Setbits information corrupt for: %s" % (fname)
        exit(-1)
    
    setbits = int(lines[1].split("<setbits>")[1].split("</setbits>")[0])
            
    if "<bits>" not in lines[2] or "</bits>" not in lines[2]:
        print "Error: Bit data not present for: %s" % (fname)
        exit(-1)
    
    bits = lines[2].split("<bits>")[1].split("</bits>")[0]
    fbuf = list(struct.unpack("<%dB" % (FILE_SIZE), bits))
                
    tot_bits = 0
    print "Filename: %s" % (fname)
    for k in xrange(len(fbuf)):
        byte = fbuf[k]
        for m in range(8):
            if (byte & bit_set_lookup[m]) != 0:
                print "\tBit %d is set in byte %d" % (m, k)
                tot_bits += 1

    return


# Processes a passowrd file and creates corresponding bloom
# filters
def process_cracked_pwd_file(cracked_pwd_file):
    tot_processed = 0
    start_time = time.time()
    metadata = get_meta_information()
    processed_info = {
        "name" : "",
        "sha1sum" : "",
        "tot_pwds" : 0,
        "processed_pwds" : 0,
        "curr_line_num" : 0,
        "percentage_completion" : 0,
        "incomplete_transaction" : False,
        "version_updated_info" : is_version_updated
        }

    resume_cracked_pwd_file = get_resume_filename(cracked_pwd_file)
    metadata_this_pwd_db = None

    create_default_bloomfilter_file()

    resuming_from_partial_run = False
    if os.path.isfile(resume_cracked_pwd_file):
        processed_info = process_resume_file(cracked_pwd_file)
        for i in xrange(len(metadata["cracked_pwd_db"])):
            if cracked_pwd_file == metadata["cracked_pwd_db"][i]["name"] and \
                    processed_info["sha1sum"] == metadata["cracked_pwd_db"][i]["sha1sum"]:
                metadata_this_pwd_db = metadata["cracked_pwd_db"][i]
        if metadata_this_pwd_db == None:
            print "Error: Resume file found but information not present in metadata"
            exit(-1)
        if processed_info["incomplete_transaction"] == True:
            resuming_from_partial_run = True
    else:
        create_resume_file(cracked_pwd_file, processed_info)
        file_found_in_metadata = False
        for i in xrange(len(metadata["cracked_pwd_db"])):
            if cracked_pwd_file == metadata["cracked_pwd_db"][i]["name"]:
                if metadata["cracked_pwd_db"][i]["processing_done"] == True:
                    print "Error: Looks like this file is already been processed."
                    exit(-1)
                file_found_in_metadata = True

        if not file_found_in_metadata:
            metadata["cracked_pwd_db"].append({
                    "name" : cracked_pwd_file,
                    "sha1sum" : processed_info["sha1sum"],
                    "tot_pwds" : 0,
                    "tot_unique_pwds" : 0,
                    "tot_bits_set" : 0,
                    "tot_time_spent" : 0,
                    "tot_files_written_to" : 0,
                    "processing_done" : False
                    })

            metadata_this_pwd_db = metadata["cracked_pwd_db"][-1]
            metadata["tot_cracked_pwd_dbs"] += 1
            update_meta_information(metadata)

    with open(cracked_pwd_file, "r") as cpf:
        for i in xrange(processed_info["curr_line_num"]):
            cpf.next()
        for line in cpf:
            processed_info["incomplete_transaction"] = True
            update_resume_file(cracked_pwd_file, processed_info)
            process_time = time.time()
            if line[-1] == '\n':
                line = line[:-1]
            pwd = line.rstrip()    
            hashes = get_hashed_values(pwd)
            bit_positions = get_bit_positions(hashes)
            is_existing_pwd, tot_new_bits, tot_new_files, tot_files_written_to = \
                set_bit_positions(bit_positions, resuming_from_partial_run)

            time_spent = (time.time() - process_time)

            metadata_this_pwd_db["tot_pwds"] += 1
            metadata_this_pwd_db["tot_bits_set"] += tot_new_bits
            metadata_this_pwd_db["tot_time_spent"] += time_spent
            metadata_this_pwd_db["tot_files_written_to"] += tot_files_written_to

            if not is_existing_pwd:
                metadata_this_pwd_db["tot_unique_pwds"] += 1
                metadata["tot_unique_pwds"] += 1

            metadata["tot_pwds"] += 1
            metadata["tot_bits_set"] += tot_new_bits
            metadata["tot_bloomfilter_files"] += tot_new_files
            metadata["tot_time_spent"] += time_spent

            processed_info["curr_line_num"] += 1
            processed_info["processed_pwds"] += 1

            processed_info["percentage_completion"] = \
                (float(processed_info["processed_pwds"])/processed_info["tot_pwds"]) * 100
            processed_info["incomplete_transaction"] = False

            update_meta_information(metadata)
            update_resume_file(cracked_pwd_file, processed_info)
            resuming_from_partial_run = False
            tot_processed += 1
            if (tot_processed % epoch_number) == 0:
                msg = "Processed passwords(this run): %d, Total processed passwords: %d, " + \
                    "Remaining passwords: %d, Total time spent(this run): %s" 
                msg = msg % (tot_processed, processed_info["processed_pwds"], processed_info["tot_pwds"] - \
                                 processed_info["processed_pwds"], 
                             (str(datetime.timedelta(seconds=int(time.time() - start_time))))) 
                print msg
    metadata_this_pwd_db["processing_done"] = True
    os.remove(resume_cracked_pwd_file)
    update_meta_information(metadata)
    print "Total time taken in this run: %s" % (str(datetime.timedelta(seconds=(time.time() - start_time))))
    print "Total time taken to process this pwd db: %s" % \
        (str(datetime.timedelta(seconds=metadata_this_pwd_db["tot_time_spent"])))
    return

# Deletes all the bloom-filters created so far.
def delete_bloomfilters():
    if os.path.isfile(BLOOMFILTER_METADATA):
        os.remove(BLOOMFILTER_METADATA)

    if os.path.isfile(DEFAULT_FNAME):
        os.remove(DEFAULT_FNAME)
    if os.path.isfile(DEFAULT_FNAME + ".zip"):
        os.remove(DEFAULT_FNAME + ".zip")
    if os.path.isfile(DEFAULT_FNAME + ".base64"):
        os.remove(DEFAULT_FNAME + ".base64")

    try:
        rc = subprocess.check_output(["find", ".", "-name", "resume*"])    
    except subprocess.CalledProcessError, e:
        print "Error: Problem executing 'ls': %s" % (str(e))
        exit(-1)

    files = rc.split('\n')
    for f in files:
        if re.search('.*/resume\..*$', f):
            os.remove(f)

    for i in range(TOT_DIR):
        dname = BF_SUBDIR + str(i)
        if not os.path.isdir(dname):
            continue

        try:
            rc = subprocess.check_output(["/bin/rm", "-rf", dname])    
        except subprocess.CalledProcessError, e:
            print "Error: Problem deleting BF directory: %s" % (str(e))
            exit(-1)
    return

def update_meta_information(metadata):
    with open(BLOOMFILTER_METADATA, "w+") as bfmd:
        json.dump(metadata, bfmd)
    return

def get_meta_information():
    metadata = {
        "tot_pwds": 0,
        "tot_unique_pwds": 0,
        "tot_cracked_pwd_dbs": 0,
        "tot_time_spent": 0,
        "tot_bloomfilter_files": 0,
        "tot_bits_set": 0,
        "cracked_pwd_db" : []
        }
    if not os.path.isfile(BLOOMFILTER_METADATA):
        return metadata
    with open(BLOOMFILTER_METADATA, "r") as bfmd:
        metadata = json.load(bfmd)
    return metadata

# "tot_pwds"                : Total passwords processed so far,
# "tot_cracked_pwd_dbs"     : Total number of cracked pwd dbs processed so far,
# "tot_time_spent"          : Total time spent in creating bloomfilter so far,
# "tot_bloomfilter_files"   : Total number of generated bloomfilter files,
# "tot_bits_set"            : Total bits set in the bloomfilter so far,
# "cracked_pwd_db"          : Array of cracked-pwd-db and their sha1sum
def print_meta_information():
    metadata = get_meta_information()
    ri = get_resume_information()
    # Print all the information here.
    if len(ri) > 0:
        print "Bloomfilter: Partially processed password databases"
        for i in range(len(ri)):
            print "Name: %s, Total passwords: %s, Processed passwords: %s, Percentage completion: %s" % \
                (ri[i]["name"], ri[i]["tot_pwds"], ri[i]["processed_pwds"], ri[i]["percentage_completion"])
        print ""

    print "Bloomfilter: Metainformation"

    for i in range(len(metadata["cracked_pwd_db"])):
        cpf = metadata["cracked_pwd_db"][i]
        print "Name: %s, Total pwds: %s, Total unique pwds: %s, Total bits set: %s, Total files edited: %s, Total time: %s" % \
            (cpf["name"], cpf["tot_pwds"], cpf["tot_unique_pwds"], cpf["tot_bits_set"], cpf["tot_files_written_to"],
             (str(datetime.timedelta(seconds=int(cpf["tot_time_spent"])))))

    print ""
    print "Total cracked passwords databases: %s" % (metadata["tot_cracked_pwd_dbs"])
    print "Total time spent: %s" % (str(datetime.timedelta(seconds=int(metadata["tot_time_spent"]))))
    print "Total passwords: %s" % (metadata["tot_pwds"])
    print "Total unique passwords: %s" % (metadata["tot_unique_pwds"])
    print "Total bits set: %s" % (metadata["tot_bits_set"])
    return

def get_resume_information():
    resume_info = []
    try:
        rc = subprocess.check_output(["find", ".", "-name", "resume*"])    
    except subprocess.CalledProcessError, e:
        print "Error: Problem executing 'ls': %s" % (str(e))
        exit(-1)

    files = rc.split('\n')
    for f in files:
        if re.search('.*/resume\..*$', f):
            processed_info = process_resume_file(f, False)
            resume_info.append(processed_info)

    return resume_info

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-x", "--clean-up",
                      action="store_true", dest="clean_up", default=False,
                      help="Clean all the bloom filter files in all the directories. Use with EXTREME CAUTION")
    parser.add_option("-r", "--cross-check",
                      action="store_true", dest="crosscheck", default=False,
                      help="Runs over all bloomfilter files and cross-checks meta-info with actual info")
    parser.add_option("-p", "--parallelize",
                      action="store_true", dest="parallelize", default=False,
                      help="Parallelize bloomfilter generation across cores")
    parser.add_option("-s", "--max-bit-vector",
                      action="store", type="int", dest="maxbitvector", default=10000,
                      help="Max entries to cache. After this, flush them all to the disk")
    parser.add_option("-t", "--num-threads",
                      action="store", type="int", dest="numthreads", default=8,
                      help="Number of threads to run to get the work done")
    parser.add_option("-a", "--add-cracked-db",
                      action="store", type="string", dest="cracked_pwd_file", default="",
                      help="""Process this cracked password file and add to bloom filter""")
    parser.add_option("-c", "--check-file",
                      action="store", type="string", dest="checkfile", default="",
                      help="""Check file and tell which bits are set""")
    parser.add_option("", "--check-dir",
                      action="store", type="string", dest="checkdir", default="",
                      help="Check all files in a given directory and tell which bits are set for each file")
    parser.add_option("-m", "--meta-info",
                      action="store_true", dest="metainfo", default=False,
                      help="""Spew meta information such as:
                              1. Number of processed cracked password files (which ones, their sha1sums etc)
                              2. Number of processed passwords
                              3. Total time spent in processing so far
                              4. Number generated bloom filter files
                              5. Number bits set in the bloom filter
                              6. Interrupted processing of passwords from last run""")

    (options, args) = parser.parse_args()

    if options.maxbitvector:
        MAX_PWDS_TO_PROCESS_AT_A_TIME = options.maxbitvector
        MAX_FILES_TO_FLUSH = MAX_PWDS_TO_PROCESS_AT_A_TIME * 5

    if options.numthreads:
        NUM_THREADS = options.numthreads

    if options.clean_up:
        print_meta_information()
        print "You have asked to delete all the bloom filter files. This will delete all the above information\n\n"
        confirm_delete = raw_input("Are you sure you want to delete it (y/n)?")
        if confirm_delete == 'y':
            print "Deleting all bloom filters"
            delete_bloomfilters()
            exit(0)
        else:
            print "Aborting deleting bloom filters"
            exit(0)
    elif options.metainfo:
        print_meta_information()
        exit(0)
    elif options.cracked_pwd_file != "":
        #pdb.set_trace()
        if not options.parallelize:
            process_cracked_pwd_file(options.cracked_pwd_file)
            exit(0)
        else:
            print "Parallelizing with %d processes" % (NUM_THREADS)
            print "Bit flush will happen after processing %d files" % (MAX_FILES_TO_FLUSH)

            all_processes = []
            p = multiprocessing.Process(target=read_pwds, args=([options.cracked_pwd_file]))
            p.start()
            all_processes.append(p)
            
            for i in range(NUM_THREADS):
                p = multiprocessing.Process(target=calculate_hashes, args=([i, tot_files_to_flush]))
                p.start()
                all_processes.append(p)

            p = multiprocessing.Process(target=flush_bits_to_disk, args=([i, tot_files_to_flush]))
            p.start()
            all_processes.append(p)
                
            print "Main Thread: Waiting for join"
            for i in range(len(all_processes)):
                all_processes[i].join()
            print "Main Thread: All children terminated...exiting"

    elif options.checkfile != "":
        checkfile(options.checkfile)
        exit(0)
    elif options.checkdir != "":
        checkdir(options.checkdir)
        exit(0)
    elif options.crosscheck:
        cross_check_bloom_filters()
    else:
        print "Unrecognized option"
        parser.print_help()


