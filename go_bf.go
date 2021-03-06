
package main

import (
	"fmt"
	"os"
	"strings"
	"bytes"
	"math"
	"strconv"
	"sync"
	"runtime"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os/exec"
	"bufio"
)

// Expected false positives for bloomfilter 50GB long,
// 10 hash functions and 400 million cracked passwords
// m = 429496729600
// n = 400,000,000
// k = 10
// P(fp) = (1 - e^[-kn/m])^k
// P(fp): 4.545514287009533e-21

var (
	MAX_PWDS_TO_PROCESS_AT_A_TIME = 10000
	MAX_FILES_TO_FLUSH = MAX_PWDS_TO_PROCESS_AT_A_TIME * 5
	// 50GB at the server
	BLOOMFILTER_SIZE = uint64(math.Pow(2, 30) * 50)
	// Total bloomfilter bits in those 50GB
	TOTAL_BITS = (BLOOMFILTER_SIZE * 8) 
	// File size in bytes (10KB)
	FILE_SIZE = uint64(math.Pow(2, 10) * 10)
	// Bloomfilter bits in each file
	BITS_PER_FILE = FILE_SIZE * 8
	// Total files in each directory.
	FILES_PER_DIR = 1000
	// Total directories
	TOT_DIR = 5242
	BF_SUBDIR = "bloomfilters/"
	BLOOMFILTER_METADATA = "metadata.bloomfilter"
	DEFAULT_FNAME = BF_SUBDIR + "default"

	// I assume that the bloom filter is array of bits rather than bytes.
	// Thus it will be stored in littel-endian way (Least significant byte at a lowest address).
	// However, inside an individual byte, I also assume that least-significant-bit is stored
	// at a least-significant-address (visually from left-to-right).
	// Thus, the 8th bit is least-significant-address. So if we want to set 8th bit then
	// we OR it with 128.

	bit_set_lookup = []byte {
		128,
		64,
		32,
		16,
		8,
		4,
		2,
		1,
	}
)

// Accepts a buf and a tag "TAG".
// Finds locations of <TAG> and </TAG>
// Returns the positions of contents
func get_tag_contents(buf []byte, tag string) (start int, end int){
	start_tag := "<" + tag + ">"
	end_tag := "</" + tag + ">"

	start_tag_bytes := []byte(start_tag)
	end_tag_bytes   := []byte(end_tag)

	start = (bytes.Index(buf, start_tag_bytes) + len(start_tag_bytes))
	end   = bytes.Index(buf, end_tag_bytes)
	return
}

// Reads a part of bloomfilter file and returns:
//  version: "0.0.1"
//  setbits: Number of set bits in BF bit array
//  BF bits buffer start and end indexes
func read_bf_file(fn string) (
	rc int,
	version string,
	setbits int,
	bitbuf_start int,
	bitbuf_end int,
	buf []byte) {

	rc = 0
	setbits = 0
	version = "0.0.0"
	bitbuf_start = 0
	bitbuf_end = 0

	fd, err := os.Open(fn)
	if err != nil {
		fmt.Println("APPU ERROR: Cannot open file: %v", fn);
		rc = -1
		return
	}
	defer fd.Close()
	
	stat, err := fd.Stat()	
	if err != nil {
		fmt.Println("APPU ERROR: Cannot stat file: %v", fn);
		rc = -1
		return
	}
	
	buf = make([]byte, stat.Size())
	_, err = fd.Read(buf)
	if err != nil {
		fmt.Println("APPU ERROR: Cannot read file: %v", fn);
		rc = -1
		return
	}


	s, e := get_tag_contents(buf, "version")
	version = string(buf[s:e])

	s, e = get_tag_contents(buf, "setbits")
	setbits, _ = strconv.Atoi(string(buf[s:e]))

	bitbuf_start, bitbuf_end = get_tag_contents(buf, "bits")

	return
}

func convert_to_zip(fname string) (retcode int) {
	if err := exec.Command("/usr/bin/zip", fname + ".zip", fname).Run(); err != nil {
		retcode = -1
	}
	return
}

func convert_to_base64(fname string) (retcode int) {
	if err := exec.Command("/usr/local/bin/node", "./base64_converter.js", fname + ".zip").Run(); err != nil {
		retcode = -1
	}
	return
}

func create_dir(dname string) (retcode int) {
	dir_exists, _ := exists(dname)
	if dir_exists {
		return
	}
	
	if err := os.Mkdir(dname, os.ModeDir | os.ModePerm); err != nil {
		retcode = -1
	}
	return 
}


func write_bf_file(fname string,
	version string,
	setbits int,
	bitsbuf []byte) (retcode int) {

	retcode = 0

	fd, err := os.Create(fname)
	if err != nil {
		fmt.Printf("APPU ERROR: Cannot create file: %v (%v)\n", fname, err);
		retcode = -1
		return
	}
	
	fbuf := []byte{}
	fbuf = append(fbuf, []byte("<version>" + version + "</version>\n")...)
	fbuf = append(fbuf, []byte("<setbits>" + strconv.Itoa(setbits) + "</setbits>\n")...)
	fbuf = append(fbuf, []byte("<bits>")...)
	fbuf = append(fbuf, bitsbuf...)
	fbuf = append(fbuf, []byte("</bits>\n")...)

	if _, err = fd.Write(fbuf); err != nil {
		retcode = -1
	}

	fd.Close()
	
	// if rc := convert_to_zip(fname); rc != 0 {
	// 	retcode = -1
	// }
	// if rc := convert_to_base64(fname); rc != 0 {
	// 	retcode = -1
	// }
	
	return
}

// Reads a file and prints 
// which bytes are set
func check_bits_in_files(fnames []string) {
	for _,fn := range(fnames) {
		rc, _, _, bitbuf_start, bitbuf_end, buf := read_bf_file(fn) 
		if rc != 0 {
			fmt.Println("APPU ERROR: Could not process file: %v", fn);
			continue
		}

		bf_bits := buf[bitbuf_start : bitbuf_end]

		zero_bytes     := 0
		non_zero_bytes := 0
		
		var non_zero_bytes_array = make([]int, 0)

		for i, b := range(bf_bits) {
			if b != 0 {
				non_zero_bytes += 1
				non_zero_bytes_array = append(non_zero_bytes_array, i)
			} else {
				zero_bytes += 1
			}
		}
		
		fmt.Println("Filename: %v\n", fn)
		for _, byte_pos := range(non_zero_bytes_array) {
			bit_numbers := get_non_zero_bit_numbers(bf_bits[byte_pos])
			for _, bit_pos := range(bit_numbers) {
				fmt.Println("\tBit %v is set in byte %v\n", bit_pos, byte_pos)
			}
		} 
	}
}

func get_non_zero_bit_numbers(b byte) (bit_numbers []int) {
	for i,j := 1, 7; j >= 0; i, j = i << 1, j - 1 {
		if (b & byte(i) != 0) {
			bit_numbers = append(bit_numbers, j)
		} 
	}
	return
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil { return true, nil }
	if os.IsNotExist(err) { return false, nil }
	return false, err
}

func check_bits_in_dir(dirname string) {
	for i := 0; i < TOT_DIR; i++ {
		start_file := i * FILES_PER_DIR
		end_file := i * FILES_PER_DIR + FILES_PER_DIR
		for j := start_file; j < end_file; j++ {
			dname := dirname + "/" + strconv.Itoa(i)
			fname := dname + "/" + strconv.Itoa(j)

			dir_exists, _ := exists(dname)
			if !(dir_exists) {
				break
			}

			file_exists, _ := exists(fname)
			if !(file_exists) {
				continue
			}

			check_bits_in_files([]string{fname})
		}
	}
}

func check_bits_in_dir_concurrent(dirname string, file_channel chan<- string) {
	for i := 0; i < TOT_DIR; i++ {
		start_file := i * FILES_PER_DIR
		end_file := i * FILES_PER_DIR + FILES_PER_DIR
		for j := start_file; j < end_file; j++ {
			dname := dirname + "/" + strconv.Itoa(i)
			fname := dname + "/" + strconv.Itoa(j)

			dir_exists, _ := exists(dname)
			if !(dir_exists) {
				break
			}

			file_exists, _ := exists(fname)
			if !(file_exists) {
				continue
			}

			file_channel <- fname
		}
	}	
}

func check_bits_in_files_concurrent(my_num int, file_channel <- chan string, wg *sync.WaitGroup) {
	for fn := range(file_channel) {
		// fmt.Println("My number: %v, Checking for: %v", my_num, fn)
		check_bits_in_files([]string{fn})
	}
	wg.Done()
}

func pwd_to_hashes(wg *sync.WaitGroup, pwd_chan <-chan string, hash_chan chan<- string) {
	defer close(hash_chan)
	defer wg.Done()

	var subwg sync.WaitGroup
	subwg.Add(num_pwd_to_hash_workers)

	for i := 0; i < num_pwd_to_hash_workers; i++ {
		go func() {
			for pwd := range(pwd_chan) {
				pwd_hashes := get_hashed_values(pwd)
				for i := 0; i < len(pwd_hashes); i++ {
					hash_chan <- pwd_hashes[i]
				}
			}
			//fmt.Printf("DELETE ME: Closing goroutine because pwd_chan closed\n")
			subwg.Done()
		}()
	}

	//fmt.Printf("DELETE ME: waiting for all goroutines of pwd_to_hashes() to be done\n")
	subwg.Wait()
	//fmt.Printf("DELETE ME: DONE WAITING FOR goroutines of pwd_to_hashes() \n")
}

// Returns 10 hash values from 10 hash-functions
// Check: http://www.eecs.harvard.edu/~kirsch/pubs/bbbf/rsa.pdf
func get_hashed_values(data string) (hashes []string) {
	data_bytes := []byte(data)
	sha1sum := sha1.Sum(data_bytes)
	h1 := hex.EncodeToString(sha1sum[:])
	sha256sum := sha256.Sum256(data_bytes)
	h2 := hex.EncodeToString(sha256sum[:])
	// fmt.Printf("Password: %v\n", data)
	// fmt.Printf("H1: sha1: %v\n", h1)
	// fmt.Printf("H2: sha256: %v\n", h2)

	for i := 0; i < 10; i++ {
		iter_data := h1 + strconv.Itoa(i) + h2
		iter_data_bytes := []byte(iter_data)
		iter_data_sha256sum := sha256.Sum256(iter_data_bytes)
		iter_data_sha256sum_str := hex.EncodeToString(iter_data_sha256sum[:])
		// fmt.Printf("Iter: %v, Sha256sum: %v\n", i, iter_data_sha256sum_str)
		// fmt.Printf("Password: %v, Generated hashes: %v\n", data, iter_data_sha256sum_str)

		hashes = append(hashes, iter_data_sha256sum_str)
	}
	return
}


type hash_location map[string] *struct{
	fname string
	dname string
	bitpos uint64
}

var fname_lock sync.Mutex
var per_file_lock map[string] *sync.Mutex

func hash_to_location(wg *sync.WaitGroup, hash_chan <-chan string, location_chan chan<- hash_location) {
	defer func() {
		close(location_chan)
		fmt.Println("DELETE ME: Closed location_chan")
	}()
	defer wg.Done()

	var subwg sync.WaitGroup
	subwg.Add(num_hash_to_location_workers)

	for i := 0; i < num_hash_to_location_workers; i++ {
		go func() {
			for hash := range(hash_chan) {
				//fmt.Printf("DELETE ME: BEFORE get_bit_positions()\n")
				hl := get_bit_positions([]string{hash})
				//fmt.Printf("DELETE ME: AFTER get_bit_positions()\n")
				//fmt.Printf("DELETE ME: Putting hash into hash location: %v\n", hl)
				location_chan <- hl
			}
			subwg.Done()
		}()
	}

	//fmt.Printf("DELETE ME: waiting for all goroutines of hash_to_location() to be done\n")
	subwg.Wait()
	//fmt.Printf("DELETE ME: DONE WAITING FOR goroutines of hash_to_location() \n")
}

var is_version_updated = make(map[string]bool)

// Accepts hashes as input and returns a dictionary with
// key as each hash-value and data as
// "fname" : "dirXYZ/bloomfilter"
// "position" : index of bit position
func get_bit_positions(hashes []string) (hl hash_location) {
	hl = make(hash_location)
	for i := 0; i < len(hashes); i++ {
		j := new(struct {
			fname string
			dname string
			bitpos uint64
		})

		hash_big_int := big.NewInt(0)
		hash_big_int.SetString(hashes[i], 16)

		t := big.NewInt(0)
		t.Mod(hash_big_int, big.NewInt(0).SetUint64(TOTAL_BITS))

		bit_number := t.Uint64()
		file_number := uint64(math.Ceil(float64(bit_number + 1.0) / float64(BITS_PER_FILE))) - 1
		bit_position := bit_number % BITS_PER_FILE
		dir_number := uint64(math.Ceil(float64(file_number + 1.0) / float64(FILES_PER_DIR))) - 1
		j.fname = strconv.Itoa(int(file_number))
		j.dname = strconv.Itoa(int(dir_number))
		j.bitpos = bit_position
		//fmt.Printf("Hash: %v, Dname: %v, Fname: %v, Bitpos: %v\n",hashes[i], j.dname, j.fname, j.bitpos)
		hl[hashes[i]] = j
	}
	return
}


// Returns whether the array is modified or not
func set_bit_in_array(fbuf []byte, byte_number int, bitpos_inside_byte int) (bool) {
	orig_byte := fbuf[byte_number]
	fbuf[byte_number] = (orig_byte | bit_set_lookup[bitpos_inside_byte])
	if fbuf[byte_number] == orig_byte {
		return false
	}
    return true
}

// In this map, key is filename
var lk_bit_positions sync.RWMutex
type map_bit_position_value struct{
	sync.Mutex
	fname string
	dname string
	bitpos_array []uint64
}

type bit_position map[string] *map_bit_position_value

var map_bit_position bit_position

var FLUSH_TO_FILE_THRESHOLD = 10000
//var FLUSH_TO_FILE_THRESHOLD = 2

func accumulate_bitpositions(wg *sync.WaitGroup, location_chan <-chan hash_location, signal_pwd_reader chan<- bool) {
	defer wg.Done()

	var total_hashes = 0

	for hl := range(location_chan) {
		for _, v := range(hl) {
			fmt.Printf("DELETE ME: Accumulate bit positions: %v\n", hl)

			if val, ok := map_bit_position[v.fname]; ok {
				fmt.Println("DELETE ME: APPENDED to bitpos_array")
				val.bitpos_array = append(val.bitpos_array, v.bitpos)
			} else {
				fmt.Println("DELETE ME: CREATED NEW bitpos_array")
				b := new(map_bit_position_value)
				b.fname = v.fname
				b.dname = v.dname
				b.bitpos_array = append(b.bitpos_array, v.bitpos)
				map_bit_position[v.fname] = b
			}

			total_hashes += 1

			if total_hashes >= (FLUSH_TO_FILE_THRESHOLD * 10) {
				fmt.Println("DELETE ME: Calling flush_to_files() as THRESHOLD exceeded")
				flush_to_files()
				signal_pwd_reader <- true
				total_hashes = 0
			}
		}

	}

	if total_hashes > 0 {
		fmt.Println("DELETE ME: Calling flush_to_files() as location_chan closed")
		flush_to_files()
	}

	return
}

func flush_to_files() {
	var bit_position_value_chan []chan *map_bit_position_value

	for i := 0; i < num_bitposition_to_file_workers; i++ {
		bit_position_value_chan = append(bit_position_value_chan, make(chan *map_bit_position_value))
	}

	var subwg sync.WaitGroup
	subwg.Add(num_bitposition_to_file_workers)

	for i := 0; i < num_bitposition_to_file_workers; i++ {
		go func(c <-chan *map_bit_position_value) {

			for bpv := range(c) {
				fmt.Printf("DELETE ME: BEFORE flush_bit_position_values(): %v\n", bpv)
				flush_bit_position_values(bpv)
				fmt.Printf("DELETE ME: AFTER flush_bit_position_values()\n")
			}

			//fmt.Printf("DELETE ME: Closing goroutine that called flush_bit_position_values()\n")
			subwg.Done()
		}(bit_position_value_chan[i])
	}

	
	var cnum = 0
	for _, v := range(map_bit_position) {
		//fmt.Printf("DELETE ME: Putting into BPV channel: %v\n", v)
		bit_position_value_chan[cnum] <- v
		//fmt.Printf("DELETE ME: AFTER Putting into channel: %v\n", v)
		cnum += 1
		if cnum >= num_bitposition_to_file_workers {
			cnum = 0
		} 
	}

	for i := 0; i < num_bitposition_to_file_workers; i++ {
		close(bit_position_value_chan[i])
	}

	//fmt.Printf("DELETE ME: waiting for all goroutines of flush_to_files() to be done\n")
	subwg.Wait()
	//fmt.Printf("DELETE ME: DONE WAITING FOR goroutines of flush_to_files()\n")
}

func flush_bit_position_values(bpv *map_bit_position_value) (
	retcode int) {
	bpv.Lock()
	defer bpv.Unlock()

	retcode = 0

	dname := BF_SUBDIR + bpv.dname
	fname := dname + "/" + bpv.fname

	fmt.Println("DELETE ME: Read HASH LOCATION")
	
	create_dir(dname)

	var fbuf []byte
	var bitsbuf []byte
	var version string
	var setbits int
	var rc int
	var bitbuf_start int
	var bitbuf_end int
	var is_file_changed = false

	if file_exists, _ := exists(fname); !file_exists {
		bitsbuf = make([]byte, FILE_SIZE)
		version = "0.0.0"
		setbits = 0
	} else {
		rc, version, setbits, bitbuf_start, bitbuf_end, fbuf = read_bf_file(fname) 
		fmt.Printf("DELETE ME: Read file, file: %v, bitbuf_start: %v, bitbuf_end: %v\n", fname, bitbuf_start, bitbuf_end)
		bitsbuf = fbuf[bitbuf_start : bitbuf_end]
		if rc != 0 {
			retcode = -1
			fmt.Printf("APPU ERROR: read_bf_file() returned -1")
			return
		}
	}

	for _, bp := range bpv.bitpos_array {
		byte_number := int(math.Ceil(float64(bp + 1.0)/ 8)) - 1
		bitpos_inside_byte := int(bp % 8)
		
		fmt.Printf("DELETE ME: SET POS, file: %v, bitpos: %v\n", fname, bp)
		
		if rc := set_bit_in_array(bitsbuf, byte_number, bitpos_inside_byte); !rc {
			// There was no change to the file
		} else {
			// File was modified
			is_file_changed = true
			setbits += 1
		}
	}

	if is_file_changed {
		version_str_array := strings.Split(version, ".")
		new_version, _ := strconv.Atoi(version_str_array[2])
		new_version++
		version = version_str_array[0] + "." + version_str_array[1] + "." + strconv.Itoa(new_version)

		write_bf_file(fname, version, setbits, bitsbuf)
	}

	return
}


func bitposition_to_file(wg *sync.WaitGroup, location_chan <-chan hash_location) {
	defer wg.Done()

	// for hl := range(location_chan) {
	// 	set_bit_positions_in_file(hl)
	// }

	var commu_chan []chan hash_location

	for i := 0; i < num_bitposition_to_file_workers; i++ {
		commu_chan = append(commu_chan, make(chan hash_location))
	}

	var subwg sync.WaitGroup
	subwg.Add(num_bitposition_to_file_workers)

	for i := 0; i < num_bitposition_to_file_workers; i++ {
		go func(c <-chan hash_location) {
			for hl := range(c) {
				fmt.Printf("DELETE ME: BEFORE set_bit_positions(): %v\n", hl)
				set_bit_positions_in_file(hl)
				fmt.Printf("DELETE ME: AFTER set_bit_positions()\n")
			}

			//fmt.Printf("DELETE ME: Closing goroutine that called set_bit_positions_in_file()\n")
			subwg.Done()
		}(commu_chan[i])
	}


	for hl := range(location_chan) {
		for _, v := range(hl) {
			num_gr := int(math.Mod(float64(v.bitpos), float64(num_bitposition_to_file_workers)))
			commu_chan[num_gr] <- hl
		}
	}

	for i := 0; i < num_bitposition_to_file_workers; i++ {
		close(commu_chan[i])
	}

	//fmt.Printf("DELETE ME: waiting for all goroutines of set_bit_positions_in_file() to be done\n")
	subwg.Wait()
	//fmt.Printf("DELETE ME: DONE WAITING FOR goroutines of set_bit_positions_in_file()\n")
}


func set_bit_positions_in_file(hl hash_location) (
	retcode int,
	existing_pwd bool,
	tot_new_bits int,
	tot_new_files int,
	tot_files_written_to int) {

	retcode = 0
	existing_pwd = true
	tot_new_bits = 0
	tot_new_files = 0
	tot_files_written_to = 0

	for _, v := range(hl) {
		fmt.Println("DELETE ME: Read HASH LOCATION")
		dname := BF_SUBDIR + v.dname
		fname := dname + "/" + v.fname
		bitpos := v.bitpos

		var file_lock *sync.Mutex;

		fname_lock.Lock()

		if val_lock, ok := per_file_lock[fname]; ok {
		   file_lock = val_lock
		} else {
		   file_lock = new(sync.Mutex)
		   per_file_lock[fname] = file_lock
		}		

		fname_lock.Unlock()

		file_lock.Lock()
		defer file_lock.Unlock()	

		create_dir(dname)

		var fbuf []byte
		var bitsbuf []byte
		var version string
		var setbits int
		var rc int
		var bitbuf_start int
		var bitbuf_end int

		if file_exists, _ := exists(fname); !file_exists {
			bitsbuf = make([]byte, FILE_SIZE)
			version = "0.0.0"
			setbits = 0
			tot_new_files += 1
		} else {
			rc, version, setbits, bitbuf_start, bitbuf_end, fbuf = read_bf_file(fname) 
			fmt.Printf("DELETE ME: Read file, file: %v, bitbuf_start: %v, bitbuf_end: %v\n", fname, bitbuf_start, bitbuf_end)
			bitsbuf = fbuf[bitbuf_start : bitbuf_end]
			if rc != 0 {
				retcode = -1
				fmt.Printf("APPU ERROR: read_bf_file() returned -1")
				return
			}
		}

		byte_number := int(math.Ceil(float64(bitpos + 1.0)/ 8)) - 1
		bitpos_inside_byte := int(bitpos % 8)
		
		fmt.Printf("DELETE ME: SET POS, file: %v, bitpos: %v\n", fname, bitpos)

		if rc := set_bit_in_array(bitsbuf, byte_number, bitpos_inside_byte); !rc {
			// There was no change to the file
		} else {
			// File was modified
			existing_pwd = false
			tot_new_bits += 1
			setbits += 1
			if _, ok := is_version_updated[fname]; ok {
				// File version already updated
			} else {
				// Update the file version
				tot_files_written_to++
				version_str_array := strings.Split(version, ".")
				new_version, _ := strconv.Atoi(version_str_array[2])
				new_version++
				version = version_str_array[0] + "." + version_str_array[1] + "." + strconv.Itoa(new_version)
				is_version_updated[fname] = true
			}
			write_bf_file(fname, version, setbits, bitsbuf)
		}
	}
	return
}


func process_pwd_file(wg *sync.WaitGroup, 
	pwd_file string, 
	pwd_chan chan<- string, 
	signal_pwd_reader <-chan bool) (retcode int) {
	defer func() {
		close(pwd_chan)
		fmt.Printf("DELETE ME: Closed pwd_chan\n")		
	}()
	defer wg.Done()

	fd, err := os.Open(pwd_file)
	if err != nil {
		fmt.Println("APPU ERROR: Cannot open file: %v", pwd_file);
		retcode = -1
		return
	}
	defer fd.Close()

	total_pwds_read := 0
	tpr := 0

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		pwd := scanner.Text()
		tpr += 1
		fmt.Printf("(Password Processor): Putting in channel: %s, Number of pwds in channel: %v\n", pwd, tpr)
		pwd_chan <- pwd
		total_pwds_read += 1
		if total_pwds_read >= FLUSH_TO_FILE_THRESHOLD {
			total_pwds_read = 0
			fmt.Printf("DELETE ME: process_pwd_file(): Waiting for signal that passwords are flushed\n")
			_ = <-signal_pwd_reader
			fmt.Printf("DELETE ME: process_pwd_file(): GOT THE signal that passwords are flushed\n")
		}
	}

	fmt.Printf("DELETE ME: Returning from process_pwd_file()\n")
	return
}

var _ = runtime.NumCPU

var total_goroutines = 5

var num_pwd_to_hash_workers           = 100
var num_hash_to_location_workers      = 100
var num_bitposition_to_file_workers   = 100

func main() {
	// runtime.GOMAXPROCS(runtime.NumCPU())

	map_bit_position = make(bit_position)
	per_file_lock = make(map[string] *sync.Mutex)

	var wg sync.WaitGroup

	pwd_chan := make(chan string, 10000)
	signal_pwd_reader := make(chan bool)

	hash_chan := make(chan string)

	location_chan := make(chan hash_location)


	wg.Add(1)
	go process_pwd_file(&wg, os.Args[1], pwd_chan, signal_pwd_reader)

	wg.Add(1)
	go pwd_to_hashes(&wg, pwd_chan, hash_chan) 

	wg.Add(1)
	go hash_to_location(&wg, hash_chan, location_chan)

	//wg.Add(1)
	//go bitposition_to_file(&wg, location_chan)

	wg.Add(1)
	go accumulate_bitpositions(&wg, location_chan, signal_pwd_reader)


	fmt.Printf("DELETE ME: waiting for all goroutines of main() to be done\n")
	wg.Wait()
	fmt.Printf("DELETE ME: DONE WAITING FOR goroutines of main()\n")

	////

	//check_bits_in_files([]string{os.Args[1]})

	// hashes := get_hashed_values("password")
	// hl := get_bit_positions(hashes)

	// for h, s := range(hl) {
	// 	fmt.Println("Hash: %v\n", h)
	// 	fmt.Println("\tDname: %v\n", s.dname)
	// 	fmt.Println("\tFname: %v\n", s.fname)
	// 	fmt.Println("\tBitpos: %v\n", s.bitpos)
	// }

	// fmt.Println("Total number of CPUs: %v, GOMAXPROCS: %v\n", runtime.NumCPU(), runtime.GOMAXPROCS(0))

}
