
package main

import (
	"fmt"
	"os"
	"math"
	"strconv"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
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
	// File size in bytes (100MB)
	FILE_SIZE = uint64(math.Pow(2, 20) * 100)
	// Bloomfilter bits in each file
	BITS_PER_FILE = FILE_SIZE * 8
	// Total files in each directory.
	FILES_PER_DIR = 32
	// Total directories
	TOT_DIR = 16
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

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil { return true, nil }
	if os.IsNotExist(err) { return false, nil }
	return false, err
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

type hl_val struct{
	fname string
	dname string
	bitpos uint64
}

type hash_location map[string] *hl_val

// Accepts hashes as input and returns a dictionary with
// key as each hash-value and data as
// "fname" : "dirXYZ/bloomfilter"
// "position" : index of bit position
func get_bit_positions(hashes []string) (hl hash_location) {
	hl = make(hash_location)
	for i := 0; i < len(hashes); i++ {
		j := new(hl_val)

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


func open_bf_file(fn string) (fd *os.File, retcode int) {
	var err error
	fd, err = os.OpenFile(fn, os.O_RDWR | os.O_SYNC, 644)
	if err != nil {
		fmt.Printf("APPU ERROR: Cannot open file: %v\n", fn);
		retcode = -1
		return
	}

	return
}


func set_bit_in_byte(b []byte, bit int) (retcode bool, t []byte){
	t = make([]byte, 1)
	t[0] = (b[0] | bit_set_lookup[bit])
	if t[0] == b[0] {
		return false, t
	}
	return true, t
}


func is_bit_set_in_byte(b []byte, bit int) (retcode bool){
	if (b[0] & bit_set_lookup[bit]) != 0 {
		return true
	}
	return false
}


func read_one_byte_from_file(fn string, fd *os.File, byte_position int64) (b []byte, retcode int) {
	// Offset 52 bytes
	b = make([]byte, 1)
	_, err := fd.ReadAt(b, (byte_position + 52))
	if err != nil {
		fmt.Println("APPU ERROR: Cannot read one byte from file: %v(position: %v)", fn, byte_position);
		retcode = -1
		return
	}

	return b, 0
}


func write_one_byte_to_file(fn string, fd *os.File, byte_position int64, b []byte) (retcode int) {
	// Offset 52 bytes
	_, err := fd.WriteAt(b, (byte_position + 52))
	if err != nil {
		fmt.Println("APPU ERROR: Cannot write one byte from file: %v(position: %v)", fn, byte_position);
		retcode = -1
		return
	}

	return
}


func check_hash_location_in_bf(hl *hl_val) (bool) {
	dname := BF_SUBDIR + hl.dname
	fname := dname + "/" + hl.fname
	
	fd, rc := open_bf_file(fname)
	if rc != 0 {
		fmt.Printf("ERROR: Could not check")
		os.Exit(1)
	}
	defer fd.Close()
	
	byte_number := int64(math.Ceil(float64(hl.bitpos + 1.0)/ 8)) - 1
	bitpos_inside_byte := int(hl.bitpos % 8)
	
	if b, rc := read_one_byte_from_file(fname, fd, byte_number); rc != 0 {
		fmt.Printf("ERROR: Could not read a byte from file\n")
		os.Exit(1)
	} else {
		if rc := is_bit_set_in_byte(b, bitpos_inside_byte); rc == false {
			return false
		}
	}
	return true
}



func main() {
	pwd_list := []string{
		"pwd411112",
		"pwd1411083",
		"yogesh",
	}

OUTER:
	for _, p := range pwd_list {
		hashes := get_hashed_values(p)
		hash_locations := get_bit_positions(hashes)
		for _, hl := range hash_locations {
			rc := check_hash_location_in_bf(hl)
			if !rc {
				fmt.Printf("Password '%v' NOT present in BF\n", p)
				continue OUTER
			}
		}
		fmt.Printf("Password '%v' PRESENT in BF\n", p)
	}
}
