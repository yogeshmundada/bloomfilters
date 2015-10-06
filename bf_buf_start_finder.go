
package main

import (
	"fmt"
	"os"
	"bytes"
	"math"
	"strconv"
)

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


func main() {
	_, _, _, bitbuf_start, _, _ := read_bf_file("bloomfilters/0/0") 
	fmt.Printf("Bitbuf start(bloomfilters/0/0): %v\n", bitbuf_start)
	_, _, _, bitbuf_start, _, _ = read_bf_file("bloomfilters/10/10367") 
	fmt.Printf("Bitbuf start(bloomfilters/10/10367): %v\n", bitbuf_start)
	_, _, _, bitbuf_start, _, _ = read_bf_file("bloomfilters/1001/1001573") 
	fmt.Printf("Bitbuf start(bloomfilters/1001/1001573): %v\n", bitbuf_start)

}
