package main

import (
	"fmt"
	"os"
	"math"
	"strconv"
	"sync"
)

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

	//FILES_PER_DIR = 1000
	// Total directories
	//TOT_DIR = 1000


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


func create_bf_file(bfn *bf_fname) (retcode int) {
	bfn.Lock()
	defer bfn.Unlock()

	dname := BF_SUBDIR + bfn.dname
	fname := dname + "/" + bfn.fname

	retcode = 0

	create_dir(dname)

	if file_exists, _ := exists(fname); file_exists {
		return
	}

	bitsbuf := make([]byte, FILE_SIZE)
	version := "0.0.0"
	setbits := 0

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
	
	return
}

type bf_fname struct{
	sync.Mutex
	fname string
	dname string
}

var num_bf_workers = 100

func bf_insert_into_channels() {
	var bf_fname_chan []chan *bf_fname

	for i := 0; i < num_bf_workers; i++ {
		bf_fname_chan = append(bf_fname_chan, make(chan *bf_fname))
	}

	var subwg sync.WaitGroup
	subwg.Add(num_bf_workers)

	for i := 0; i < num_bf_workers; i++ {
		go func(c <-chan *bf_fname) {

			for bfn := range(c) {
				fmt.Printf("DELETE ME: BEFORE create_bf_file(): %v\n", bfn)
				create_bf_file(bfn)
				fmt.Printf("DELETE ME: AFTER create_bf_file()\n")
			}

			subwg.Done()
		}(bf_fname_chan[i])
	}
	
	var cnum = 0
	var dnum = 0

	for i := 0; i < (FILES_PER_DIR * TOT_DIR); i++ {
		t := new(bf_fname)
		t.fname = strconv.Itoa(i)
		t.dname = strconv.Itoa(dnum)
		cnum += 1
		if cnum >= FILES_PER_DIR {
			cnum = 0
			dnum += 1
		}
		bf_fname_chan[(i % num_bf_workers)] <- t
	}

	for i := 0; i < num_bf_workers; i++ {
		close(bf_fname_chan[i])
	}

	subwg.Wait()
}


func main() {
	bf_insert_into_channels()
}
