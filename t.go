
package main

import (
	"fmt"
	"sort"
)

type MN []uint64

func (s MN) Len() int {
	return len(s)
}

func (s MN) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s MN) Less(i, j int) bool {
	return s[i] < s[j]
}


func main() {
	z := MN{100,23,1,56,2,66,90,35,78}
	fmt.Printf("Before sorting: %v\n", z)
	sort.Sort(z)
	fmt.Printf("After sorting: %v\n", z)
}
