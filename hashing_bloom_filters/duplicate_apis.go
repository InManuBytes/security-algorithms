package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

// PROBLEM:
// Find duplicate api keys in a large log file

func main() {
	file := `a1b2c3
x9y8z7
a1b2c3
q1w2e3`
	println(file)
	err := os.WriteFile("keys", []byte(file), 0666)
	if err != nil {
		log.Fatal(err)
	}
	duplicates, err := findDuplicates("keys")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Duplicates: %v", duplicates)
}

type dups struct {
	// originally had:
	// keys    map[string]bool
	// but if we only want unique duplicate keys in keyList
	keys map[string]uint8
	// Go maps do not rely solely on the hash to decide equality
	// As of Go 1.18+ go uses 64-bit hash, a fast, non-cryptographic, randomized
	// hash function basede on AquaHash, SipHash derivative optimized
	// for DOS resistance and speed. Since it's not cryptographically
	// secure it is collision resistance.
	// Before that, it used a variatn of runtime.strhash, similar to
	// FNV variants but hardened
	keyList []string
}

func findDuplicates(file string) ([]string, error) {
	openFile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer openFile.Close()

	scanner := bufio.NewScanner(openFile) // streaming input

	// map grows with the number of distinct keys
	duplicates := &dups{
		keys:    make(map[string]uint8),
		keyList: []string{},
	}
	for scanner.Scan() {
		key := scanner.Text()
		timesSeen := duplicates.keys[key] // if you access a nonexistent key timeSeen is zero value
		// QUESTION: how can we only append once?
		// count the number of times we see each key
		if timesSeen == 1 {
			// we've seen it once now, it's a duplicate
			duplicates.keyList = append(duplicates.keyList, key)
		}
		if timesSeen < 2 {
			duplicates.keys[key] = timesSeen + 1
		}
	}

	// missed the scanner error the first time around
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return duplicates.keyList, nil
}
