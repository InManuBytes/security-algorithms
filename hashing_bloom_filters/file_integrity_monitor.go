/* Notes - Pseudocode
1. We have to parse the json
2. Iterate over the map
  - each key is a file we have to check
  - compute the sha256 for the file
  - check if it's the same from the given sha
3. For each file we check we have to format log lines
  - same sha: OK: FILE_NAME
  - diff sha: ALERT: FILE_NAME (checksum mismatch)
*/

package main

import (
	"fmt"
	"encoding/json"
	"os"
	"io"
	"crypto/sha256"
	"log"
)

const (
	ChecksumMatch    = "OK: %s"
	ChecksumMismatch = "ALERT: %s (checksum mismatch)"
)

func main() {
	// bin/app.exe has the wrong checksum
	manifestJsonBlob := []byte(`
	{
		"bin/app.exe": "a467a6c8a92b61fcd70cb83618a4268d73d5aeddc6a90168f93207ac2dde0820",
		"config/settings.yaml": "320df0b959781a7b12b304edd9431559900d67925a9b275d3ac0a55ad81b0c6a"
	}`)
	verifyIntegrity(manifestJsonBlob)
}

func verifyIntegrity(input []byte) {
	var files map[string]string
	err := json.Unmarshal(input, &files)
	if err != nil {
		log.Fatal(err)
	}

	for file, checksum := range files {
		file, err := os.Open(file) // file is a reader
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		// from the example in the docs
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			// io.Copy handles large files by reading in chunks
			log.Fatal(err)
		}
		// hash.Sum(nil) return a byte slice as hexadecimal
		// %x is a base 16 integer
		// NOTE: while this works, it can be vulnerable to timing attacks
		if checksum != fmt.Sprintf("%x", hash.Sum(nil)) {
			log.Printf(ChecksumMismatch, file.Name())
			continue
		}
		log.Printf(ChecksumMatch, file.Name())
	}
}

func verifyIntegrityFixed(input []byte) {
	var files map[string]string
	err := json.Unmarshal(input, &files)
	if err != nil {
		log.Fatal(err)
	}

	for file, checksum := range files {
		file, err := os.Open(file) // file is a reader
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		// from the example in the docs
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			// io.Copy handles large files by reading in chunks
			log.Fatal(err)
		}

		// TODO fix naive check
	}

	return
}
