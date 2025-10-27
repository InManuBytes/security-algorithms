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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
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

	// tighter
	if ok := verifyIntegrityFixed(manifestJsonBlob); !ok {
		os.Exit(1)
	}
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
		// hash.Sum(nil) return a byte slice
		// %x is a base 16 integer
		// NOTE: while this works, it can be vulnerable to timing attacks
		if checksum != fmt.Sprintf("%x", hash.Sum(nil)) {
			log.Printf(ChecksumMismatch, file.Name())
			continue
		}
		log.Printf(ChecksumMatch, file.Name())
	}
}

func verifyIntegrityFixed(input []byte) bool {
	var files map[string]string
	err := json.Unmarshal(input, &files)
	if err != nil {
		log.Fatal(err)
	}

	allOk := true

	for filePath, checksum := range files { // careful with shadow variables
		expectedHash, err := hex.DecodeString(checksum)
		if err != nil || len(checksum) != sha256.Size {
			log.Printf("ERROR: %s (invalid expected SHA256 hex)", filePath)
			allOk = false
			continue
		}

		file, err := os.Open(filePath) // file is a reader
		if err != nil {
			log.Printf("ERROR: %s", err) // alternatively you can log and error and continue
			allOk = false
			continue
		}

		// from the example in the docs
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			// io.Copy handles large files by reading in chunks
			log.Fatal(err)
		}
		// runs on each iteration to avoid "too many open files"
		if cerr := file.Close(); cerr != nil {
			log.Printf("WARN: %s (close fialed: %v)", filePath, err)
		}

		computedHash := hash.Sum(nil)
		// if you don't need constant time semantics use
		if !bytes.Equal(computedHash, expectedHash) {
			log.Printf(ChecksumMismatch, filePath)
			allOk = false
			continue
		}

		log.Printf(ChecksumMatch, filePath)

	}

	return allOk
}
