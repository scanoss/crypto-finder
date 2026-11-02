package main

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"

	"example.com/transliba"
)

func main() {
	data := []byte("payload")
	fmt.Println(fingerprint(data))
	fmt.Println(transliba.Used(data))
}

func fingerprint(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func legacy(data []byte) [16]byte {
	return md5.Sum(data)
}
