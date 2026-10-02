package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"example.com/reachlib"
)

func main() {
	data := []byte("payload")
	fmt.Println(fingerprint(data))
	fmt.Println(reachlib.Digest(data))
	reachlib.Visit([][]byte{data}, callback)
}

func fingerprint(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func legacy(data []byte) [16]byte {
	return md5.Sum(data)
}

func callback(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// hasher implements reachlib.Hasher but nothing here passes it to the
// library: a first-party type reached only through a dependency's interface
// call is a case the project-only pass cannot see, so it stays out of the
// parity check.
type hasher struct{}

func (hasher) Hash(data []byte) []byte {
	sum := sha512.Sum512(data)
	return sum[:]
}
