// Package translibb is a transitive dependency that does the hashing.
package translibb

import (
	"crypto/sha256"
	"crypto/sha512"
)

// UsedHash is reached from the application through transliba.Used.
func UsedHash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// UnusedHash is reached only from transliba.Unused.
func UnusedHash(data []byte) []byte {
	sum := sha512.Sum512(data)
	return sum[:]
}
