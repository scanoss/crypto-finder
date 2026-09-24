// Package reachlib is a local dependency with its own hashing.
package reachlib

import "crypto/sha256"

// Digest hashes data.
func Digest(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// Visit calls fn for every item.
func Visit(items [][]byte, fn func([]byte) [32]byte) {
	for _, item := range items {
		fn(item)
	}
}

// Hasher hashes data.
type Hasher interface {
	Hash(data []byte) []byte
}

// Apply hashes data with h.
func Apply(h Hasher, data []byte) []byte {
	return h.Hash(data)
}
