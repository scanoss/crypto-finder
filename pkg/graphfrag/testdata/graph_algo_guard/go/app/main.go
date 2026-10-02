package main

import (
	"crypto/sha256"
	"fmt"

	"example.com/dep/hasher"
)

type local struct{}

func (local) Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func run(h hasher.Hasher, msg string) {
	fmt.Println(h.Sum([]byte(msg)))
}

func main() {
	h := hasher.New([]byte("key"))
	run(h, "a")
	run(local{}, "b")
	fmt.Println(hasher.Verify(h, []byte("a"), nil))
}
