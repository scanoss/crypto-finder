package main

import (
	"crypto/cipher"

	b2 "example.com/acme/blk"
)

func aliased(key []byte) {
	block, err := b2.NewCipher(key)
	_ = err
	cipher.NewCBCEncrypter(block, nil)
}
