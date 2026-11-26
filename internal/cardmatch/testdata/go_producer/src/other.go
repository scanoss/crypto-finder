package main

import (
	"crypto/cipher"

	"example.com/other/blk"
)

func otherPkg(key []byte) {
	block, err := blk.NewCipher(key)
	_ = err
	cipher.NewCBCEncrypter(block, nil)
}
