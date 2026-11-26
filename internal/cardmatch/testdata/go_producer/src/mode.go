package main

import (
	"crypto/cipher"

	"example.com/acme/blk"
)

func plain(key []byte) {
	block, err := blk.NewCipher(key)
	_ = err
	cipher.NewCBCEncrypter(block, nil)
}

func reassigned(key []byte, other cipher.Block) {
	block, err := blk.NewCipher(key)
	_ = err
	block = other
	cipher.NewCBCEncrypter(block, nil)
}

func viaParam(block cipher.Block) {
	cipher.NewCBCEncrypter(block, nil)
}

func caller(key []byte) {
	b, _ := blk.NewCipher(key)
	viaParam(b)
}

func otherCall(key []byte) {
	block, err := blk.Other(key)
	_ = err
	cipher.NewCBCEncrypter(block, nil)
}

func nested(key []byte) {
	block, err := blk.NewCipher(key)
	if err == nil {
		cipher.NewCBCEncrypter(block, nil)
	}
}
