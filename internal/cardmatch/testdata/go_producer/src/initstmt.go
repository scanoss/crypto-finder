package main

import (
	"crypto/cipher"
	"crypto/des"

	"example.com/acme/blk"
)

func initIf(key, iv []byte) {
	if block, err := blk.NewCipher(key); err == nil {
		_ = block
	}
	if block, err := des.NewCipher(key); err == nil {
		cipher.NewCBCEncrypter(block, iv)
	}
}

func initIfBody(key, iv []byte) {
	if block, err := blk.NewCipher(key); err == nil {
		cipher.NewCBCEncrypter(block, iv)
	}
}

func initElse(key, iv []byte) {
	if block, err := blk.NewCipher(key); err != nil {
		_ = err
	} else {
		cipher.NewCBCEncrypter(block, iv)
	}
}

func initSwitch(key, iv []byte, m int) {
	switch block, err := blk.NewCipher(key); m {
	case 1:
		_ = err
		cipher.NewCBCEncrypter(block, iv)
	case 2:
		cipher.NewCBCEncrypter(block, iv)
	}
}

func initSwitchAfter(key, iv []byte, m int) {
	switch block, err := blk.NewCipher(key); m {
	case 1:
		_, _ = block, err
	}
	block, _ := des.NewCipher(key)
	cipher.NewCBCEncrypter(block, iv)
}

func initSwitchGaps(key, iv []byte, m int) {
	switch block, err := blk.NewCipher(key); m {
	case 1:
		_ = err

	case 2:
		cipher.NewCBCEncrypter(block, iv)
	// a comment before the clause
	case 3:
		cipher.NewCBCEncrypter(block, iv)
	}
	switch block, err := des.NewCipher(key); m {
	case 1:
		_ = err
		cipher.NewCBCEncrypter(block, iv)
	}
}
