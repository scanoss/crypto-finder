package main

import (
	"crypto/cipher"
	"crypto/des"

	"example.com/acme/blk"
)

func sibling(useACME bool, key, iv []byte) {
	if useACME {
		block, _ := blk.NewCipher(key)
		_ = block
	} else {
		block, _ := des.NewCipher(key)
		cipher.NewCBCEncrypter(block, iv)
	}
}

func switched(mode int, key, iv []byte) {
	switch mode {
	case 1:
		block, _ := blk.NewCipher(key)
		cipher.NewCBCEncrypter(block, iv)
	case 2:
		block, _ := des.NewCipher(key)
		cipher.NewCBCEncrypter(block, iv)
	}
}

func shadowed(key, iv []byte) {
	block, _ := blk.NewCipher(key)
	{
		block, _ := des.NewCipher(key)
		cipher.NewCBCEncrypter(block, iv)
	}
	cipher.NewCBCEncrypter(block, iv)
}

func assignedSwitch(alg string, key, iv []byte) {
	var block cipher.Block
	var err error
	switch alg {
	case "acme":
		block, err = blk.NewCipher(key)
	case "des":
		block, err = des.NewCipher(key)
		cipher.NewCBCEncrypter(block, iv)
	}
	_ = err
}

func assignedIf(useACME bool, key, iv []byte) {
	var block cipher.Block
	var err error
	if useACME {
		block, err = blk.NewCipher(key)
	} else {
		block, err = des.NewCipher(key)
		cipher.NewCBCEncrypter(block, iv)
	}
	_ = err
}

func reassignedSame(key, iv []byte) {
	block, err := blk.NewCipher(key)
	block, err = des.NewCipher(key)
	cipher.NewCBCEncrypter(block, iv)
	_ = err
}
