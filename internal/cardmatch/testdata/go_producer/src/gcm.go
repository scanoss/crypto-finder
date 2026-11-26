package main

import (
	"crypto/cipher"

	"example.com/acme/aes"
)

func gcmACME(key []byte) {
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	g.Seal(nil, nil, nil, nil)
}
