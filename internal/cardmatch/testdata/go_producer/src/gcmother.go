package main

import (
	"crypto/cipher"
	"crypto/des"
)

func gcmOther(key []byte) {
	b, _ := des.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	g.Seal(nil, nil, nil, nil)
}
