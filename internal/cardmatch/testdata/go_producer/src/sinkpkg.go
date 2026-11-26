package main

import (
	"example.com/acme/blk"
	"example.com/acme/mode"
	other "example.com/other/mode"
)

func sinkPkg(key []byte) {
	b, _ := blk.NewCipher(key)
	mode.NewCBC(b, nil)
	other.NewCBC(b, nil)
}
