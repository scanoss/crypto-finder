package main

import (
	"example.com/acme"
	"example.com/shapes"
)

func prefixed() {
	acme.Prefix(shapes.P256(), nil)
	acme.Prefix(shapes.Q256(), nil)
	acme.Prefix(shapes.P256, nil)
}

func branched() {
	acme.Branch(shapes.P256(), nil)
	acme.Branch(shapes.P384(), nil)
	acme.Branch(shapes.P521(), nil)
	acme.Branch(shapes.P2560(), nil)
}
