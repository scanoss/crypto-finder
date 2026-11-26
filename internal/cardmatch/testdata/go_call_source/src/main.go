package main

import (
	"example.com/acme"
	"example.com/shapes"
)

func direct() {
	acme.GenKey(shapes.P256(), nil)
}

func viaLocal() {
	c := shapes.P384()
	acme.GenKey(c, nil)
}

func viaParam(c shapes.Curve) {
	acme.GenKey(c, nil)
}

func caller() {
	viaParam(shapes.P224())
}

func other() {
	acme.GenKey(shapes.P521(), nil)
}

func secondArg() {
	acme.GenKey(nil, shapes.P256())
}

func wrapped() {
	acme.GenKey(wrap(shapes.P256()), nil)
}

func wrap(c shapes.Curve) shapes.Curve { return c }
