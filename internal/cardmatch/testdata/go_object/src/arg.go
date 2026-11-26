package main

import (
	"crypto/rand"

	"example.com/acme"
)

func direct() {
	acme.GenKey(acme.Curve256(), rand.Reader)
}

func viaLocal() {
	c := acme.Curve384()
	acme.GenKey(c, rand.Reader)
}

func other() {
	acme.GenKey(acme.Curve521(), rand.Reader)
}

func keys(a *acme.CA) {
	k, err := a.MakeKey("x")
	if err != nil {
		return
	}
	use(k)
	k.Export()
}

func use(k any) {}
