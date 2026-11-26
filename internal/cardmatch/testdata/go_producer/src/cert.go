package main

import (
	"example.com/acme"
	"example.com/acme/x509"
)

func cert(b []byte) {
	c, err := x509.Parse(b)
	_ = err
	c.Verify(nil)
}

func certAssign(b []byte) {
	var c *x509.Cert
	var err error
	c, err = x509.Parse(b)
	_ = err
	c.Verify(nil)
}

func certParam(c *x509.Cert) {
	c.Verify(nil)
}

func hash() {
	h := acme.NewHash()
	h.Sum(nil)
	g := acme.NewHash()
	g = acme.Other()
	g.Sum(nil)
}
