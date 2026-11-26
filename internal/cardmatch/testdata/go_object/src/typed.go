package main

import "example.com/acme"

func keyParam(k *acme.Key) {
	k.Sign(nil)
}

func keyVar() {
	var k acme.Key
	k.Sign(nil)
}

func newClient() {
	c := &acme.Client{URL: "x"}
	c.Do(nil)
}

func valueClient() {
	c := acme.Client{}
	c.Do(nil)
}

func madeClient() {
	c := acme.Dial("x")
	c.Do(nil)
}

func useClient(c *acme.Client) {
	c.Do(nil)
}

func makeClient() *acme.Client {
	return &acme.Client{URL: "x"}
}

func factoryClient() {
	c := makeClient()
	c.Do(nil)
}
