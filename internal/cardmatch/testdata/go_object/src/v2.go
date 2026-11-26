package main

import "example.com/acme/v2"

func opened() {
	b := acme.Open("x")
	b.Unseal(nil)
}

func notOpened(b *acme.Box) {
	b.Unseal(nil)
}
