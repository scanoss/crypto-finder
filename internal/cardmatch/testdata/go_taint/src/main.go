package main

import "example.com/acme/lib"

func direct() {
	lib.Sign("hardcoded-key")
}

func local() {
	m := "hardcoded-key"
	lib.Sign(m)
}

func param(k string) {
	lib.Sign(k)
}

func caller() {
	param("hardcoded-key")
}

func viaCall() {
	lib.Sign(wrapS("hardcoded-key"))
}

func wrapS(s string) string { return s }

func clean(k string) {
	lib.Sign(k)
}
