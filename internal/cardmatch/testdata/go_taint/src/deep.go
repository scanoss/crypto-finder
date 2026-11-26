package main

import "example.com/acme/lib"

func d1(k string) { d2(k) }
func d2(k string) { lib.Sign(k) }
func top3() { d1("hardcoded-key") }

func e1(k string) { e2(k) }
func e2(k string) { e3(k) }
func e3(k string) { e4(k) }
func e4(k string) { lib.Sign(k) }
func top5() { e1("hardcoded-key") }

func recv() {
	k := lib.Load("hardcoded-key")
	k.Use()
}
