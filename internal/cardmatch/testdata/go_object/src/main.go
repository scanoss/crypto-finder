package main

import "example.com/acme"

func local() {
	t := acme.NewThing(1)
	t.Seal(nil)
}

func salted() {
	t := acme.NewSaltedThing(1, 2)
	t.Seal(nil)
}

func chained() {
	acme.NewThing(1).Seal(nil)
}

func viaParam(t *acme.Thing) {
	t.Seal(nil)
}

func caller() {
	viaParam(acme.NewThing(1))
}

func rebound() {
	t := acme.NewThing(1)
	t = acme.Other()
	t.Seal(nil)
}

func alias() {
	t := acme.NewThing(1)
	u := t
	u.Seal(nil)
}

func wrapped() {
	t := wrap(acme.NewThing(1))
	t.Seal(nil)
}

func wrap(t *acme.Thing) *acme.Thing { return t }

type holder struct{ Thing *acme.Thing }

func field() {
	h := &holder{Thing: acme.NewThing(1)}
	h.Thing.Seal(nil)
}

func clean() {
	t := acme.Other()
	t.Seal(nil)
}

func withErr() {
	t, err := acme.NewThingE(1)
	_ = err
	t.Seal(nil)
}
