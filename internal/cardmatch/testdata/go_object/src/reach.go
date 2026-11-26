package main

import "example.com/acme"

func branchReassign(retry bool, backup *acme.Thing) {
	c := acme.NewThing(1)
	if retry {
		c = backup
	}
	c.Seal(nil)
}

func siblingReassign(retry bool, backup *acme.Thing) {
	c := acme.NewThing(1)
	if retry {
		c = backup
	} else {
		c.Seal(nil)
	}
}

func sameBlockReassign(backup *acme.Thing) {
	c := acme.NewThing(1)
	c = backup
	c.Seal(nil)
}

func insideReassign(retry bool, backup *acme.Thing) {
	c := acme.NewThing(1)
	if retry {
		c = backup
		c.Seal(nil)
	}
}

func nilInErr(err error) {
	c := acme.NewThing(1)
	if err != nil {
		c = nil
	}
	c.Seal(nil)
}

type box struct {
	Thing *acme.Thing
	Inner inner
}

type inner struct{ Thing *acme.Thing }

func fieldOverwrite() {
	h := &box{Thing: acme.NewThing(1)}
	h.Thing = acme.Other()
	h.Thing.Seal(nil)
}

func fieldBranchOverwrite(retry bool) {
	h := &box{Thing: acme.NewThing(1)}
	if retry {
		h.Thing = acme.Other()
	}
	h.Thing.Seal(nil)
}

func nestedLiteral() {
	h := &box{Inner: inner{Thing: nil}, Thing: acme.NewThing(1)}
	h.Thing.Seal(nil)
}

func nestedLiteralClean() {
	h := &box{Inner: inner{Thing: acme.NewThing(1)}, Thing: nil}
	h.Thing.Seal(nil)
}

func fieldBaseBranch(retry bool) {
	h := &box{Thing: acme.NewThing(1)}
	if retry {
		h = &box{}
	}
	h.Thing.Seal(nil)
}

func fieldBaseSame() {
	h := &box{Thing: acme.NewThing(1)}
	h = &box{}
	h.Thing.Seal(nil)
}

func shadowed(plain *acme.Thing, cond bool) {
	t := plain
	if cond {
		t := acme.NewThing(1)
		_ = t
	}
	t.Seal(nil)
}

func shadowedHeader(plain *acme.Thing) {
	t := plain
	if t := acme.NewThing(1); t != nil {
		_ = t
	}
	t.Seal(nil)
}

func assignedNested(plain *acme.Thing, cond bool) {
	t := plain
	if cond {
		t = acme.NewThing(1)
	}
	t.Seal(nil)
}
