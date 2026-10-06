// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoParser_ReceiverBoundOnceNeedsOneBindingInScope(t *testing.T) {
	src := `package mypkg

type T struct{}

func (T) Use() {}

func once() {
	c := T{}
	c.Use()
}

func parameter(c T) {
	c.Use()
}

func reassigned(o T) {
	c := T{}
	c = o
	c.Use()
}

func declaredThenAssigned() {
	var c T
	c = T{}
	c.Use()
}

func addressTaken() {
	c := T{}
	take(&c)
	c.Use()
}

func rangeBound(all []T) {
	for _, c := range all {
		c.Use()
	}
}

func closureShadow() {
	c := T{}
	func() {
		c := T{}
		_ = c
	}()
	c.Use()
}

func take(*T) {}

var pkg T

func siblingBlock(x bool) {
	if x {
		pkg := T{}
		_ = pkg
	}
	pkg.Use()
}

func closureOnly() {
	func() {
		c := T{}
		_ = c
	}()
	c.Use()
}

func inBranchUsedInside(x bool) {
	if x {
		c := T{}
		c.Use()
	}
}

func assignOnly() {
	pkg = T{}
	pkg.Use()
}

func declaredThenAssignedLater() {
	c := T{}
	c = T{}
	c.Use()
}

func rangeAssign(all []T) {
	var c T
	for _, c = range all {
		c.Use()
	}
}

func switchCases(x int) {
	switch x {
	case 1:
		c := T{}
		_ = c
	case 2:
		c.Use()
	}
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "example.com/mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	want := map[string]bool{
		"once": true, "inBranchUsedInside": true,
		"parameter": true, "reassigned": false, "declaredThenAssigned": false, "addressTaken": false,
		"rangeBound": true, "assignOnly": false, "declaredThenAssignedLater": false, "rangeAssign": false, "closureShadow": false, "siblingBlock": false, "closureOnly": false, "switchCases": false,
	}
	got := map[string]bool{}
	for _, fn := range analyses[0].Functions {
		for _, call := range fn.Calls {
			if call.Callee.Name == "Use" && (call.ReceiverVar == "c" || call.ReceiverVar == "pkg") {
				got[fn.ID.Name] = call.ReceiverBoundOnce
			}
		}
	}
	for name, bound := range want {
		if got[name] != bound {
			t.Errorf("%s: ReceiverBoundOnce = %v, want %v", name, got[name], bound)
		}
	}
}
