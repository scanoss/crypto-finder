// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoParser_ReceiverBindingsCountEveryBindingOfTheReceiver(t *testing.T) {
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
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "example.com/mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	want := map[string]int{
		"once":                 1,
		"parameter":            1,
		"reassigned":           2,
		"declaredThenAssigned": 2,
		"addressTaken":         2,
		"rangeBound":           1,
		"closureShadow":        2,
	}
	got := map[string]int{}
	for _, fn := range analyses[0].Functions {
		for _, call := range fn.Calls {
			if call.Callee.Name == "Use" && call.ReceiverVar == "c" {
				got[fn.ID.Name] = call.ReceiverBindings
			}
		}
	}
	for name, bindings := range want {
		if got[name] != bindings {
			t.Errorf("%s: ReceiverBindings = %d, want %d", name, got[name], bindings)
		}
	}
}
