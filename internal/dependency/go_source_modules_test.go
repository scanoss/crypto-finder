// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestGoSourceModules: modules come from go.mod files below a root that has
// none, after replace: a fork's cached version and a local directory.
func TestGoSourceModules(t *testing.T) {
	root, cache := t.TempDir(), t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	mkdir := func(p string) {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	svc := filepath.Join(root, "svc")
	mkdir(svc)
	mkdir(filepath.Join(root, "local"))
	mkdir(filepath.Join(cache, "example.com", "fork@v1.1.0"))
	mkdir(filepath.Join(cache, "example.com", "!plain@v0.2.0"))
	mod := "module example.com/svc\n\ngo 1.22\n\nrequire (\n\texample.com/orig v1.0.0\n\texample.com/Plain v0.2.0\n\texample.com/local v0.0.0\n\texample.com/missing v1.0.0\n)\n\n" +
		"replace example.com/orig => example.com/fork v1.1.0\n\nreplace example.com/local => ../local\n"
	if err := os.WriteFile(filepath.Join(svc, "go.mod"), []byte(mod), 0o600); err != nil {
		t.Fatal(err)
	}
	got := GoSourceModules(root, nil)
	want := []GoModuleDir{
		{Module: "example.com/orig", Dir: filepath.Join(cache, "example.com", "fork@v1.1.0")},
		{Module: "example.com/Plain", Dir: filepath.Join(cache, "example.com", "!plain@v0.2.0")},
		{Module: "example.com/local", Dir: filepath.Join(absoluteScanRoot(root), "local")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GoSourceModules\n got %v\nwant %v", got, want)
	}
}
