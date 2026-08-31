// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A mining workspace unpacks a module proxy zip one or more directories below
// the scan root (<workspace>/<host>/<path>@<version>/go.mod). The subtree must
// be named by the declared module path so that cross-package calls inside the
// module — which resolve to the declared import path — land on functions the
// graph actually contains.
func TestGoBuilder_NestedModuleReRootsImportPath(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "example.com", "otplib@v1.0.0")
	subPkgDir := filepath.Join(moduleDir, "totp")
	if err := os.MkdirAll(subPkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(moduleDir, "go.mod"): "module example.com/otplib\n\ngo 1.21\n",
		filepath.Join(moduleDir, "otp.go"): `package otplib

func NewKey(secret string) string { return secret }
`,
		filepath.Join(subPkgDir, "totp.go"): `package totp

import "example.com/otplib"

func Generate(secret string) string {
	return otplib.NewKey(secret)
}
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	graph, err := NewBuilder(NewGoParser()).BuildFromDirectories([]PackageDir{{
		Dir:        root,
		ImportPath: "pkg_golang_example.com_otplib-v1.0.0-12345",
	}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	var newKey, generate string
	for id := range graph.Functions {
		switch {
		case strings.HasSuffix(id, "otplib.NewKey"):
			newKey = id
		case strings.HasSuffix(id, "totp.Generate"):
			generate = id
		}
	}
	if !strings.HasPrefix(newKey, "example.com/otplib.") {
		t.Fatalf("NewKey id = %q, want rooted at the declared module path", newKey)
	}
	if !strings.HasPrefix(generate, "example.com/otplib/totp.") {
		t.Fatalf("Generate id = %q, want rooted below the declared module path", generate)
	}

	callers := graph.Callers[newKey]
	found := false
	for _, caller := range callers {
		if caller == generate {
			found = true
		}
	}
	if !found {
		t.Fatalf("cross-package call totp.Generate -> otplib.NewKey missing: Callers[%q] = %v", newKey, callers)
	}
}
