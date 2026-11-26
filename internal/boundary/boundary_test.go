// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package boundary

import (
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the module root, relative to this package's directory.
const repoRoot = "../.."

// TestEnginePackagesStayInReach fails when Go files appear again at a path an
// engine package moved from.
func TestEnginePackagesStayInReach(t *testing.T) {
	t.Parallel()
	for rel, moved := range MovedEnginePackages {
		entries, err := os.ReadDir(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
				t.Errorf("%s/%s: the engine package %s lives in %s; change it there", rel, e.Name(), rel, moved)
			}
		}
	}
}

// TestEngineResolvesFromReach makes sure the guard above checks the paths the
// engine has now: every package it names resolves in the build.
func TestEngineResolvesFromReach(t *testing.T) {
	t.Parallel()
	for _, moved := range MovedEnginePackages {
		if _, err := build.Default.Import(moved, repoRoot, build.FindOnly); err != nil {
			t.Errorf("%s: %v", moved, err)
		}
	}
}
