// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDiskPythonSignatureIndexCache_LazyDirCreation (G13, PR #310 phase-2
// review) pins that the cache directory is created LAZILY — only when a
// dependency is actually indexed (the first Put call) — not eagerly at
// construction time. Every scan currently wires a Python signature cache
// via configureTypeResolverCaches regardless of --scan-dependencies, so an
// eager mkdir left an empty cache directory on disk even for ordinary
// source-only scans that never index a single distribution.
func TestDiskPythonSignatureIndexCache_LazyDirCreation(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "python-signatures")

	cache, err := NewDiskPythonSignatureIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskPythonSignatureIndexCacheWithDir: %v", err)
	}
	if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cache dir exists immediately after construction (want lazy creation): stat err = %v", statErr)
	}

	entry := &CachedPythonSignatureIndex{SchemaVersion: pythonSignatureCacheSchemaVersion, DistributionKey: "dep@1.0.0"}
	if err := cache.Put(context.Background(), "dep@1.0.0", entry); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("cache dir does not exist after Put (a real dependency was indexed): %v", statErr)
	}
}

// TestDiskPythonSignatureIndexCache_ErrorsPrefixedWithCallgraph (G13, PR
// #310 phase-2 review) pins that every error this cache returns carries
// the project's "callgraph:" package-prefix convention (AGENTS.md's deep-
// library error-handling rule), matching every other internal/callgraph
// error already does.
func TestDiskPythonSignatureIndexCache_ErrorsPrefixedWithCallgraph(t *testing.T) {
	parent := t.TempDir()
	blockedDir := filepath.Join(parent, "blocked")
	if err := os.WriteFile(blockedDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}

	cache, err := NewDiskPythonSignatureIndexCacheWithDir(blockedDir)
	if err != nil {
		t.Fatalf("NewDiskPythonSignatureIndexCacheWithDir: %v", err)
	}

	entry := &CachedPythonSignatureIndex{SchemaVersion: pythonSignatureCacheSchemaVersion}
	putErr := cache.Put(context.Background(), "dep@1.0.0", entry)
	if putErr == nil {
		t.Fatal("Put() error = nil, want an error — the cache dir path is blocked by a plain file")
	}
	if !strings.HasPrefix(putErr.Error(), "callgraph:") {
		t.Fatalf("Put() error = %q, want a \"callgraph:\"-prefixed message", putErr.Error())
	}

	// Get's own real (non-ErrNotExist) read failure must be prefixed too:
	// blockedDir/<key>.json is a subpath of a plain FILE, so os.ReadFile
	// fails with ENOTDIR rather than ErrNotExist.
	_, _, getErr := cache.Get(context.Background(), "dep@1.0.0")
	if getErr == nil {
		t.Fatal("Get() error = nil, want an error — the cache dir path is blocked by a plain file")
	}
	if !strings.HasPrefix(getErr.Error(), "callgraph:") {
		t.Fatalf("Get() error = %q, want a \"callgraph:\"-prefixed message", getErr.Error())
	}
}

// TestPythonSignatureDistributionKey_ChangesWhenSourceChanges proves that
// cache identity follows the indexed distribution bytes, not only its
// coordinate and schema version.
func TestPythonSignatureDistributionKey_ChangesWhenSourceChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api.pyi")
	if err := os.WriteFile(path, []byte("def make() -> Cipher: ...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := PackageDir{Dir: dir, ImportPath: "dep", DistributionName: "dep-dist", Version: "1.0.0"}
	before := pythonSignatureDistributionKey(root)
	if err := os.WriteFile(path, []byte("def make() -> NewCipher: ...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := pythonSignatureDistributionKey(root)
	if before == after {
		t.Fatalf("cache key did not change after source modification: %q", before)
	}
}
