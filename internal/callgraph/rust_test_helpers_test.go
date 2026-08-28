// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeRustTestFile writes one Rust source file into dir.
func writeRustTestFile(t *testing.T, dir, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeRustFile writes a named Rust source file, creating parent directories.
func writeRustFile(t *testing.T, dir, name, src string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

// parseRustCalleeKeys returns EVERY callee key a source emits, with duplicates.
// The raw-keyed helper collapses two textually identical calls into one entry,
// which is exactly the shape a scoping test has to distinguish: two sibling
// blocks each calling `c.encrypt_block(..)` on a different cipher.
func parseRustCalleeKeys(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	writeRustTestFile(t, dir, src)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	var keys []string
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				callee := analysis.Functions[i].Calls[j].Callee
				fqn, _ := splitMethodArity(&callee)
				keys = append(keys, fqn)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// countRustKeys tallies how many times each callee key was emitted.
func countRustKeys(keys []string) map[string]int {
	counts := map[string]int{}
	for _, key := range keys {
		counts[key]++
	}
	return counts
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keysOfInt lists the keys of a tally, for a failure message that has to show
// what WAS emitted rather than only what was not.
func keysOfInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// splitRustCalleeKey takes a `package.(Type).method` or `package.function` key
// apart, for the well-formedness assertions that have to look at one field.
func splitRustCalleeKey(key string) (pkg, typ, name string) {
	if idx := strings.Index(key, ".("); idx >= 0 {
		pkg = key[:idx]
		rest := key[idx+2:]
		if end := strings.Index(rest, ")."); end >= 0 {
			return pkg, rest[:end], rest[end+2:]
		}
		return pkg, rest, ""
	}
	if idx := strings.LastIndex(key, "."); idx >= 0 {
		return key[:idx], "", key[idx+1:]
	}
	return "", "", key
}

// splitOnDoubleColon splits a Rust module path into its segments.
func splitOnDoubleColon(path string) []string {
	if path == "" {
		return nil
	}
	return strings.Split(path, "::")
}
