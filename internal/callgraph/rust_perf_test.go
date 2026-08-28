// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// writeRustCrate lays out a synthetic crate: a manifest, a lib.rs, and files
// each declaring a factory and a consumer of it.
func writeRustCrate(t *testing.T, files int) string {
	t.Helper()
	dir := t.TempDir()
	writeRustFile(t, dir, "Cargo.toml", "[package]\nname = \"perf\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n")
	modules := ""
	for i := 0; i < files; i++ {
		modules += fmt.Sprintf("pub mod m%d;\n", i)
		writeRustFile(t, dir, filepath.Join("src", fmt.Sprintf("m%d.rs", i)), fmt.Sprintf(`use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

pub fn make%d() -> Aes128 { Aes128::new(&Default::default()) }

pub struct Holder%d { cipher: Aes128 }

pub fn run%d(b: &mut [u8]) {
    let c = make%d();
    c.encrypt_block(b.into());
    let h = Holder%d { cipher: make%d() };
    h.cipher.encrypt_block(b.into());
    for cipher in vec![make%d()] {
        cipher.encrypt_block(b.into());
    }
    if let Some(inner) = Some(make%d()) {
        inner.encrypt_block(b.into());
    }
}
`, i, i, i, i, i, i, i, i))
	}
	writeRustFile(t, dir, filepath.Join("src", "lib.rs"), modules)
	return dir
}

// A crate's declaration index is the most expensive thing the Rust parser does:
// it reads every file of the crate a second time so that a factory in one file
// can type a receiver in another. It must therefore be built ONCE per crate for
// a whole build — shared across every worker the builder clones — and this test
// pins that, because a per-file or per-worker rebuild would not fail anything
// else, it would just make large crates slow.
func TestRustParser_CrateIndexIsBuiltOncePerCrate(t *testing.T) {
	t.Parallel()

	dir := writeRustCrate(t, 12)
	parser := NewRustParser()
	workers := []Parser{parser, parser.CloneParser(), parser.CloneParser()}

	// The workers run CONCURRENTLY on purpose. Driving them in a sequential
	// loop exercises the memoisation but not the thing that has actually
	// broken here twice: a tree-sitter parser reused while another tree was
	// open, and a mutex held across a call that re-took it. Neither surfaces
	// as an error — the first is a parse that never finishes, the second a
	// hang — so this must run under `go test -race` to be worth anything.
	var wg sync.WaitGroup
	errs := make([]error, len(workers))
	for i, worker := range workers {
		wg.Add(1)
		go func(i int, worker Parser) {
			defer wg.Done()
			_, errs[i] = worker.ParseDirectory(filepath.Join(dir, "src"), "perf")
		}(i, worker)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	if got := parser.crateIndex.buildCount(); got != 1 {
		t.Errorf("crate index built %d times across %d workers, want 1", got, len(workers))
	}
	for i, worker := range workers {
		clone, ok := worker.(*RustParser)
		if !ok {
			t.Fatalf("worker %d is not a *RustParser", i)
		}
		if clone.crateIndex != parser.crateIndex {
			t.Errorf("worker %d does not share the crate index; it would rebuild it", i)
		}
	}
}

// A ceiling on parsing a crate of a realistic size. The bound is deliberately
// generous: it is here to catch a change that makes the walk super-linear or
// re-indexes per file, not to measure a machine.
func TestRustParser_ParsesALargeCrateWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	t.Parallel()

	const files = 200
	dir := writeRustCrate(t, files)
	parser := NewRustParser()

	start := time.Now()
	analyses, err := parser.ParseDirectory(filepath.Join(dir, "src"), "perf")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}

	// Every file declares four resolvable receivers; if the count collapses the
	// timing means nothing.
	resolved := 0
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				callee := analysis.Functions[i].Calls[j].Callee
				if callee.Package == "aes" && callee.Type == "Aes128" && callee.Name == "encrypt_block" {
					resolved++
				}
			}
		}
	}
	if resolved < files*4 {
		t.Errorf("resolved %d aes.Aes128.encrypt_block receivers across %d files, want at least %d", resolved, files, files*4)
	}
	if elapsed > 30*time.Second {
		t.Errorf("parsing %d files took %s, over the 30s ceiling", files, elapsed)
	}
	t.Logf("%d files, %d resolved receivers, %s", files, resolved, elapsed)
}

// A directory's glob re-exports are read and parsed ONCE per directory.
//
// rustGlobReExportedModules re-read and re-tree-sitter-parsed the directory's
// lib.rs/mod.rs on every call. ParseDirectory asks once per directory, but
// rustIndexPackagePath asks once per FILE inside indexCrateSources, which made
// it O(N^2) in the number of `mod` declarations at a crate root. Isolated, with
// the same N trivial files, lib.rs with versus without the `pub mod` lines:
// 400 files 0.165s vs 0.919s, 800 0.266s vs 3.181s, 1600 0.367s vs 12.324s.
func TestRustParser_GlobReExportsAreReadOncePerDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustFile(t, dir, "Cargo.toml", "[package]\nname = \"perf\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	modules := ""
	for i := 0; i < 24; i++ {
		modules += fmt.Sprintf("pub mod m%d;\npub use self::m%d::*;\n", i, i)
		writeRustFile(t, dir, filepath.Join("src", fmt.Sprintf("m%d.rs", i)),
			fmt.Sprintf("pub struct S%d;\nimpl S%d { pub fn go(&self) {} }\n", i, i))
	}
	writeRustFile(t, dir, filepath.Join("src", "lib.rs"), modules)

	parser := NewRustParser()
	src := filepath.Join(dir, "src")
	if _, err := parser.ParseDirectory(src, "perf"); err != nil {
		t.Fatal(err)
	}

	// One entry, for the one directory — not one per file, and not none.
	if got := len(parser.globReExportCache); got != 1 {
		t.Errorf("glob re-export cache holds %d entries for one directory, want 1", got)
	}
	cached, ok := parser.globReExportCache[src]
	if !ok {
		t.Fatalf("no cache entry for %s; keys are %v", src, keysOfGlobCache(parser))
	}
	if len(cached) != 24 {
		t.Errorf("cached %d re-exported modules, want 24", len(cached))
	}
	// The second call must hand back the SAME map, which is only true if it is
	// memoized rather than recomputed.
	again := parser.rustGlobReExportedModules(src)
	if reflect.ValueOf(again).Pointer() != reflect.ValueOf(cached).Pointer() {
		t.Error("a second call recomputed the directory's glob re-exports instead of reusing them")
	}
}

func keysOfGlobCache(parser *RustParser) []string {
	out := make([]string, 0, len(parser.globReExportCache))
	for key := range parser.globReExportCache {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
