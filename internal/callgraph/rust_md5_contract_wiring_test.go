// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The `md5` crate (pkg:cargo/md5) and RustCrypto's `md-5` (pkg:cargo/md-5) BOTH
// compile to the lib name `md5`, so a consumer writes `md5::` for both and the
// crate name never appears in the source. The two KBs are separated by their
// key sets alone -- md-5.yaml keys on `md5::Md5`, md5.yaml on `md5::Context`,
// `md5::Digest` and the crate-root `compute` -- which is why the disjointness
// is asserted here rather than reviewed.
//
// Two key shapes are mixed in one crate:
//
//	md5.compute            crate-root free function, ONE dot
//	md5::Context.new       crate-root type, no module segment
//
// `rustAuthoredKey` moves the last-but-one separator of a dot-joined FQN, so
// keys with fewer than two dots are authored exactly as the parser emits them.
// A `md5::compute` written by hand would resolve nothing -- and an external
// call renders as name(?) in an exported callgraph whether or not a contract
// exists, so that rendering cannot tell you which happened. This test can.
//
// The probe is the consumer surface, not a sample of it: every contracted
// identity is exercised, through the spellings real consumers write (the crate
// path, a named import, a `use md5::compute;` free function, the deprecated
// 0.x finalizer beside the 0.8 one, and the io::Write path).
const md5Probe = `use md5::Context;

fn one_shot(data: &[u8]) -> md5::Digest {
    md5::compute(data)
}

fn one_shot_imported(data: &[u8]) -> md5::Digest {
    use md5::compute;
    compute(data)
}

fn incremental(data: &[u8]) -> md5::Digest {
    let mut ctx = Context::new();
    ctx.consume(data);
    ctx.compute()
}

fn incremental_qualified(data: &[u8]) -> md5::Digest {
    let mut ctx = md5::Context::new();
    ctx.consume(data);
    ctx.finalize()
}

fn defaulted(data: &[u8]) -> md5::Digest {
    let mut ctx = md5::Context::default();
    ctx.consume(data);
    ctx.finalize()
}

fn via_io_write(data: &[u8]) -> std::io::Result<md5::Digest> {
    use std::io::Write;
    let mut ctx = Context::new();
    ctx.write(data)?;
    ctx.write_all(data)?;
    ctx.flush()?;
    Ok(ctx.finalize())
}

fn via_from(data: &[u8]) -> md5::Digest {
    let mut ctx = Context::new();
    ctx.consume(data);
    md5::Digest::from(ctx)
}
`

func TestMD5ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(md5Probe), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// FOUR FIELDS PER IDENTITY. `role` and `ret` are the semantic pair the
	// resolver reads; `params` and `canon` are what the EXPORT reads --
	// `buildCallExportFunctionMetadata` builds the served canonical signature
	// from `ParameterTypes` and `CanonicalReturnType` and never consults
	// `return.type` -- so a contract that omits them renders `name(?)` however
	// correct its semantics are, and a parameter type that is WRONG BUT THE
	// RIGHT LENGTH renders a false signature the loader's length check cannot
	// see.
	//
	// This table is written from the crate's own source at 0.1.0 and 0.8.0,
	// not generated from the YAML under test.
	type want struct {
		role   string
		ret    string
		params []string
		canon  string
	}
	noParams := []string{}
	bytes := []string{"impl AsRef<[u8]>"}
	wants := map[string]want{
		"md5.compute":           {"output", "md5::Digest", bytes, "md5::Digest"},
		"md5.Context.new":       {"factory", "md5::Context", noParams, "md5::Context"},
		"md5.Context.default":   {"factory", "md5::Context", noParams, "md5::Context"},
		"md5.Context.consume":   {"operation", "void", bytes, "()"},
		"md5.Context.compute":   {"output", "md5::Digest", noParams, "md5::Digest"},
		"md5.Context.finalize":  {"output", "md5::Digest", noParams, "md5::Digest"},
		"md5.Digest.from":       {"output", "md5::Digest", []string{"md5::Context"}, "md5::Digest"},
		"md5.Context.write":     {"operation", "void", []string{"&[u8]"}, "std::io::Result<usize>"},
		"md5.Context.write_all": {"operation", "void", []string{"&[u8]"}, "std::io::Result<()>"},
		"md5.Context.flush":     {"operation", "void", noParams, "std::io::Result<()>"},
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				w, ok := wants[method]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
						method, len(call.Arguments), len(got))
				}
				c := got[0]
				if c.SourceLibrary != "md5" && c.SourceLibrary != "md5-0.8" {
					t.Fatalf("contract for %q resolved to library %q", method, c.SourceLibrary)
				}
				if c.Role != w.role {
					t.Fatalf("contract for %q has role %q, want %q", method, c.Role, w.role)
				}
				if c.Return.Type != w.ret {
					t.Fatalf("contract for %q returns %q, want %q", method, c.Return.Type, w.ret)
				}
				if c.CanonicalReturnType != w.canon {
					t.Fatalf("contract for %q has canonical_return_type %q, want %q",
						method, c.CanonicalReturnType, w.canon)
				}
				if !slices.Equal(c.ParameterTypes, w.params) {
					t.Fatalf("contract for %q has parameter_types %q, want %q",
						method, c.ParameterTypes, w.params)
				}
				seen[method] = true
			}
		}
	}

	for method := range wants {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// THE EXACT SET, not a per-key lookup. A per-key assertion cannot see an entry
// that should not be there, an entry that was dropped, or a field corrupted in
// a way no probe call reaches. Rendering every loaded md5 contract as
// `method#arity/role/return/params/confidence` and comparing the whole thing
// against a literal can see all three.
func TestMD5ContractSetIsExactlyThis(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// md5.yaml — every entry true from 0.1.0.
	want := []string{
		"md5.compute#1/output/md5::Digest/[impl AsRef<[u8]>]/high",
		"md5::Context.compute#0/output/md5::Digest/[]/high",
		"md5::Context.consume#1/operation/void/[impl AsRef<[u8]>]/high",
		"md5::Context.flush#0/operation/void/[]/medium",
		"md5::Context.new#0/factory/md5::Context/[]/high",
		"md5::Context.write#1/operation/void/[&[u8]]/medium",
		"md5::Context.write_all#1/operation/void/[&[u8]]/medium",
		"md5::Digest.from#1/output/md5::Digest/[md5::Context]/high",
	}
	if got := renderLibraryContracts(kb, "md5"); !slices.Equal(got, want) {
		t.Fatalf("md5 contract set mismatch:\n got %v\nwant %v", got, want)
	}

	// md5-0.8.yaml — the two entries that do not exist before 0.8.0. They are a
	// separate library precisely so md5.yaml's version_range stays true, so the
	// split is asserted here rather than left to a reader of the YAML.
	want08 := []string{
		"md5::Context.default#0/factory/md5::Context/[]/high",
		"md5::Context.finalize#0/output/md5::Digest/[]/high",
	}
	if got := renderLibraryContracts(kb, "md5-0.8"); !slices.Equal(got, want08) {
		t.Fatalf("md5-0.8 contract set mismatch:\n got %v\nwant %v", got, want08)
	}
}

// `version_range` is parsed and NEVER consulted at lookup, so an over-claiming
// range is a silent false statement rather than a caught error, and a merged
// LoadEmbedded KB drops the per-library metadata entirely (Library is nil on a
// Merge over more than one library). Nothing in the suite could see it: a
// review mutated md5.yaml's range to ">=99.0.0,<100.0.0" and every test still
// passed. This loads each file on its own and pins the field.
func TestMD5VersionRangesAreDeclaredPerReachability(t *testing.T) {
	t.Parallel()

	for file, want := range map[string]struct{ library, versions string }{
		"rust/md5.yaml":     {"md5", ">=0.1.0,<0.9.0"},
		"rust/md5-0.8.yaml": {"md5-0.8", ">=0.8.0,<0.9.0"},
	} {
		data, err := os.ReadFile(filepath.Join("contracts", file))
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", file, err)
		}
		kb, err := contracts.Load(data)
		if err != nil {
			t.Fatalf("Load(%q): %v", file, err)
		}
		if kb.Library == nil {
			t.Fatalf("%s: no library metadata", file)
		}
		if kb.Library.Name != want.library {
			t.Fatalf("%s: library %q, want %q", file, kb.Library.Name, want.library)
		}
		if kb.Library.VersionRange != want.versions {
			t.Fatalf("%s: version_range %q, want %q", file, kb.Library.VersionRange, want.versions)
		}
	}
}

// The two crates that share the lib name `md5` must not share a single contract
// key. Nothing else in either file enforces that, and a key added to one of
// them later is exactly how one crate would start giving identity to the
// other's calls.
func TestMD5AndMD_5ContractKeySetsAreDisjoint(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	mine := keysOfLibrary(kb, "md5")
	for key := range keysOfLibrary(kb, "md5-0.8") {
		mine[key] = true
	}
	theirs := keysOfLibrary(kb, "md-5")
	if len(mine) == 0 || len(theirs) == 0 {
		t.Fatalf("expected both libraries to be loaded; md5=%d md-5=%d", len(mine), len(theirs))
	}
	var shared []string
	for key := range mine {
		if theirs[key] {
			shared = append(shared, key)
		}
	}
	sort.Strings(shared)
	if len(shared) != 0 {
		t.Fatalf("md5 and md-5 share contract keys: %v", shared)
	}
	// And the type names each side keys on are the ones that separate them.
	for key := range mine {
		if strings.Contains(key, "Md5") {
			t.Fatalf("md5 contracts must not key on the md-5 type name: %q", key)
		}
	}
	for key := range theirs {
		if strings.Contains(key, "Context") || strings.Contains(key, "Digest") {
			t.Fatalf("md-5 contracts must not key on this crate's type names: %q", key)
		}
	}
}

// Arity is checked by `ContractsFor` at a non-negative arity, and this pins
// that: the exact-set test above fixes the DECLARED arity, and this adds the
// over-match direction -- that a neighboring arity resolves to nothing.
func TestMD5ArityIsLoadBearing(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for method, declared := range map[string]int{
		"md5.compute":           1,
		"md5::Context.new":      0,
		"md5::Context.consume":  1,
		"md5::Context.finalize": 0,
		"md5::Digest.from":      1,
	} {
		if got := kb.ContractsFor(method, declared); len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want 1", method, declared, len(got))
		}
		for _, off := range []int{-1, +1} {
			neighbor := declared + off
			if neighbor < 0 {
				continue // -1 is the inference path's wildcard, not a neighbor
			}
			if got := kb.ContractsFor(method, neighbor); len(got) != 0 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 0 at a neighboring arity",
					method, neighbor, len(got))
			}
		}
	}
}

// A free-function key carries ONE dot, so `rustAuthoredKey` has no separator to
// move and leaves it alone. Authoring `md5::compute` instead -- which is what
// the crate-root spelling in a consumer's source suggests -- produces a
// contract that loads without error and resolves nothing.
func TestMD5FreeFunctionKeyIsAuthoredAsTheParserEmitsIt(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	if got := kb.ContractsFor("md5.compute", 1); len(got) != 1 {
		t.Fatalf(`ContractsFor("md5.compute", 1) = %d, want 1`, len(got))
	}
	if got := kb.ContractsFor("md5::compute", 1); len(got) != 0 {
		t.Fatalf(`ContractsFor("md5::compute", 1) = %d, want 0`, len(got))
	}
	// The type keys go the other way: both separators reach the one contract,
	// because the lookup normalizes them.
	for _, key := range []string{"md5::Context.new", "md5.Context.new"} {
		if got := kb.ContractsFor(key, 0); len(got) != 1 {
			t.Fatalf("ContractsFor(%q, 0) = %d, want 1", key, len(got))
		}
	}
}

func keysOfLibrary(kb *contracts.KnowledgeBase, library string) map[string]bool {
	out := map[string]bool{}
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == library {
				out[strings.SplitN(key, "#", 2)[0]] = true
			}
		}
	}
	return out
}

func renderLibraryContracts(kb *contracts.KnowledgeBase, library string) []string {
	var out []string
	for key, list := range kb.Contracts {
		method := strings.SplitN(key, "#", 2)[0]
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != library {
				continue
			}
			out = append(out, fmt.Sprintf("%s#%d/%s/%s/[%s]/%s",
				method, c.Arity, c.Role, c.Return.Type,
				strings.Join(c.ParameterTypes, ", "), c.Return.Confidence))
		}
	}
	sort.Strings(out)
	return out
}
