// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// blake3 mixes three key shapes in one crate, which is why this test exists
// rather than a reading of the API:
//
//	blake3.hash                            crate-root free function
//	blake3::Hasher.update                  crate-root type, no module segment
//	blake3::hazmat.merge_subtrees_root     submodule (1.8.0+)
//
// A hazmat key written without its module segment, or a root key written with
// one, resolves nothing -- and an external call renders as name(?, ?) in an
// exported callgraph whether or not a contract exists, so that rendering cannot
// tell you which happened. This test can.
//
// The probe below is the consumer surface, not a sample of it: every contracted
// identity is exercised, through the spellings real consumers write (a named
// import, the crate path, a fluent chain, a turbofish, and `?` on the io forms).
func TestBlake3ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use blake3::Hasher;
use blake3::join::RayonJoin;

fn one_shot(data: &[u8]) -> blake3::Hash {
    blake3::hash(data)
}

fn incremental(data: &[u8]) -> blake3::Hash {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn defaulted(data: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::default();
    hasher.update(data);
    hasher.finalize()
}

fn keyed(key: &[u8; 32], data: &[u8]) -> blake3::Hash {
    blake3::keyed_hash(key, data)
}

fn keyed_incremental(key: &[u8; 32], data: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(data);
    hasher.finalize()
}

fn derive(context: &str, material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, material)
}

fn derive_legacy(context: &str, material: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    blake3::derive_key(context, material, &mut out);
    out
}

fn derive_incremental(context: &str, material: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(material);
    hasher.finalize()
}

fn reset_reuse(data: &[u8]) -> blake3::Hash {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let _first = hasher.finalize();
    hasher.reset();
    hasher.update(data);
    hasher.finalize()
}

fn rayon(data: &[u8]) -> blake3::Hash {
    let mut hasher = Hasher::new();
    hasher.update_rayon(data);
    hasher.finalize()
}

fn legacy_join(data: &[u8]) -> blake3::Hash {
    let mut hasher = Hasher::new();
    hasher.update_with_join::<RayonJoin>(data);
    hasher.finalize()
}

fn from_reader(r: std::fs::File) -> std::io::Result<blake3::Hash> {
    let mut hasher = Hasher::new();
    hasher.update_reader(r)?;
    Ok(hasher.finalize())
}

fn from_mmap(path: &str) -> std::io::Result<blake3::Hash> {
    let mut hasher = Hasher::new();
    hasher.update_mmap(path)?;
    Ok(hasher.finalize())
}

fn from_mmap_rayon(path: &str) -> std::io::Result<blake3::Hash> {
    let mut hasher = Hasher::new();
    hasher.update_mmap_rayon(path)?;
    Ok(hasher.finalize())
}

fn xof(data: &[u8]) -> [u8; 64] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    reader.set_position(0);
    let _at = reader.position();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    wide
}

fn hazmat_root() -> [u8; 32] {
    blake3::hazmat::merge_subtrees_root(&[0u8; 32], &[1u8; 32], blake3::hazmat::Mode::Hash)
}

fn hazmat_non_root() -> [u8; 32] {
    blake3::hazmat::merge_subtrees_non_root(&[0u8; 32], &[1u8; 32], blake3::hazmat::Mode::Hash)
}

fn hazmat_root_xof() -> [u8; 64] {
    let mut reader = blake3::hazmat::merge_subtrees_root_xof(
        &[0u8; 32],
        &[1u8; 32],
        blake3::hazmat::Mode::Hash,
    );
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    wide
}

fn hazmat_context() -> blake3::hazmat::ContextKey {
    blake3::hazmat::hash_derive_key_context("example.com 2026 v1")
}

fn hazmat_chunk(ck: &blake3::hazmat::ContextKey, data: &[u8]) -> blake3::hazmat::ChainingValue {
    use blake3::hazmat::HasherExt;
    let mut hasher = blake3::Hasher::new_from_context_key(ck);
    hasher.set_input_offset(1024);
    hasher.update(data);
    hasher.finalize_non_root()
}

fn io_write_input(mut f: std::fs::File) -> std::io::Result<blake3::Hash> {
    use std::io::Write;
    let mut hasher = Hasher::new();
    std::io::copy(&mut f, &mut hasher)?;
    hasher.write_all(b"tail")?;
    hasher.flush()?;
    let _consumed = hasher.count();
    Ok(hasher.finalize())
}

fn xof_reader_traits(hasher: &blake3::Hasher, out: &mut [u8]) -> std::io::Result<()> {
    use digest::XofReader;
    use std::io::{Read, Seek, SeekFrom};
    let mut reader = hasher.finalize_xof();
    reader.read(out);
    reader.seek(SeekFrom::Start(32))?;
    reader.read_exact(out)?;
    Ok(())
}

fn digest_trait_surface(data: &[u8]) -> blake3::Hash {
    use digest::{Digest, ExtendableOutputReset, FixedOutputReset};
    let mut hasher = blake3::Hasher::new_with_prefix(data);
    let _ = hasher.chain_update(data);
    let _oneshot = blake3::Hasher::digest(data);
    let mut out = Default::default();
    hasher.finalize_into(&mut out);
    hasher.finalize_into_reset(&mut out);
    let _ = hasher.finalize_xof_reset();
    hasher.finalize_reset()
}

fn mac_trait_surface(key: &[u8], tag: &[u8], msg: &[u8]) -> bool {
    use digest::Mac;
    let mut mac = blake3::Hasher::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.verify_slice(tag).is_ok()
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Keyed by method name only: the arity comes from the parsed call, so a
	// contract declared at the wrong arity fails here rather than being
	// papered over by a lookup that guesses.
	// FOUR FIELDS PER IDENTITY, and each one has caught something.
	//
	// `role` and `ret` are the semantic pair the resolver reads. `params` and
	// `canon` are what the EXPORT reads -- `buildCallExportFunctionMetadata`
	// builds the served canonical signature from `ParameterTypes` and
	// `CanonicalReturnType` and never consults `return.type` -- so a contract
	// that omits them renders `name(?)` no matter how correct its semantics
	// are, and a parameter type that is WRONG BUT THE RIGHT LENGTH renders a
	// false signature that the loader's length check cannot see.
	//
	// Asserting only `role` let a wrong return ship: `merge_subtrees_root` was
	// declared as returning a `ChainingValue`, copied from
	// `merge_subtrees_non_root`, when it returns a full `blake3::Hash`
	// (1.8.5 src/hazmat.rs:476). Asserting only `role` and `ret` then left
	// both export fields unguarded entirely.
	//
	// This table is written from the crate's own source at 0.1.0 and 1.8.5,
	// not generated from the YAML under test.
	type want struct {
		role   string
		ret    string
		params []string
		canon  string
	}
	noParams := []string{}
	hazmatParams := []string{
		"&blake3::hazmat::ChainingValue",
		"&blake3::hazmat::ChainingValue",
		"blake3::hazmat::Mode",
	}
	wants := map[string]want{
		// --- unkeyed -------------------------------------------------------
		"blake3.hash":           {"output", "blake3::Hash", []string{"&[u8]"}, "blake3::Hash"},
		"blake3.Hasher.new":     {"factory", "blake3::Hasher", noParams, "blake3::Hasher"},
		"blake3.Hasher.default": {"factory", "blake3::Hasher", noParams, "blake3::Hasher"},
		// --- keyed ---------------------------------------------------------
		"blake3.keyed_hash":       {"output", "blake3::Hash", []string{"&[u8; 32]", "&[u8]"}, "blake3::Hash"},
		"blake3.Hasher.new_keyed": {"factory", "blake3::Hasher", []string{"&[u8; 32]"}, "blake3::Hasher"},
		// --- key derivation ------------------------------------------------
		"blake3.Hasher.new_derive_key":       {"factory", "blake3::Hasher", []string{"&str"}, "blake3::Hasher"},
		"blake3.Hasher.new_from_context_key": {"factory", "blake3::Hasher", []string{"&blake3::hazmat::ContextKey"}, "blake3::Hasher"},
		// --- hasher lifecycle ----------------------------------------------
		"blake3.Hasher.update":            {"operation", "blake3::Hasher", []string{"&[u8]"}, "&mut blake3::Hasher"},
		"blake3.Hasher.update_rayon":      {"operation", "blake3::Hasher", []string{"&[u8]"}, "&mut blake3::Hasher"},
		"blake3.Hasher.update_with_join":  {"operation", "blake3::Hasher", []string{"&[u8]"}, "&mut blake3::Hasher"},
		"blake3.Hasher.update_reader":     {"operation", "blake3::Hasher", []string{"impl std::io::Read"}, "std::io::Result<&mut blake3::Hasher>"},
		"blake3.Hasher.update_mmap":       {"operation", "blake3::Hasher", []string{"impl AsRef<std::path::Path>"}, "std::io::Result<&mut blake3::Hasher>"},
		"blake3.Hasher.update_mmap_rayon": {"operation", "blake3::Hasher", []string{"impl AsRef<std::path::Path>"}, "std::io::Result<&mut blake3::Hasher>"},
		"blake3.Hasher.set_input_offset":  {"operation", "blake3::Hasher", []string{"u64"}, "&mut blake3::Hasher"},
		"blake3.Hasher.count":             {"operation", "u64", noParams, "u64"},
		"blake3.Hasher.reset":             {"operation", "blake3::Hasher", noParams, "&mut blake3::Hasher"},
		"blake3.Hasher.finalize":          {"output", "blake3::Hash", noParams, "blake3::Hash"},
		"blake3.Hasher.finalize_xof":      {"output", "blake3::OutputReader", noParams, "blake3::OutputReader"},
		"blake3.Hasher.finalize_non_root": {"output", "blake3::hazmat::ChainingValue", noParams, "blake3::hazmat::ChainingValue"},
		// --- io::Write input path ------------------------------------------
		"blake3.Hasher.write_all": {"operation", "blake3::Hasher", []string{"&[u8]"}, "std::io::Result<()>"},
		"blake3.Hasher.flush":     {"operation", "blake3::Hasher", noParams, "std::io::Result<()>"},
		// --- the reader ----------------------------------------------------
		"blake3.OutputReader.fill":         {"output", "void", []string{"&mut [u8]"}, "()"},
		"blake3.OutputReader.read":         {"output", "void", []string{"&mut [u8]"}, "()"},
		"blake3.OutputReader.read_exact":   {"output", "void", []string{"&mut [u8]"}, "std::io::Result<()>"},
		"blake3.OutputReader.position":     {"operation", "u64", noParams, "u64"},
		"blake3.OutputReader.set_position": {"operation", "void", []string{"u64"}, "()"},
		"blake3.OutputReader.seek":         {"operation", "u64", []string{"std::io::SeekFrom"}, "std::io::Result<u64>"},
		// --- RustCrypto digest / Mac surface -------------------------------
		"blake3.Hasher.new_with_prefix":     {"factory", "blake3::Hasher", []string{"&[u8]"}, "blake3::Hasher"},
		"blake3.Hasher.new_from_slice":      {"factory", "blake3::Hasher", []string{"&[u8]"}, "core::result::Result<blake3::Hasher, digest::InvalidLength>"},
		"blake3.Hasher.chain_update":        {"operation", "blake3::Hasher", []string{"&[u8]"}, "blake3::Hasher"},
		"blake3.Hasher.digest":              {"output", "blake3::Hash", []string{"&[u8]"}, "digest::Output<blake3::Hasher>"},
		"blake3.Hasher.finalize_into":       {"output", "void", []string{"&mut digest::Output<blake3::Hasher>"}, "()"},
		"blake3.Hasher.finalize_into_reset": {"output", "void", []string{"&mut digest::Output<blake3::Hasher>"}, "()"},
		"blake3.Hasher.finalize_reset":      {"output", "blake3::Hash", noParams, "digest::Output<blake3::Hasher>"},
		"blake3.Hasher.finalize_xof_reset":  {"output", "blake3::OutputReader", noParams, "blake3::OutputReader"},
		"blake3.Hasher.verify_slice":        {"output", "void", []string{"&[u8]"}, "core::result::Result<(), digest::MacError>"},
		// --- hazmat free functions -----------------------------------------
		"blake3::hazmat.hash_derive_key_context": {"output", "blake3::hazmat::ContextKey", []string{"&str"}, "blake3::hazmat::ContextKey"},
		"blake3::hazmat.merge_subtrees_root":     {"output", "blake3::Hash", hazmatParams, "blake3::Hash"},
		"blake3::hazmat.merge_subtrees_non_root": {"output", "blake3::hazmat::ChainingValue", hazmatParams, "blake3::hazmat::ChainingValue"},
		"blake3::hazmat.merge_subtrees_root_xof": {"output", "blake3::OutputReader", hazmatParams, "blake3::OutputReader"},
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
				if c.SourceLibrary != "blake3" {
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

// `derive_key` is the family's one API break: 0.1.0-0.3.8 wrote the derived
// bytes into a caller-supplied buffer and returned nothing, and 1.0.0 onwards
// returns them. One name, two arities, across the contracted range. A
// single-arity contract would leave every pre-1.0 call site unresolved while
// the suite stayed green, which is why this is asserted separately from the
// probe above.
func TestBlake3DeriveKeyIsContractedAtBothArities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for arity, wantReturn := range map[int]string{
		2: "[u8; 32]", // 1.0.0 onwards; read at 1.0.0 src/lib.rs:870 and 1.8.5 src/lib.rs:1003
		3: "void",     // 0.1.0 src/lib.rs:700, 0.3.8 src/lib.rs:781
	} {
		got := kb.ContractsFor("blake3.derive_key", arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(blake3.derive_key, %d) = %d, want exactly one", arity, len(got))
		}
		if got[0].SourceLibrary != "blake3" {
			t.Fatalf("ContractsFor(blake3.derive_key, %d) resolved to %q", arity, got[0].SourceLibrary)
		}
		// The return type is what distinguishes the two eras, and nothing else
		// in this file reads it: without this assertion, collapsing the pair
		// onto one return would leave the suite green.
		if got[0].Return.Type != wantReturn {
			t.Fatalf("blake3.derive_key/%d returns %q, want %q", arity, got[0].Return.Type, wantReturn)
		}
	}
}

// The module segment is load-bearing, and this is the assertion that says so.
// `hazmat` items carry a module segment; crate-root items carry none. What is
// NOT load-bearing is which separator spells it, and both halves matter:
// a consumer writing `use blake3::hazmat;` then `hazmat::merge_subtrees_root(..)`
// produces `blake3.hazmat.merge_subtrees_root`, which resolves only because the
// lookup normalizes the separator. Measured: both real consumer spellings reach
// the same single contract.
func TestBlake3ModuleSegmentIsLoadBearing(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// Both spellings a real consumer can produce for the SAME call resolve, and
	// resolve to the same contract. The second is what the parser emits for
	// `use blake3::hazmat;` + `hazmat::merge_subtrees_root(..)`; without the
	// separator normalization it would resolve nothing.
	for _, key := range []string{
		"blake3::hazmat.merge_subtrees_root",
		"blake3.hazmat.merge_subtrees_root",
	} {
		got := kb.ContractsFor(key, 3)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, 3) = %d, want 1", key, len(got))
		}
		if got[0].Return.Type != "blake3::Hash" || got[0].SourceLibrary != "blake3" {
			t.Fatalf("ContractsFor(%q, 3) resolved to %#v", key, got[0])
		}
	}

	// Absent when the module segment is DROPPED entirely. This is the key an
	// author writing from the crate's root API would produce, so it is worth
	// pinning -- but on its own it proves little, since any unauthored key is
	// absent too. It earns its place next to the two rows above, not instead of
	// them.
	if got := kb.ContractsFor("blake3.merge_subtrees_root", 3); len(got) != 0 {
		t.Fatalf("ContractsFor(blake3.merge_subtrees_root, 3) = %d, want 0", len(got))
	}
	// And the crate-root type must NOT need a module segment.
	if got := kb.ContractsFor("blake3.Hasher.new", 0); len(got) != 1 {
		t.Fatalf("ContractsFor(blake3.Hasher.new, 0) = %d, want 1", len(got))
	}
}

// Arity is checked by `ContractsFor` at a non-negative arity, and this pins
// that. It does NOT pin the Rust inference path, and the difference matters:
// that path looks contracts up at arity -1 (the Rust parser emits no `#N`
// suffix for `splitMethodArity` to read), where `rustContractsFor` falls through
// to lowest-arity-by-name. Measured: `ContractsFor("blake3.derive_key", -1)`
// returns the ARITY-2 entry, so a 0.1.0-0.3.8 three-argument call site infers
// `[u8; 32]` rather than `void` during inference. The export path passes the
// real argument count and honors the pair. Both arities are declared because
// the export path is the one that reaches a served answer; the -1 fallback is a
// property of the inference layer and is out of scope for this file.
//
// A REPRESENTATIVE SUBSET is looked up one argument either side of its declared
// arity, not all 42: the coverage test above already fails if any entry's
// declared arity is wrong, since it looks each identity up at the argument
// count a real parsed call carries. What this adds is the over-match direction
// -- that a neighboring arity resolves to nothing -- which Rust's exact-arity
// lookup makes hard to break, so a subset is enough to notice if it ever does.
func TestBlake3ArityIsLoadBearing(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	// `derive_key` is deliberately excluded: it is contracted at both 2 and 3.
	for method, declared := range map[string]int{
		"blake3.hash":                            1,
		"blake3.keyed_hash":                      2,
		"blake3::Hasher.new":                     0,
		"blake3::Hasher.new_keyed":               1,
		"blake3::Hasher.new_derive_key":          1,
		"blake3::Hasher.update":                  1,
		"blake3::Hasher.finalize":                0,
		"blake3::Hasher.finalize_xof":            0,
		"blake3::OutputReader.fill":              1,
		"blake3::hazmat.hash_derive_key_context": 1,
		"blake3::hazmat.merge_subtrees_root":     3,
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
