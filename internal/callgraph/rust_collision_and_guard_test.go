// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// A `match` arm's `if` GUARD is code, and its calls are reachable.
//
// The guard is a child of the match_pattern node under field name "condition";
// walkRustMatch bound the pattern and walked only the arm's value, so nothing in
// a guard was ever visited. 72 lost call sites across 12 crates. The reviewer
// probed 32 syntactic positions and only this one lost calls.
func TestRustParser_MatchArmGuardCallsAreWalked(t *testing.T) {
	t.Parallel()

	got := parseRustCrateCalleeKeyCounts(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"mguard\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nhmac = \"0.12\"\nsha2 = \"0.10\"\n",
		"src/lib.rs": `use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

pub enum E { A, B }

pub fn pick(e: E, key: &[u8]) -> u32 {
    match e {
        E::A if HmacSha256::new_from_slice(key).is_ok() => 1,
        _ => 0,
    }
}
`,
	}, "mguard")

	// hmac.yaml keys Hmac.new_from_slice; losing the guard lost the contract
	// hit entirely.
	if got["hmac.(Hmac).new_from_slice"] != 1 {
		t.Errorf("hmac.(Hmac).new_from_slice emitted %d times, want 1; got %v",
			got["hmac.(Hmac).new_from_slice"], sortedKeyList(got))
	}
}

// `impl Trait for Box<dyn X>` is an impl for X reached through a box. Keying it
// on `Box` erased the only identity in the header and collided independent
// impls: quinn-proto 0.11.9 src/crypto/rustls.rs:220
// `impl crypto::HeaderKey for Box<dyn HeaderProtectionKey>` and :584
// `impl crypto::PacketKey for Box<dyn PacketKey>` both typed as `(Box)`.
func TestRustParser_BoxedDynSelfTypeKeysOnTheBoxedTrait(t *testing.T) {
	t.Parallel()

	got := parseRustDeclarationKeys(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"quinn-proto\"\nversion = \"0.11.9\"\nedition = \"2021\"\n",
		"src/lib.rs": `pub trait HeaderProtectionKey { fn sample_size(&self) -> usize; }
pub trait PacketKey { fn tag_len(&self) -> usize; }

pub trait HeaderKey { fn decrypt(&self); }
pub trait AeadKey { fn encrypt(&self); }

impl HeaderKey for Box<dyn HeaderProtectionKey> {
    fn decrypt(&self) { let _ = self.sample_size(); }
}

impl AeadKey for Box<dyn PacketKey> {
    fn encrypt(&self) { let _ = self.tag_len(); }
}

// A generic type of the crate's own is NOT a box: its own name is the identity.
pub struct Holder<T> { pub inner: T }
impl<T> Holder<T> { pub fn get(&self) {} }
`,
	}, "quinn-proto")

	for _, want := range []string{
		"quinn-proto.(HeaderProtectionKey).decrypt",
		"quinn-proto.(PacketKey).encrypt",
		"quinn-proto.(Holder).get",
	} {
		if !got[want] {
			t.Errorf("missing declaration %q; got %v", want, sortedBoolKeyList(got))
		}
	}
	for _, bad := range []string{
		"quinn-proto.(Box).decrypt",
		"quinn-proto.(Box).encrypt",
	} {
		if got[bad] {
			t.Errorf("declared %q; `Box` is not the identity of the type an impl is for", bad)
		}
	}
}

// parseRustDeclarationKeys returns the set of declaration keys a crate fixture
// produces, in the `package.(Type).method` shape.
func parseRustDeclarationKeys(t *testing.T, files map[string]string, importPath string) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		writeRustFile(t, dir, name, content)
	}
	parser := NewRustParser()
	keys := map[string]bool{}
	var walk func(string, string)
	walk = func(at, pkg string) {
		parsed, err := parser.ParseDirectory(at, pkg)
		if err != nil {
			t.Fatalf("ParseDirectory(%s): %v", at, err)
		}
		for _, analysis := range parsed {
			for i := range analysis.Functions {
				keys[analysis.Functions[i].ID.String()] = true
			}
		}
		entries, err := os.ReadDir(at)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() && !skipCallgraphWalkDir(entry.Name()) {
				walk(filepath.Join(at, entry.Name()), parser.SubPackagePath(pkg, entry.Name()))
			}
		}
	}
	walk(filepath.Join(dir, "src"), importPath)
	return keys
}

func sortedBoolKeyList(keys map[string]bool) []string {
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Two declarations of one `Type.method` key are MERGED, never replaced.
//
// Rust allows a type to have an inherent `fn feed` and a trait impl's `fn feed`,
// and the contract KB keys both as `Type.method` on purpose:
// `impl Digest for Sha256 { fn update }` is the RustCrypto shape and
// `sha2::Sha256.update` has to match it. Builder.mergeAnalysisFunctions was
// last-write-wins, and idiomatic Rust puts the substantive `impl T { .. }` before
// the trait impls, so the survivor was the one-line forwarder — 32 declarations
// and 119 edges lost across the 53-crate corpus, worst of them
// age 0.11.1 src/plugin.rs:625 `age.(IdentityPluginV1).unwrap_stanzas`, the whole
// plugin decryption path (58 edges), replaced by a 2-edge forwarder at :732.
func TestRustBuilder_CollidingTypedMethodsAreMergedNotDropped(t *testing.T) {
	t.Parallel()

	const source = `use hmac::{Hmac, Mac};
use sha2::Sha256;
type K = Hmac<Sha256>;

pub trait Sink { fn feed(&self, d: &[u8]); }

pub struct T { k: Vec<u8> }

impl T {
    // Substantive, declared FIRST — the idiomatic order.
    pub fn feed(&self, d: &[u8]) {
        let mut m = K::new_from_slice(&self.k).unwrap();
        m.update(d);
        let _ = m.finalize();
    }
}

impl Sink for T {
    // One-line forwarder, declared SECOND.
    fn feed(&self, d: &[u8]) { T::feed(self, d) }
}
`

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[package]\nname = \"collide\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nhmac = \"0.12\"\nsha2 = \"0.10\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRustFile(t, dir, "src/lib.rs", source)

	builder := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: filepath.Join(dir, "src"), ImportPath: "collide"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	fn := graph.Functions["collide.(T).feed"]
	if fn == nil {
		t.Fatalf("collide.(T).feed not declared; got %v", sortedGraphKeys(graph))
	}
	// The three hmac.yaml hits live in the inherent body. Dropping it for the
	// forwarder took all three.
	want := map[string]bool{
		"hmac.(Hmac).new_from_slice": false,
		"hmac.(Hmac).update":         false,
		"hmac.(Hmac).finalize":       false,
	}
	for i := range fn.Calls {
		key := fn.Calls[i].Callee.String()
		if _, tracked := want[key]; tracked {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("merged collide.(T).feed lost %q; it has %d calls", key, len(fn.Calls))
		}
	}
	// The forwarder's own call is unioned in rather than discarded, which is
	// what makes the merge an over-approximation instead of a deletion.
	forwarded := false
	for i := range fn.Calls {
		if fn.Calls[i].Callee.String() == "collide.(T).feed" {
			forwarded = true
		}
	}
	if !forwarded {
		t.Error("the trait forwarder's own call was dropped; the merge must union both bodies")
	}
	// The surviving declaration is the earlier, substantive one.
	if fn.StartLine > 15 {
		t.Errorf("merged declaration starts at line %d; the substantive body is the earlier one", fn.StartLine)
	}
}

func sortedGraphKeys(graph *CallGraph) []string {
	out := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
