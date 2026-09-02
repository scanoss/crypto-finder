// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// aes-kw renamed its entire public API at 0.3.0, and the KB carries both lines.
// These parse real consumer shapes and check the emitted key resolves.
func TestAesKwContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use aes_kw::{AesKw, KekAes128, KekAes256, KeyInit, KwAes128, KwpAes256};

// 0.1.0-0.2.1: the Kek line.
fn legacy(key: &[u8], data: &[u8]) {
    let kek = aes_kw::KekAes128::new(&key.into());
    let mut out = [0u8; 40];
    kek.wrap(data, &mut out).unwrap();
    let _v = kek.wrap_vec(data).unwrap();
    kek.unwrap(data, &mut out).unwrap();
    let _u = kek.unwrap_vec(data).unwrap();
}

fn legacy_padded(key: &[u8], data: &[u8]) {
    let kek = aes_kw::KekAes256::new(&key.into());
    let mut out = [0u8; 48];
    kek.wrap_with_padding(data, &mut out).unwrap();
    let _v = kek.wrap_with_padding_vec(data).unwrap();
    kek.unwrap_with_padding(data, &mut out).unwrap();
}

// 0.3.0-0.3.1: AesKw / AesKwp.
fn modern(kw_key: &[u8], key: &[u8]) {
    let kw = aes_kw::KwAes128::new(&kw_key.into());
    let mut buf = [0u8; 24];
    kw.wrap_key(key, &mut buf).unwrap();
    kw.unwrap_key(&buf, &mut [0u8; 16]).unwrap();
}

fn modern_padded(kw_key: &[u8], key: &[u8]) {
    let kwp = aes_kw::KwpAes256::new(&kw_key.into());
    let _wrapped = kwp.wrap_fixed_key(key);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	type key struct {
		method string
		arity  int
	}
	want := map[key]string{
		{"aes_kw.KekAes128.new", 1}:                   "factory",
		{"aes_kw.KekAes128.wrap", 2}:                  "operation",
		{"aes_kw.KekAes128.wrap_vec", 1}:              "operation",
		{"aes_kw.KekAes128.unwrap", 2}:                "operation",
		{"aes_kw.KekAes128.unwrap_vec", 1}:            "operation",
		{"aes_kw.KekAes256.new", 1}:                   "factory",
		{"aes_kw.KekAes256.wrap_with_padding", 2}:     "operation",
		{"aes_kw.KekAes256.wrap_with_padding_vec", 1}: "operation",
		{"aes_kw.KekAes256.unwrap_with_padding", 2}:   "operation",
		{"aes_kw.KwAes128.new", 1}:                    "factory",
		{"aes_kw.KwAes128.wrap_key", 2}:               "operation",
		{"aes_kw.KwAes128.unwrap_key", 2}:             "operation",
		{"aes_kw.KwpAes256.new", 1}:                   "factory",
		{"aes_kw.KwpAes256.wrap_fixed_key", 1}:        "operation",
	}
	seen := map[key]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				arity := len(call.Arguments)
				k := key{method, arity}
				expectRole, ok := want[k]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, arity, len(got))
				}
				if got[0].SourceLibrary != "aes-kw" {
					t.Fatalf("contract for %q came from %q, want aes-kw", method, got[0].SourceLibrary)
				}
				if got[0].Role != expectRole {
					t.Fatalf("contract for %q/%d role = %q, want %q", method, arity, got[0].Role, expectRole)
				}
				seen[k] = true
			}
		}
	}
	for k := range want {
		if !seen[k] {
			t.Fatalf("parsed calls did not cover %q at arity %d; seen = %v", k.method, k.arity, seen)
		}
	}
}

// WHAT ARITY KEYING DOES AND DOES NOT PROTECT — measured twice, and the first
// two explanations were both wrong.
//
// The claim started as "kek.wrap(d, &mut o).unwrap() emits the crate's unwrap at
// arity 0". False: that yields core::result.Result.unwrap. It was then narrowed
// to "only when the INNER method shares the name". Also false. Measured:
//
//	kek.wrap(d, &mut o).unwrap()             -> core::result.Result.unwrap  n=0
//	KekAes128::try_from(k).unwrap()          -> aes_kw.KekAes128.unwrap     n=0
//	Kek::<Aes128>::try_from(k).unwrap()      -> aes_kw.Kek.unwrap           n=0
//	KekAes128::try_from(k).expect("bad")     -> aes_kw.KekAes128.expect     n=1
//
// The real trigger is the Result-extraction routing on a PATH-QUALIFIED
// ASSOCIATED-FUNCTION receiver: the crate's type carries onto whatever extracts
// the Result, `unwrap` or `expect` alike. That shape is the crate's own idiom
// (0.2.1 kw_tests.rs:102, kwp_tests.rs:188), and adding the `try_from` entries
// is what made it reachable — so this guard matters more after that change, not
// less.
//
// So no alias may carry a zero-arity `unwrap`, and the test below asserts it.
//
// WHAT ACTUALLY PREVENTS A WRONG TYPING IS NOT THE ARITY, and an earlier version
// of this comment said it was. Rust callee names carry no `#N` suffix, so
// splitMethodArity returns -1 for every aes-kw call and rustContractsFor falls
// through to lowestArityByName — contracts.go's own doc names inference.go's
// candidateFromCallResult as that caller, and it passes the raw -1. The
// protection is `shouldInfer`: it fires only for inferenceTriggerTypes, so a
// function with a concrete declared return is suppressed. Verified on
// `fn make(k: &[u8]) -> KekAes128 { KekAes128::try_from(k).unwrap() }`:
// inferred=nil, suppressed. The -1 lookup is asserted below as current
// behavior so a change in either layer is noticed.
func TestAesKwHasNoZeroArityUnwrap(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, ty := range []string{
		"Kek", "KekAes128", "KekAes192", "KekAes256",
		"AesKw", "KwAes128", "KwAes192", "KwAes256",
		"AesKwp", "KwpAes128", "KwpAes192", "KwpAes256",
	} {
		key := "aes_kw." + ty + ".unwrap"
		if got := kb.ContractsFor(key, 0); len(got) != 0 {
			t.Errorf("%s resolves at arity 0 (%d contracts); that is Result::unwrap, "+
				"not the crate's own unwrap", key, len(got))
		}
	}

	// The genuine two-argument form must still resolve, or the guard above
	// would be satisfied by simply having no unwrap at all.
	if got := kb.ContractsFor("aes_kw.KekAes256.unwrap", 2); len(got) != 1 {
		t.Errorf("the crate's own unwrap/2 resolved to %d contracts, want one", len(got))
	}

	// The -1 path documented above: an unknown arity falls through to the
	// lowest-arity entry by name. Asserted as CURRENT behavior so a change is
	// noticed, not as something desirable.
	if got := kb.ContractsFor("aes_kw.KekAes128.unwrap", -1); len(got) != 1 {
		t.Errorf("ContractsFor(unwrap, -1) = %d; the lowest-arity-by-name "+
			"fallthrough changed, and the comment above needs revisiting", len(got))
	}
}

// EVERY ENTRY'S FULL SHAPE IS ASSERTED — arity, role, parameter types AND
// return type.
//
// An earlier version checked only that the return type was NON-EMPTY and that
// the parameter-type COUNT equalled the arity. A review showed both were
// hollow: the loader already rejects a count mismatch, so that line could never
// fail on its own, and five separate mutations survived — a bogus return type
// on `Kek.wrap`, a factory returning the wrong type, garbage parameter type
// strings, and a KW/KWP return swap. Those are exactly the two fields that
// encode the API, and two real defects had slipped through them.
// checkKeySizeContribution asserts the keySize derivation to the same depth as
// the aes.yaml guard: index, name, parameter role AND derivation. A review's
// mutation sweep showed that checking only the property let all four of those
// mutate freely.
func checkKeySizeContribution(t *testing.T, key string, params []contracts.ParameterContract) {
	t.Helper()

	if len(params) != 1 {
		t.Errorf("%s has %d parameter contracts, want 1", key, len(params))
		return
	}
	pc := params[0]
	if pc.Index == nil || *pc.Index != 0 {
		t.Errorf("%s keySize parameter index = %v, want 0", key, pc.Index)
	}
	if pc.Name != "key" {
		t.Errorf("%s keySize parameter name = %q, want key", key, pc.Name)
	}
	if pc.Role != "metadata-contributing" {
		t.Errorf("%s keySize parameter role = %q, want metadata-contributing", key, pc.Role)
	}
	if pc.Contributes == nil {
		t.Errorf("%s declares no keySize contribution", key)
		return
	}
	if pc.Contributes.Property != "keySize" {
		t.Errorf("%s contributes %q, want keySize", key, pc.Contributes.Property)
	}
	if pc.Contributes.Derivation != "argument_bit_length" {
		t.Errorf("%s keySize derivation = %q, want argument_bit_length", key, pc.Contributes.Derivation)
	}
}

func TestAesKwEveryAliasIsTyped(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	const res = "core::result::Result"
	type sig struct {
		arity  int
		role   string
		ret    string // "" means "the constructed type itself"
		params []string
	}

	kekMethods := []struct {
		name string
		sig  sig
	}{
		{"new", sig{1, "factory", "", []string{"&GenericArray<u8, Aes::KeySize>"}}},
		// `from` is an overload set, so the KB declares no parameter_types
		// (AGENTS.md). nil here means "assert that it declares none".
		{"from", sig{1, "factory", "", nil}},
		{"try_from", sig{1, "factory", res, []string{"&[u8]"}}},
		{"wrap", sig{2, "operation", res, []string{"&[u8]", "&mut [u8]"}}},
		{"wrap_vec", sig{1, "operation", res, []string{"&[u8]"}}},
		{"unwrap", sig{2, "operation", res, []string{"&[u8]", "&mut [u8]"}}},
		{"unwrap_vec", sig{1, "operation", res, []string{"&[u8]"}}},
		{"wrap_with_padding", sig{2, "operation", res, []string{"&[u8]", "&mut [u8]"}}},
		{"wrap_with_padding_vec", sig{1, "operation", res, []string{"&[u8]"}}},
		{"unwrap_with_padding", sig{2, "operation", res, []string{"&[u8]", "&mut [u8]"}}},
		{"unwrap_with_padding_vec", sig{1, "operation", res, []string{"&[u8]"}}},
	}

	// wrap_fixed_key returns a type declared inside a PRIVATE module, and
	// unwrap_fixed_key takes it back — a different width from wrap's argument.
	modernMethods := func(wrapped string) []struct {
		name string
		sig  sig
	} {
		return []struct {
			name string
			sig  sig
		}{
			{"new", sig{1, "factory", "", []string{"&Array<u8, C::KeySize>"}}},
			{"wrap_key", sig{2, "operation", res, []string{"&[u8]", "&mut [u8]"}}},
			{"unwrap_key", sig{2, "operation", res, []string{"&[u8]", "&mut [u8]"}}},
			{"wrap_fixed_key", sig{1, "operation", wrapped, []string{"&Array<u8, N>"}}},
			{"unwrap_fixed_key", sig{1, "operation", res, []string{"&" + wrapped + "<N>"}}},
		}
	}

	check := func(ty string, methods []struct {
		name string
		sig  sig
	},
	) {
		for _, m := range methods {
			key := "aes_kw." + ty + "." + m.name
			got := kb.ContractsFor(key, m.sig.arity)
			if len(got) != 1 {
				t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", key, m.sig.arity, len(got))
				continue
			}
			c := got[0]
			if c.SourceLibrary != "aes-kw" {
				t.Errorf("%s came from %q, want aes-kw", key, c.SourceLibrary)
			}
			if c.Role != m.sig.role {
				t.Errorf("%s role = %q, want %q", key, c.Role, m.sig.role)
			}
			wantRet := m.sig.ret
			if wantRet == "" {
				wantRet = "aes_kw::" + ty
			}
			if c.Return.Type != wantRet {
				t.Errorf("%s return = %q, want %q", key, c.Return.Type, wantRet)
			}
			if len(c.ParameterTypes) != len(m.sig.params) {
				t.Errorf("%s has %d parameter types, want %d", key, len(c.ParameterTypes), len(m.sig.params))
				continue
			}
			for i, want := range m.sig.params {
				if c.ParameterTypes[i] != want {
					t.Errorf("%s parameter %d = %q, want %q", key, i, c.ParameterTypes[i], want)
				}
			}
			// The confidence is asserted too. A review's mutation sweep found
			// `high -> low` surviving on all 84 entries: it flows into
			// InferredReturn.Confidence and 36 other test files assert it, so an
			// unasserted downgrade here is a silent behavior change.
			if c.Return.Confidence != "high" {
				t.Errorf("%s return confidence = %q, want high", key, c.Return.Confidence)
			}
			// The key-taking factories carry the keySize derivation every other
			// symmetric Rust contract attaches (aes.yaml, aes-gcm.yaml, ...).
			// The key-taking factories carry the keySize derivation every other
			// symmetric Rust contract attaches. Asserted to the same depth as
			// the aes.yaml guard (rust_block_cipher_contract_wiring_test.go):
			// index, name, role AND derivation. A review's sweep showed that
			// checking only the property let the index, the name, the parameter
			// role and the derivation all mutate freely.
			if m.sig.role == "factory" {
				checkKeySizeContribution(t, key, c.Parameters)
			}
		}
	}

	for _, ty := range []string{"Kek", "KekAes128", "KekAes192", "KekAes256"} {
		check(ty, kekMethods)
	}
	for _, ty := range []string{"AesKw", "KwAes128", "KwAes192", "KwAes256"} {
		check(ty, modernMethods("aes_kw::kw::KwWrappedKey"))
	}
	for _, ty := range []string{"AesKwp", "KwpAes128", "KwpAes192", "KwpAes256"} {
		check(ty, modernMethods("aes_kw::kwp::KwpWrappedKey"))
	}
}

// BOTH API LINES MUST COEXIST IN THE KB. `Kek` exists only in 0.1.0-0.2.1 and
// `AesKw` only in 0.3.x, so if one stops resolving the KB has been narrowed to
// a single line and half the published range went dark.
//
// 0.0.0 is deliberately outside the declared range: it is a yanked, empty
// placeholder whose src/lib.rs is 0 bytes. The range is stated in the YAML
// rather than asserted here, because a merged knowledge base carries no
// per-library metadata.
func TestAesKwCarriesBothApiLines(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		key   string
		arity int
		line  string
	}{
		{"aes_kw.Kek.new", 1, "0.1.0-0.2.1"},
		{"aes_kw.Kek.wrap", 2, "0.1.0-0.2.1"},
		{"aes_kw.AesKw.new", 1, "0.3.x"},
		{"aes_kw.AesKw.wrap_key", 2, "0.3.x"},
		{"aes_kw.AesKwp.wrap_key", 2, "0.3.x"},
	} {
		if got := kb.ContractsFor(tc.key, tc.arity); len(got) != 1 {
			t.Errorf("%s (%s line) resolved to %d contracts, want one", tc.key, tc.line, len(got))
		}
	}
}
