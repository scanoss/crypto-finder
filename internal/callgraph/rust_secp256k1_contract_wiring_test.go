// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The KB is asserted as a SET, not as a sample.
//
// A per-key `ContractsFor` assertion cannot see an entry that should not be
// there, an entry that was dropped, or a field that was corrupted. Rendering
// every loaded contract for the library and comparing the whole set against a
// literal can see all three, and the claim was checked by
// mutating this file's yaml by hand before the PR opened -- delete an entry,
// flip a role, change an arity, corrupt a return type, corrupt
// parameter_types, downgrade confidence, rename a method to the emitted key
// shape, add an unexpected entry, add a duplicate -- and asserting each one
// FAILS. There is no committed mutation sweep; the check is a release step.
func TestSecp256k1ContractSetIsExact(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type row struct {
		method string
		arity  int
		role   string
		ret    string
		params []string
	}
	want := []row{
		{"secp256k1.generate_keypair", 1, "factory", "(secp256k1::SecretKey, secp256k1::PublicKey)", []string{"&mut rand::Rng"}},
		{"secp256k1::KeyPair.from_seckey_slice", 2, "factory", "core::result::Result", []string{"&secp256k1::Secp256k1", "&[u8]"}},
		{"secp256k1::KeyPair.from_seckey_str", 2, "factory", "core::result::Result", []string{"&secp256k1::Secp256k1", "&str"}},
		{"secp256k1::KeyPair.from_secret_key", 2, "factory", "secp256k1::KeyPair", []string{"&secp256k1::Secp256k1", "&secp256k1::SecretKey"}},
		{"secp256k1::KeyPair.new", 2, "factory", "secp256k1::KeyPair", []string{"&secp256k1::Secp256k1", "&mut rand::Rng"}},
		{"secp256k1::KeyPair.new_global", 1, "factory", "secp256k1::KeyPair", []string{"&mut rand::Rng"}},
		{"secp256k1::KeyPair.sign_schnorr", 1, "operation", "secp256k1::schnorr::Signature", []string{}},
		{"secp256k1::Keypair.from_seckey_slice", 2, "factory", "core::result::Result", []string{"&secp256k1::Secp256k1", "&[u8]"}},
		{"secp256k1::Keypair.from_seckey_str", 2, "factory", "core::result::Result", []string{"&secp256k1::Secp256k1", "&str"}},
		{"secp256k1::Keypair.from_secret_key", 2, "factory", "secp256k1::Keypair", []string{"&secp256k1::Secp256k1", "&secp256k1::SecretKey"}},
		{"secp256k1::Keypair.new", 2, "factory", "secp256k1::Keypair", []string{"&secp256k1::Secp256k1", "&mut rand::Rng"}},
		{"secp256k1::Keypair.new_global", 1, "factory", "secp256k1::Keypair", []string{"&mut rand::Rng"}},
		{"secp256k1::Keypair.sign_schnorr", 1, "operation", "secp256k1::schnorr::Signature", []string{}},
		{"secp256k1::Keypair.sign_schnorr_no_aux_rand", 1, "operation", "secp256k1::schnorr::Signature", []string{"&[u8]"}},
		{"secp256k1::PublicKey.from_secret_key", 2, "factory", "secp256k1::PublicKey", []string{"&secp256k1::Secp256k1", "&secp256k1::SecretKey"}},
		{"secp256k1::PublicKey.from_secret_key_global", 1, "factory", "secp256k1::PublicKey", []string{"&secp256k1::SecretKey"}},
		{"secp256k1::Secp256k1.generate_keypair", 1, "factory", "(secp256k1::SecretKey, secp256k1::PublicKey)", []string{"&mut rand::Rng"}},
		{"secp256k1::Secp256k1.generate_keypair", 2, "factory", "core::result::Result", []string{"&mut rand::Rng", "bool"}},
		{"secp256k1::Secp256k1.generate_schnorrsig_keypair", 1, "factory", "(secp256k1::KeyPair, secp256k1::schnorrsig::PublicKey)", []string{"&mut rand::Rng"}},
		{"secp256k1::Secp256k1.recover", 2, "operation", "core::result::Result", []string{"&secp256k1::Message", "&secp256k1::ecdsa::RecoverableSignature"}},
		{"secp256k1::Secp256k1.recover_compact", 4, "operation", "core::result::Result", []string{"&secp256k1::Message", "&[u8]", "bool", "secp256k1::RecoveryId"}},
		{"secp256k1::Secp256k1.recover_ecdsa", 2, "operation", "core::result::Result", []string{}},
		{"secp256k1::Secp256k1.schnorrsig_sign", 2, "operation", "secp256k1::schnorr::Signature", []string{"&secp256k1::Message", "&secp256k1::KeyPair"}},
		{"secp256k1::Secp256k1.schnorrsig_verify", 3, "operation", "core::result::Result", []string{}},
		{"secp256k1::Secp256k1.sign", 2, "operation", "secp256k1::ecdsa::Signature", []string{"&secp256k1::Message", "&secp256k1::SecretKey"}},
		{"secp256k1::Secp256k1.sign_compact", 2, "operation", "core::result::Result", []string{"&secp256k1::Message", "&secp256k1::SecretKey"}},
		{"secp256k1::Secp256k1.sign_ecdsa", 2, "operation", "secp256k1::ecdsa::Signature", []string{}},
		{"secp256k1::Secp256k1.sign_ecdsa_grind_r", 3, "operation", "secp256k1::ecdsa::Signature", []string{}},
		{"secp256k1::Secp256k1.sign_ecdsa_low_r", 2, "operation", "secp256k1::ecdsa::Signature", []string{}},
		{"secp256k1::Secp256k1.sign_ecdsa_recoverable", 2, "operation", "secp256k1::ecdsa::RecoverableSignature", []string{}},
		{"secp256k1::Secp256k1.sign_ecdsa_recoverable_with_noncedata", 3, "operation", "secp256k1::ecdsa::RecoverableSignature", []string{}},
		{"secp256k1::Secp256k1.sign_ecdsa_with_noncedata", 3, "operation", "secp256k1::ecdsa::Signature", []string{}},
		{"secp256k1::Secp256k1.sign_grind_r", 3, "operation", "secp256k1::ecdsa::Signature", []string{"&secp256k1::Message", "&secp256k1::SecretKey", "usize"}},
		{"secp256k1::Secp256k1.sign_low_r", 2, "operation", "secp256k1::ecdsa::Signature", []string{"&secp256k1::Message", "&secp256k1::SecretKey"}},
		{"secp256k1::Secp256k1.sign_recoverable", 2, "operation", "secp256k1::ecdsa::RecoverableSignature", []string{"&secp256k1::Message", "&secp256k1::SecretKey"}},
		{"secp256k1::Secp256k1.sign_schnorr", 2, "operation", "secp256k1::schnorr::Signature", []string{}},
		{"secp256k1::Secp256k1.sign_schnorr_no_aux_rand", 2, "operation", "secp256k1::schnorr::Signature", []string{}},
		{"secp256k1::Secp256k1.sign_schnorr_with_aux_rand", 3, "operation", "secp256k1::schnorr::Signature", []string{}},
		{"secp256k1::Secp256k1.sign_schnorr_with_rng", 3, "operation", "secp256k1::schnorr::Signature", []string{}},
		{"secp256k1::Secp256k1.verify", 3, "operation", "core::result::Result", []string{"&secp256k1::Message", "&secp256k1::ecdsa::Signature", "&secp256k1::PublicKey"}},
		{"secp256k1::Secp256k1.verify_ecdsa", 3, "operation", "core::result::Result", []string{}},
		{"secp256k1::Secp256k1.verify_raw", 3, "operation", "core::result::Result", []string{"&secp256k1::Message", "&[u8]", "&secp256k1::PublicKey"}},
		{"secp256k1::Secp256k1.verify_schnorr", 3, "operation", "core::result::Result", []string{}},
		{"secp256k1::SecretKey.new", 1, "factory", "secp256k1::SecretKey", []string{"&mut rand::Rng"}},
		{"secp256k1::SecretKey.new", 2, "factory", "secp256k1::SecretKey", []string{"&secp256k1::Secp256k1", "&mut rand::Rng"}},
		{"secp256k1::SecretKey.sign_ecdsa", 1, "operation", "secp256k1::ecdsa::Signature", []string{}},
		{"secp256k1::ecdh.shared_secret_point", 2, "operation", "[u8; 64]", []string{"&secp256k1::PublicKey", "&secp256k1::SecretKey"}},
		{"secp256k1::ecdh::SharedSecret.new", 2, "operation", "secp256k1::ecdh::SharedSecret", []string{"&secp256k1::PublicKey", "&secp256k1::SecretKey"}},
		{"secp256k1::ecdh::SharedSecret.new", 3, "operation", "secp256k1::ecdh::SharedSecret", []string{"&secp256k1::Secp256k1", "&secp256k1::PublicKey", "&secp256k1::SecretKey"}},
		{"secp256k1::ecdh::SharedSecret.new_with_hash", 3, "operation", "secp256k1::ecdh::SharedSecret", []string{"&secp256k1::PublicKey", "&secp256k1::SecretKey", "impl FnMut([u8; 32], [u8; 32]) -> secp256k1::ecdh::SharedSecret"}},
		{"secp256k1::ellswift::ElligatorSwift.shared_secret", 5, "operation", "secp256k1::ellswift::ElligatorSwiftSharedSecret", []string{"secp256k1::ellswift::ElligatorSwift", "secp256k1::ellswift::ElligatorSwift", "secp256k1::SecretKey", "impl Into<secp256k1::ellswift::Party>", "Option<&[u8]>"}},
		{"secp256k1::ellswift::ElligatorSwift.shared_secret_with_hasher", 5, "operation", "secp256k1::ellswift::ElligatorSwiftSharedSecret", []string{"secp256k1::ellswift::ElligatorSwift", "secp256k1::ellswift::ElligatorSwift", "secp256k1::SecretKey", "impl Into<secp256k1::ellswift::Party>", "impl FnMut([u8; 32], [u8; 64], [u8; 64]) -> secp256k1::ellswift::ElligatorSwiftSharedSecret"}},
		{"secp256k1::key::PublicKey.from_secret_key", 2, "factory", "secp256k1::PublicKey", []string{"&secp256k1::Secp256k1", "&secp256k1::SecretKey"}},
		{"secp256k1::key::SecretKey.new", 1, "factory", "secp256k1::SecretKey", []string{"&mut rand::Rng"}},
		{"secp256k1::key::SecretKey.new", 2, "factory", "secp256k1::SecretKey", []string{"&secp256k1::Secp256k1", "&mut rand::Rng"}},
		{"secp256k1::schnorrsig::KeyPair.from_secret_key", 2, "factory", "secp256k1::KeyPair", []string{"&secp256k1::Secp256k1", "secp256k1::SecretKey"}},
		{"secp256k1::schnorrsig::KeyPair.new", 2, "factory", "secp256k1::KeyPair", []string{"&secp256k1::Secp256k1", "&mut rand::Rng"}},
	}

	render := func(r row) string {
		return fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=high",
			r.method, r.arity, r.role, r.ret, strings.Join(r.params, ","))
	}

	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[render(r)] = true
	}

	gotSet := map[string]bool{}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "secp256k1" {
				continue
			}
			gotSet[fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=%s",
				c.Method, c.Arity, c.Role, c.Return.Type,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence)] = true
		}
	}

	var missing, unexpected []string
	for k := range wantSet {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for k := range gotSet {
		if !wantSet[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	for _, m := range missing {
		t.Errorf("missing from the KB: %s", m)
	}
	for _, u := range unexpected {
		t.Errorf("present in the KB but not declared here: %s", u)
	}
}

// The keys must be authored as `secp256k1::<module>::Type.method`, not as the
// call graph emits them. rustAuthoredKey (contracts.go:267) moves the
// second-to-last dot onto "::" when the file loads, so authoring the EMITTED
// form produces a contract that loads without error and joins nothing — the
// state that looks exactly like having no contract at all.
//
// The one exception is a FREE function: `secp256k1::ecdh.shared_secret_point`
// carries a single dot, rustAuthoredKey returns it unchanged, and the module
// separator therefore stays "::" in the head with a "." before the function.
func TestSecp256k1KeysUseTheAuthoredShape(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	seen := 0
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "secp256k1" {
				continue
			}
			seen++
			head := c.Method
			if i := strings.LastIndex(head, "."); i > 0 {
				head = head[:i]
			}
			if strings.Contains(head, ".") {
				t.Errorf("%s: module path uses '.', want '::' (the authored shape)", c.Method)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no secp256k1 contracts loaded at all; the zero above would be meaningless")
	}
}

// With the authored keys the parser types the whole surface. This pins the two
// shapes that are easiest to get wrong and that a wrong key silently hides: the
// pre-0.21 `secp256k1::key::` module path, which is a DIFFERENT key from the
// crate-root re-export and is the only spelling that compiles on 0.1.0-0.20.x,
// and the free function in `ecdh`, whose key carries one dot rather than two.
func TestSecp256k1ModuleQualifiedAndFreeFunctionKeysResolve(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use secp256k1::{Secp256k1, SecretKey, PublicKey};
use secp256k1::ecdh::SharedSecret;
fn old_era(rng: &mut u8) {
    let secp = Secp256k1::new();
    let sk = secp256k1::key::SecretKey::new(&secp, rng);
    let pk = secp256k1::key::PublicKey::from_secret_key(&secp, &sk);
    let _ = (sk, pk);
}
fn modern(pk: &PublicKey, sk: &SecretKey) {
    let _ = SharedSecret::new(pk, sk);
    let _ = secp256k1::ecdh::shared_secret_point(pk, sk);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, a := range analyses {
		for _, fn := range a.Functions {
			for _, c := range fn.Calls {
				callee := c.Callee
				m, _ := splitMethodArity(&callee)
				seen[m] = len(c.Arguments)
			}
		}
	}
	for _, tc := range []struct {
		key   string
		arity int
	}{
		{"secp256k1::key.SecretKey.new", 2},
		{"secp256k1::key.PublicKey.from_secret_key", 2},
		{"secp256k1::ecdh.SharedSecret.new", 2},
		{"secp256k1::ecdh.shared_secret_point", 2},
	} {
		n, ok := seen[tc.key]
		if !ok {
			t.Errorf("%s was never emitted; seen = %v", tc.key, seen)
			continue
		}
		if n != tc.arity {
			t.Errorf("%s emitted at arity %d, want %d", tc.key, n, tc.arity)
		}
		if got := kb(t).ContractsFor(tc.key, tc.arity); len(got) == 0 {
			t.Errorf("%s/%d resolves to no contract; the key does not join", tc.key, tc.arity)
		}
	}
}

func kb(t *testing.T) *contracts.KnowledgeBase {
	t.Helper()
	k, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	return k
}

// The surface this family deliberately does not claim must stay absent. These
// calls move bytes between representations, do EC arithmetic for BIP-32 and
// BIP-341 derivation, or allocate a libsecp256k1 context; none of them computes
// a signature, a key or a shared secret.
func TestSecp256k1NonCryptoSurfaceIsAbsent(t *testing.T) {
	t.Parallel()

	k := kb(t)
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"secp256k1::Secp256k1.new", 0},
		{"secp256k1::Secp256k1.gen_new", 0},
		{"secp256k1::Secp256k1.signing_only", 0},
		{"secp256k1::Secp256k1.verification_only", 0},
		{"secp256k1::Secp256k1.randomize", 1},
		{"secp256k1::Secp256k1.seeded_randomize", 1},
		{"secp256k1::Message.from_slice", 1},
		{"secp256k1::Message.from_digest", 1},
		{"secp256k1::Message.from_digest_slice", 1},
		{"secp256k1::Message.from_hashed_data", 1},
		{"secp256k1::SecretKey.from_slice", 1},
		{"secp256k1::SecretKey.from_byte_array", 1},
		{"secp256k1::SecretKey.secret_bytes", 0},
		{"secp256k1::SecretKey.add_tweak", 1},
		{"secp256k1::SecretKey.mul_tweak", 1},
		{"secp256k1::PublicKey.from_slice", 1},
		{"secp256k1::PublicKey.serialize", 0},
		{"secp256k1::PublicKey.serialize_uncompressed", 0},
		{"secp256k1::PublicKey.combine", 1},
		{"secp256k1::PublicKey.combine_keys", 1},
		{"secp256k1::XOnlyPublicKey.from_slice", 1},
		{"secp256k1::XOnlyPublicKey.serialize", 0},
		{"secp256k1::ecdsa::Signature.from_der", 1},
		{"secp256k1::ecdsa::Signature.from_compact", 1},
		{"secp256k1::ecdsa::Signature.serialize_der", 0},
		{"secp256k1::ecdsa::Signature.serialize_compact", 0},
		{"secp256k1::ecdsa::Signature.normalize_s", 0},
		{"secp256k1::ecdsa::RecoverableSignature.from_compact", 2},
		{"secp256k1::ecdsa::RecoverableSignature.to_standard", 0},
		{"secp256k1::schnorr::Signature.from_slice", 1},
		{"secp256k1::ecdh::SharedSecret.from_bytes", 1},
		{"secp256k1::ecdh::SharedSecret.from_slice", 1},
		{"secp256k1::ecdh::SharedSecret.secret_bytes", 0},
		{"secp256k1::Keypair.secret_bytes", 0},
		{"secp256k1::Keypair.add_xonly_tweak", 2},
		{"secp256k1::ellswift::ElligatorSwift.from_array", 1},
		{"secp256k1::ellswift::ElligatorSwift.to_array", 0},
	} {
		if got := k.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("%s/%d resolved to %d contracts; it must stay absent", tc.method, tc.arity, len(got))
		}
	}
}
