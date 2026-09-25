// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Every call the crypto_rules rust/rsa rules name in metadata.crypto.api, and the
// key operations those padding and key objects feed, written the way a consumer
// writes them, must resolve to exactly one rsa contract with the expected role.
// The source mixes eras on purpose: the parser does not compile, and the KB
// carries every era at once.
func TestRsaContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	src := `use rsa::{Oaep, PaddingScheme, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use rsa::oaep;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::pss::{self, BlindedSigningKey};
use sha2::Sha256;

fn modern(mut rng: R, k: RsaPrivateKey, p: RsaPublicKey, exp: BigUint, c: &[u8], d: &[u8], m: &[u8], sig: &[u8]) {
    let _ = RsaPrivateKey::new(&mut rng, 2048);
    let _ = RsaPrivateKey::new_with_exp(&mut rng, 3072, &exp);
    let _ = Oaep::new::<Sha256>();
    let _ = rsa::Oaep::new_with_label::<Sha256, _>("label");
    let _ = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
    let _ = Oaep::new_with_mgf_hash_and_label::<Sha256, Sha256, _>("label");
    let _ = oaep::EncryptingKey::<Sha256>::new(p);
    let _ = oaep::DecryptingKey::<Sha256>::new(k);
    let _ = rsa::pkcs1v15::EncryptingKey::new(p);
    let _ = rsa::pkcs1v15::DecryptingKey::new(k);
    let _ = Pkcs1v15Sign::new::<Sha256>();
    let _ = Pkcs1v15Sign::new_unprefixed();
    let _ = SigningKey::<Sha256>::new(k);
    let _ = SigningKey::<Sha256>::new_with_prefix(k);
    let _ = SigningKey::<Sha256>::new_unprefixed(k);
    let _ = SigningKey::<Sha256>::random(&mut rng, 2048);
    let _ = VerifyingKey::<Sha256>::new(p);
    let _ = VerifyingKey::<Sha256>::new_with_prefix(p);
    let _ = VerifyingKey::<Sha256>::new_unprefixed(p);
    let _ = Pss::new::<Sha256>();
    let _ = Pss::new_with_salt::<Sha256>(32);
    let _ = Pss::new_blinded::<Sha256>();
    let _ = Pss::new_blinded_with_salt::<Sha256>(32);
    let _ = pss::SigningKey::<Sha256>::new(k);
    let _ = pss::SigningKey::<Sha256>::new_with_salt_len(k, 32);
    let _ = pss::SigningKey::<Sha256>::random(&mut rng, 2048);
    let _ = BlindedSigningKey::<Sha256>::new(k);
    let _ = BlindedSigningKey::<Sha256>::new_with_salt_len(k, 32);
    let _ = BlindedSigningKey::<Sha256>::random(&mut rng, 2048);
    let _ = pss::VerifyingKey::<Sha256>::new(p);
    let _ = pss::VerifyingKey::<Sha256>::new_with_salt_len(p, 32);
    let _ = pss::VerifyingKey::<Sha256>::new_with_auto_salt_len(p);
    let _ = k.decrypt(Oaep::new::<Sha256>(), c);
    let _ = k.decrypt_blinded(&mut rng, Pkcs1v15Encrypt, c);
    let _ = k.sign(Pkcs1v15Sign::new::<Sha256>(), d);
    let _ = k.sign_with_rng(&mut rng, Pss::new::<Sha256>(), d);
    let _ = p.encrypt(&mut rng, Oaep::new::<Sha256>(), m);
    let _ = p.verify(Pkcs1v15Sign::new::<Sha256>(), d, sig);
}

fn padding_scheme(rng: R, hash: Option<Hash>) {
    let _ = PaddingScheme::new_oaep::<Sha256>();
    let _ = PaddingScheme::new_pkcs1v15_encrypt();
    let _ = PaddingScheme::new_pkcs1v15_sign(hash);
    let _ = PaddingScheme::new_pss::<Sha256, _>(rng);
    let _ = PaddingScheme::new_pkcs1v15_sign::<Sha256>();
    let _ = PaddingScheme::new_pss::<Sha256>();
}

fn legacy(mut rng: R) {
    let _ = rsa::RSAPrivateKey::new(&mut rng, 1024);
}`

	want := map[rsaParsedCall]string{
		{"rsa.RsaPrivateKey.decrypt", 2}:                    "rsa operation",
		{"rsa.RsaPrivateKey.decrypt_blinded", 3}:            "rsa operation",
		{"rsa.RsaPrivateKey.sign", 2}:                       "rsa operation",
		{"rsa.RsaPrivateKey.sign_with_rng", 3}:              "rsa-0.7 operation",
		{"rsa.RsaPublicKey.encrypt", 3}:                     "rsa-0.9 operation",
		{"rsa.RsaPublicKey.verify", 3}:                      "rsa-0.9 operation",
		{"rsa.RsaPrivateKey.new", 2}:                        "rsa factory",
		{"rsa.RsaPrivateKey.new_with_exp", 3}:               "rsa factory",
		{"rsa.Oaep.new", 0}:                                 "rsa-0.8 factory",
		{"rsa.Oaep.new_with_label", 1}:                      "rsa-0.8 factory",
		{"rsa.Oaep.new_with_mgf_hash", 0}:                   "rsa-0.8 factory",
		{"rsa.Oaep.new_with_mgf_hash_and_label", 1}:         "rsa-0.8 factory",
		{"rsa::oaep.EncryptingKey.new", 1}:                  "rsa-0.8.2 factory",
		{"rsa::oaep.DecryptingKey.new", 1}:                  "rsa-0.8.2 factory",
		{"rsa::pkcs1v15.EncryptingKey.new", 1}:              "rsa-0.8.2 factory",
		{"rsa::pkcs1v15.DecryptingKey.new", 1}:              "rsa-0.8.2 factory",
		{"rsa.Pkcs1v15Sign.new", 0}:                         "rsa-0.8 factory",
		{"rsa.Pkcs1v15Sign.new_unprefixed", 0}:              "rsa-0.9 factory",
		{"rsa::pkcs1v15.SigningKey.new", 1}:                 "rsa-0.7 factory",
		{"rsa::pkcs1v15.SigningKey.new_with_prefix", 1}:     "rsa-0.7-prefixed factory",
		{"rsa::pkcs1v15.SigningKey.new_unprefixed", 1}:      "rsa-0.9 factory",
		{"rsa::pkcs1v15.SigningKey.random", 2}:              "rsa-0.8 factory",
		{"rsa::pkcs1v15.VerifyingKey.new", 1}:               "rsa-0.7 factory",
		{"rsa::pkcs1v15.VerifyingKey.new_with_prefix", 1}:   "rsa-0.7-prefixed factory",
		{"rsa::pkcs1v15.VerifyingKey.new_unprefixed", 1}:    "rsa-0.9 factory",
		{"rsa.Pss.new", 0}:                                  "rsa-0.8 factory",
		{"rsa.Pss.new_with_salt", 1}:                        "rsa-0.8 factory",
		{"rsa.Pss.new_blinded", 0}:                          "rsa-0.8 factory",
		{"rsa.Pss.new_blinded_with_salt", 1}:                "rsa-0.8 factory",
		{"rsa::pss.SigningKey.new", 1}:                      "rsa-0.7 factory",
		{"rsa::pss.SigningKey.new_with_salt_len", 2}:        "rsa-0.7 factory",
		{"rsa::pss.SigningKey.random", 2}:                   "rsa-0.8 factory",
		{"rsa::pss.BlindedSigningKey.new", 1}:               "rsa-0.7 factory",
		{"rsa::pss.BlindedSigningKey.new_with_salt_len", 2}: "rsa-0.7 factory",
		{"rsa::pss.BlindedSigningKey.random", 2}:            "rsa-0.9 factory",
		{"rsa::pss.VerifyingKey.new", 1}:                    "rsa-0.7 factory",
		{"rsa::pss.VerifyingKey.new_with_salt_len", 2}:      "rsa-0.9 factory",
		{"rsa::pss.VerifyingKey.new_with_auto_salt_len", 1}: "rsa-0.10 factory",
		{"rsa.PaddingScheme.new_oaep", 0}:                   "rsa-padding-scheme factory",
		{"rsa.PaddingScheme.new_pkcs1v15_encrypt", 0}:       "rsa-padding-scheme factory",
		{"rsa.PaddingScheme.new_pkcs1v15_sign", 1}:          "rsa-padding-scheme-0.3 factory",
		{"rsa.PaddingScheme.new_pss", 1}:                    "rsa-padding-scheme-0.3 factory",
		{"rsa.PaddingScheme.new_pkcs1v15_sign", 0}:          "rsa-padding-scheme-0.7 factory",
		{"rsa.PaddingScheme.new_pss", 0}:                    "rsa-padding-scheme-0.7 factory",
		{"rsa.RSAPrivateKey.new", 2}:                        "rsa-0.1 factory",
	}

	seen := map[rsaParsedCall]bool{}
	for _, c := range parseRsaCalls(t, src) {
		expect, ok := want[c]
		if !ok {
			continue
		}
		seen[c] = true
		got := kb.ContractsFor(c.method, c.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want exactly one", c.method, c.arity, len(got))
			continue
		}
		if actual := got[0].SourceLibrary + " " + got[0].Role; actual != expect {
			t.Errorf("contract for %s#%d = %s, want %s", c.method, c.arity, actual, expect)
		}
	}
	for c := range want {
		if !seen[c] {
			t.Errorf("the parser emitted no call %s#%d", c.method, c.arity)
		}
	}
}

// A consumer's own `mod rsa` and a foreign crate's same-named types are not the
// rsa crate, and must reach no rsa contract.
func TestRsaContractsIgnoreForeignIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	src := `mod rsa {
    pub struct Oaep;
    impl Oaep { pub fn new() -> Self { Oaep } }
}
use ecdsa::SigningKey;

fn f(k: K) {
    let _ = rsa::Oaep::new();
    let _ = SigningKey::from_bytes(k);
    let _ = sha2::Sha256::new();
}`

	calls := parseRsaCalls(t, src)
	if len(calls) == 0 {
		t.Fatal("the parser emitted no calls")
	}
	for _, c := range calls {
		for _, ctr := range kb.ContractsFor(c.method, c.arity) {
			if ctr.SourceLibrary == "rsa" || strings.HasPrefix(ctr.SourceLibrary, "rsa-") {
				t.Errorf("%s#%d resolved to rsa contract %s (%s)", c.method, c.arity, ctr.Method, ctr.SourceLibrary)
			}
		}
	}
}

type rsaParsedCall struct {
	method string
	arity  int
}

func parseRsaCalls(t *testing.T, src string) []rsaParsedCall {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	var out []rsaParsedCall
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				call := &fn.Calls[j]
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				out = append(out, rsaParsedCall{method, len(call.Arguments)})
			}
		}
	}
	return out
}
