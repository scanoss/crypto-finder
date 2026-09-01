// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The totp-rs KB is keyed on what the Rust parser emits, so a parser identity
// change must fail here rather than leaving the contracts silently unmatched.
//
// Two things in this family are easy to get wrong and both are pinned below.
// `Secret` is declared in src/secret.rs but re-exported from the crate root, so
// the emitted key follows the consumer's spelling (`totp_rs.Secret.*`) and not
// the defining module. And `TOTP::new` has two arities: Cargo.toml declares
// `default = []`, so the five-argument form is the default build and the
// seven-argument one requires the `otpauth` feature.
func TestTotpContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use totp_rs::{Algorithm, Secret, TOTP};

// default build: no features, so new/5
fn build_default(secret: Vec<u8>) {
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret).unwrap();
    let _code = totp.generate(1_700_000_000);
    let _mac = totp.sign(1_700_000_000);
}

// otpauth feature: new/7
fn build_otpauth(secret: Vec<u8>, issuer: Option<String>, account: String) {
    let totp = TOTP::new(Algorithm::SHA256, 8, 1, 30, secret, issuer, account).unwrap();
    let _now = totp.generate_current().unwrap();
    let _ok = totp.check_current("123456").unwrap();
}

fn verify(totp: &TOTP) {
    let _ok = totp.check("123456", 1_700_000_000);
}

// The receiver a URI factory returns must be typed, or the operation chained
// off it has nothing to resolve against.
fn from_uri(uri: &str) {
    let totp = TOTP::from_url(uri).unwrap();
    let _code = totp.generate_current().unwrap();
}

fn mint() {
    let _s = Secret::generate_secret();
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Call-site keys join segments with "."; the KB keeps Rust's "::" module
	// separator and ContractsFor bridges the two.
	type want struct {
		role  string
		arity int
	}
	wants := map[string][]want{
		"totp_rs.TOTP.new":               {{"factory", 5}, {"factory", 7}},
		"totp_rs.TOTP.from_url":          {{"factory", 1}},
		"totp_rs.TOTP.generate":          {{"operation", 1}},
		"totp_rs.TOTP.generate_current":  {{"operation", 0}},
		"totp_rs.TOTP.sign":              {{"operation", 1}},
		"totp_rs.TOTP.check":             {{"operation", 2}},
		"totp_rs.TOTP.check_current":     {{"operation", 1}},
		"totp_rs.Secret.generate_secret": {{"factory", 0}},
	}
	seen := map[string]map[int]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				expected, ok := wants[method]
				if !ok {
					continue
				}
				arity := len(call.Arguments)
				got := kb.ContractsFor(method, arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
						method, arity, len(got))
				}
				if got[0].SourceLibrary != "totp-rs" {
					t.Fatalf("contract for %q came from %q, want totp-rs", method, got[0].SourceLibrary)
				}
				var matched bool
				for _, w := range expected {
					if w.arity != arity {
						continue
					}
					matched = true
					if got[0].Role != w.role {
						t.Fatalf("contract for %q/%d role = %q, want %q", method, arity, got[0].Role, w.role)
					}
				}
				if !matched {
					t.Fatalf("parsed %q at arity %d, which the KB does not declare", method, arity)
				}
				if seen[method] == nil {
					seen[method] = map[int]bool{}
				}
				seen[method][arity] = true
			}
		}
	}

	for method, expected := range wants {
		for _, w := range expected {
			if !seen[method][w.arity] {
				t.Fatalf("parsed calls did not cover %q at arity %d; seen = %v", method, w.arity, seen)
			}
		}
	}
}

// `Secret` is declared in src/secret.rs and `pub use`-exported from lib.rs.
// Keying the contract on the defining module would compile, load and silently
// never resolve, so assert the module-qualified spelling is NOT what answers.
func TestTotpSecretContractFollowsConsumerSpellingNotDefiningModule(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	if got := kb.ContractsFor("totp_rs.Secret.generate_secret", 0); len(got) != 1 {
		t.Fatalf("ContractsFor(consumer spelling) = %d, want exactly one", len(got))
	}
	if got := kb.ContractsFor("totp_rs.secret.Secret.generate_secret", 0); len(got) != 0 {
		t.Fatalf("the defining-module spelling resolved (%d contracts); the KB must "+
			"follow the crate-root re-export the consumer writes", len(got))
	}
}

// The URI and RFC factories are typed so a chained operation resolves, and they
// must stay factories: a contract carries no crypto assertion, and promoting
// them to operations is the nearest way this file could start claiming that
// parsing an otpauth:// URI is cryptography.
func TestTotpUriFactoriesAreNotOperations(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, method := range []string{
		"totp_rs.TOTP.from_url",
		"totp_rs.TOTP.from_url_unchecked",
		"totp_rs.TOTP.from_rfc6238",
	} {
		got := kb.ContractsFor(method, 1)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, 1) = %d, want exactly one", method, len(got))
		}
		if got[0].Role != "factory" {
			t.Errorf("%s: role = %q, want factory", method, got[0].Role)
		}
	}
}
