// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A method call whose RECEIVER is another method call on a third-party type.
//
// The crate's own facts only describe what the scanned source declares, so a
// third-party method had no declared return type at parse time and the chain
// broke at the first link. The next call in the chain then fell through to the
// unresolved branch and came out owned by the SCANNED crate -- a wrong identity
// rather than a missing one, because it looks resolved and matches no contract.
//
// Builder APIs are where this bites, because returning `&mut Self` exists so
// that calls chain, and chaining is how their documentation shows them.
// Measured on security-framework 3.7.0's SecTransform encrypt builder:
//
//	before: `b.padding(..).mode(..)`  ->  padding resolved, `mode` came out as
//	        `<scanned crate>.mode`
//	after:  both resolve to
//	        `security_framework::os::macos::encrypt_transform.Builder.<method>`
//
// The contracts KB is the declaration for those methods, and the parser already
// loads it for associated-type resolution.
func TestRustParser_ChainedThirdPartyReceiverResolvesThroughContracts(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
security-framework = "3.7"
`

	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			// The case that already worked, pinned so the change cannot
			// regress it: separate statements, receiver bound to a name.
			name: "separate statements still resolve",
			body: `use security_framework::os::macos::encrypt_transform::{Builder, Mode, Padding};

fn go() {
    let mut b = Builder::new();
    b.padding(Padding::pkcs7());
    b.mode(Mode::cbc());
}
`,
			want: []string{
				"security_framework::os::macos::encrypt_transform.Builder.padding",
				"security_framework::os::macos::encrypt_transform.Builder.mode",
			},
		},
		{
			name: "chained setters resolve to the owning crate",
			body: `use security_framework::os::macos::encrypt_transform::{Builder, Mode, Padding};

fn go() {
    let mut b = Builder::new();
    b.padding(Padding::pkcs7()).mode(Mode::cbc());
}
`,
			want: []string{
				"security_framework::os::macos::encrypt_transform.Builder.padding",
				"security_framework::os::macos::encrypt_transform.Builder.mode",
			},
		},
		{
			name: "a chain three links long",
			body: `use security_framework::key::{GenerateKeyOptions, KeyType};

fn go() {
    let mut o = GenerateKeyOptions::default();
    o.set_key_type(KeyType::rsa()).set_size_in_bits(2048).set_label("k");
}
`,
			want: []string{
				"security_framework::key.GenerateKeyOptions.set_key_type",
				"security_framework::key.GenerateKeyOptions.set_size_in_bits",
				"security_framework::key.GenerateKeyOptions.set_label",
			},
		},
		{
			// A contract that declares canonical_return_type behind a Result:
			// `SecIdentity::private_key` yields a SecKey, and the operation on
			// it has to resolve to the key's type, not the identity's.
			name: "canonical_return_type carries the concrete type past a wrapper",
			body: `use security_framework::identity::SecIdentity;
use security_framework::key::Algorithm;

fn go(id: &SecIdentity) {
    let k = id.private_key().unwrap();
    let _ = k.create_signature(Algorithm::RSASignatureMessagePSSSHA256, b"m");
}
`,
			want: []string{
				"security_framework::key.SecKey.create_signature",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
				"Cargo.toml": manifest,
				"src/lib.rs": tt.body,
			}, "app"), "\n")
			for _, want := range tt.want {
				if !strings.Contains(joined, want) {
					t.Errorf("missing %q; got:\n%s", want, joined)
				}
			}
			// The failure this fixes is a WRONG key, so absence of the wrong
			// one is asserted as well as presence of the right one.
			for _, line := range strings.Split(joined, "\n") {
				if strings.HasPrefix(line, "app.") && line != "app." {
					t.Errorf("a third-party call came out owned by the scanned crate: %q", line)
				}
			}
		})
	}
}

// A method with no contract must stay unresolved rather than borrow the
// receiver's type. Guessing here would turn every unknown chain link into a
// confident wrong identity, which is the failure mode the whole resolver is
// written to avoid.
func TestRustParser_UncontractedChainLinkStaysUnresolved(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
security-framework = "3.7"
`
	body := `use security_framework::os::macos::encrypt_transform::Builder;

fn go() {
    let mut b = Builder::new();
    b.no_such_method().also_not_a_method();
}
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml": manifest,
		"src/lib.rs": body,
	}, "app"), "\n")

	if strings.Contains(joined, "Builder.also_not_a_method") {
		t.Errorf("an uncontracted method was given the receiver's type:\n%s", joined)
	}
}
