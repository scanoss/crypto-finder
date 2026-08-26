// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Curve-crate KBs bind the concrete type aliases, so a parser identity change
// must fail here rather than resolving the generic ecdsa crate instead.
func TestEllipticCurveContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use k256::ecdsa::SigningKey;
use k256::ecdh::EphemeralSecret;
use p256::ecdsa::VerifyingKey;

fn demo(peer: &k256::PublicKey, msg: &[u8], sig: &k256::ecdsa::Signature) {
    let _a = SigningKey::generate();
    let _b = k256::SecretKey::generate();
    let _c = EphemeralSecret::generate();
    let _d = _c.diffie_hellman(peer);
    let _e = _a.sign(msg);
    let _f = VerifyingKey::from_sec1_bytes(msg);
    let _g = k256::schnorr::SigningKey::generate();
    let _h = p384::ecdsa::SigningKey::random(&mut rng);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"k256::ecdsa.SigningKey.generate":          "k256",
		"k256.SecretKey.generate":                  "k256",
		"k256::ecdh.EphemeralSecret.generate":      "k256",
		"k256::schnorr.SigningKey.generate":        "k256",
		"p256::ecdsa.VerifyingKey.from_sec1_bytes": "p256",
		"p384::ecdsa.SigningKey.random":            "p384",
	}
	seen := map[string]bool{}
	var parsed []string

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				parsed = append(parsed, method)
				library, ok := want[method]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract (method key %q); parsed = %v",
						method, len(call.Arguments), len(got), method, parsed)
				}
				if got[0].SourceLibrary != library {
					t.Fatalf("contract for %q = %#v, want library %s", method, got[0], library)
				}
				seen[method] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v; parsed = %v", method, seen, parsed)
		}
	}
}
