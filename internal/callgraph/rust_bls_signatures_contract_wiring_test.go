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

// The bls-signatures KB is keyed on what the Rust parser emits, and this crate
// mixes two key shapes in one crate root.
//
// The three TYPES are re-exported from the crate root, so their keys carry no
// module segment: `bls_signatures.PrivateKey.sign`. The crate-root FREE
// functions — `verify`, `verify_messages`, `aggregate`, `hash` — key as
// `bls_signatures.<fn>` with no type at all. A key written with the wrong shape
// resolves to nothing, which looks exactly like having no contract.
//
// WHAT THIS CONTRACT FIXES IS NOT ONLY AN ABSENT TYPE. Without it,
// `sk.public_key().verify(sig, msg)` had its receiver typed as `std::Vec` — a
// WRONG attribution, naming Vec's method for a BLS verification. That is the
// defect this test pins first. The `std::Vec` spelling of it needs a consumer
// that declares a same-named `public_key()` of its own returning `Vec<u8>`;
// without one the call lands in the consumer's package instead, which the
// contract header records with the measurement.
func TestBlsSignaturesContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// The FULL BUILDER, not the parser alone: contract-driven chain propagation
	// runs after the KB is loaded.
	dir := t.TempDir()
	src := `use bls_signatures::{aggregate, verify, verify_messages, PrivateKey, PublicKey, Serialize, Signature};

fn app(rng: &mut R, sigs: &[Signature], sink: &mut Vec<u8>) {
    let sk = PrivateKey::generate(rng);
    let derived = PrivateKey::new(b"seed material");
    let parsed = PrivateKey::from_string("1234");
    let pk = sk.public_key();
    let sig = sk.sign(b"message");
    let point = bls_signatures::hash(b"message");
    let ok = verify(&sig, &[point], &[pk]);
    let ok2 = pk.verify(sig, b"message");
    let ok3 = verify_messages(&sig, &[b"message"], &[pk]);
    let agg = aggregate(sigs);
    let affine = pk.as_affine();
    let raw = sk.as_bytes();
    sk.write_bytes(sink);
    let back = PrivateKey::from_bytes(&raw);
    let pk_raw = pk.as_bytes();
    pk.write_bytes(sink);
    let pk_back = PublicKey::from_bytes(&pk_raw);
    let sig_raw = sig.as_bytes();
    sig.write_bytes(sink);
    let sig_back = Signature::from_bytes(&sig_raw);
    let _ = (ok, ok2, ok3, agg, affine, back, derived, parsed, pk_back, sig_back);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	want := map[string]string{
		"bls_signatures.PrivateKey.generate":    "factory",
		"bls_signatures.PrivateKey.new":         "factory",
		"bls_signatures.PrivateKey.from_string": "factory",
		"bls_signatures.PrivateKey.public_key":  "factory",
		"bls_signatures.PrivateKey.sign":        "operation",
		"bls_signatures.PrivateKey.from_bytes":  "factory",
		"bls_signatures.PrivateKey.as_bytes":    "output",
		"bls_signatures.PrivateKey.write_bytes": "output",
		"bls_signatures.PublicKey.as_affine":    "output",
		"bls_signatures.PublicKey.from_bytes":   "factory",
		"bls_signatures.PublicKey.as_bytes":     "output",
		"bls_signatures.PublicKey.write_bytes":  "output",
		"bls_signatures.Signature.from_bytes":   "factory",
		"bls_signatures.Signature.as_bytes":     "output",
		"bls_signatures.Signature.write_bytes":  "output",
		"bls_signatures.hash":                   "operation",
		"bls_signatures.verify":                 "operation",
		"bls_signatures.verify_messages":        "operation",
		"bls_signatures.aggregate":              "operation",
		// The one the contract rescued from `std.Vec.verify`.
		"bls_signatures.PublicKey.verify": "operation",
	}
	seen := map[string]bool{}

	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			callee := fn.Calls[i].Callee
			method, _ := splitMethodArity(&callee)
			role, ok := want[method]
			if !ok {
				continue
			}
			got := kb.ContractsFor(method, len(fn.Calls[i].Arguments))
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
					method, len(fn.Calls[i].Arguments), len(got))
			}
			if got[0].Role != role || got[0].SourceLibrary != "bls-signatures" {
				t.Fatalf("contract for %q = %#v, want bls-signatures %s", method, got[0], role)
			}
			seen[method] = true
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}

	// EVERY declared entry has to be driven through the builder, not just the
	// interesting ones. A first draft's fixture exercised 6 of the entries and
	// left the rest to the static surface check, which is how `write_bytes`
	// stayed missing from both: nothing failed when an entry was never called.
	declared := 0
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary == "bls-signatures" {
				declared++
			}
		}
	}
	if declared != len(want) {
		t.Fatalf("the contract declares %d entries and this fixture drives %d; "+
			"add the call to the source above rather than shrinking the check",
			declared, len(want))
	}
}

// TestBlsSignaturesContractIsTheSourcesSurface names every entry AND closes the
// set, so neither a misspelling nor an invented entry can ship.
//
// Both halves matter, and the second one is the lesson of a previous family in
// this campaign: a test that reads each entry's own method back to query it hits
// by construction and catches no typo, and a total-count assertion is worse
// than nothing — it defends invented entries, because deleting them breaks the
// count. Here the owner set and each owner's method set are both named.
func TestBlsSignaturesContractIsTheSourcesSurface(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// Read from src/key.rs and src/signature.rs at 0.15.0, and identical at
	// every version in the contract's range.
	//
	// THIS MAP IS THE SOURCES' SURFACE AND NOT A MIRROR OF THE CONTRACT, which
	// is the whole point of the second half of the check and is the half a
	// first draft got wrong: it omitted `write_bytes`, exactly as the contract
	// did, so the trait shipped two-thirds declared and this test was green
	// AND rejected the repair -- adding the real entries produced three
	// "which the sources do not have" errors. The three `Serialize` methods are
	// therefore cited individually: the trait declares `write_bytes` (key.rs:69
	// at 0.15.0), `from_bytes` (:72) and a defaulted `as_bytes` (:74), and it
	// is implemented for PrivateKey (:162), PublicKey (:198) and Signature
	// (signature.rs:54). If a method is added here it must be because it was
	// read in one of those files, not because an entry exists below.
	want := map[string]map[string]int{
		"bls_signatures::PrivateKey": {
			"generate": 1, "new": 1, "from_string": 1, "sign": 1,
			"public_key": 0,
			"from_bytes": 1, "as_bytes": 0, "write_bytes": 1,
		},
		"bls_signatures::PublicKey": {
			"verify": 2, "as_affine": 0,
			"from_bytes": 1, "as_bytes": 0, "write_bytes": 1,
		},
		"bls_signatures::Signature": {
			"from_bytes": 1, "as_bytes": 0, "write_bytes": 1,
		},
		// The crate-root free functions carry no owning type.
		"bls_signatures": {
			"verify": 3, "verify_messages": 3, "aggregate": 1, "hash": 1,
		},
	}

	declared := map[string]map[string]int{}
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary != "bls-signatures" {
				continue
			}
			dot := strings.LastIndex(entry.Method, ".")
			if dot < 0 {
				t.Errorf("entry %q has no owner separator", entry.Method)
				continue
			}
			owner, method := entry.Method[:dot], entry.Method[dot+1:]
			if declared[owner] == nil {
				declared[owner] = map[string]int{}
			}
			declared[owner][method] = entry.Arity
		}
	}

	for owner, methods := range want {
		got := declared[owner]
		if got == nil {
			t.Errorf("%s: no entries declared", owner)
			continue
		}
		for m, arity := range methods {
			gotArity, ok := got[m]
			if !ok {
				t.Errorf("%s: the sources have %q and the contract does not declare it", owner, m)
				continue
			}
			if gotArity != arity {
				t.Errorf("%s.%s declared at arity %d, the sources have %d", owner, m, gotArity, arity)
			}
		}
		for m := range got {
			if _, ok := methods[m]; !ok {
				t.Errorf("%s: the contract declares %q, which the sources do not have", owner, m)
			}
		}
	}
	for owner := range declared {
		if _, ok := want[owner]; !ok {
			t.Errorf("the contract declares entries for %q, which is not a type the crate has", owner)
		}
	}
}
