// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The snow KB is keyed on what the Rust parser emits, and snow makes that
// non-uniform in two ways a contract can get wrong silently.
//
// FIRST, THE ROOT RE-EXPORTS. lib.rs exports Builder, Keypair, Error,
// HandshakeState, TransportState and StatelessTransportState from the crate
// root, so their keys carry NO module segment. params::NoiseParams is not
// re-exported, so its key does. A key written the other way round for either
// group resolves to nothing, which looks exactly like having no contract.
//
// SECOND, THE BUILDER RENAME. `NoiseBuilder` is the 0.1.x/0.2.x name and
// `Builder` the 0.3.0+ one. Both ship in the committed range and both are
// distinct keys; recording only the modern one would leave every consumer
// pinned to the older API untyped. The two name sets are NOT aliases: the
// legacy key generator is `generate_private_key`, and the fixture below writes
// it that way because `NoiseBuilder::generate_keypair` never existed. A fixture
// that invents a call site would have the parser key it and this test pass on
// a contract entry naming nothing.
func TestSnowContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// The FULL BUILDER, not the parser alone: contract-driven chain propagation
	// runs after the KB is loaded, so a parser-only helper cannot see the keys
	// this test is about. That distinction cost a debugging pass here.
	dir := t.TempDir()
	src := `use snow::params::NoiseParams;
use snow::{Builder, NoiseBuilder};

fn modern(secret: &[u8], payload: &[u8], out: &mut [u8]) {
    let params: NoiseParams = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();
    let keypair = Builder::new(params).generate_keypair().unwrap();
    // The DIRECT chain, with no configuration link in between: this is the
    // shape that resolves. The configured one below does not, by the
    // limitation recorded in the contract header.
    let direct = Builder::new(params).build_initiator().unwrap();
    let mut handshake = Builder::new(params).local_private_key(secret).build_initiator().unwrap();
    let _ = handshake.write_message(payload, out);
    let mut transport = handshake.into_transport_mode().unwrap();
    let _ = transport.read_message(payload, out);
    transport.rekey_outgoing();
    transport.rekey_initiator_manually(secret);
    _ = (keypair, direct);
}

fn legacy(secret: &[u8]) {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let secret_key = NoiseBuilder::new(params).generate_private_key().unwrap();
    _ = (secret_key, secret);
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

	// Call-site keys join segments with "."; the KB keeps Rust's "::" module
	// separator and ContractsFor bridges the two.
	// Only the keys the graph actually resolves are asserted. What is absent is
	// absent for a reason recorded in the contract header: a Result-wrapped
	// return loses its inner type, so nothing downstream of
	// `build_initiator().unwrap()` can be typed, and chain propagation stops one
	// configuration link short. Asserting those here would pin a bug, not a
	// contract.
	want := map[string]string{
		"snow.Builder.new":                       "factory",
		"snow.Builder.generate_keypair":          "factory",
		"snow.Builder.local_private_key":         "config",
		"snow.Builder.build_initiator":           "factory",
		"snow.NoiseBuilder.new":                  "factory",
		"snow.NoiseBuilder.generate_private_key": "factory",
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
			if got[0].Role != role || got[0].SourceLibrary != "snow" {
				t.Fatalf("contract for %q = %#v, want snow %s", method, got[0], role)
			}
			seen[method] = true
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// The stateless transport is a DIFFERENT type with a DIFFERENT arity, not an
// alias: its read/write take an explicit nonce, so a consumer that manages
// nonces itself must not resolve to the stateful contract.
func TestSnowStatelessTransportIsNotTheStatefulContract(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	stateful := kb.ContractsFor("snow::TransportState.write_message", 2)
	stateless := kb.ContractsFor("snow::StatelessTransportState.write_message", 3)
	if len(stateful) != 1 || len(stateless) != 1 {
		t.Fatalf("stateful=%d stateless=%d, want one each", len(stateful), len(stateless))
	}
	if len(kb.ContractsFor("snow::StatelessTransportState.write_message", 2)) != 0 {
		t.Fatal("the stateless write resolved at the stateful arity; the nonce argument is not optional")
	}
}

// Every declared snow entry must resolve to exactly one contract of this
// library at its declared arity, with its parameter list the length its arity
// says.
//
// WHAT THIS DOES NOT PROVE, stated because the obvious reading is wrong: it
// cannot catch a misspelled method or a wrong arity. It reads the method and
// arity off the same entry it then queries, so the query hits by construction —
// verified by mutation, renaming an entry and padding its parameter list left
// every test green. What it does catch is a collision with another library's
// contract and a parameter list that does not match its arity. The keys
// themselves are pinned by name below.
func TestSnowContractEntriesAreInternallyConsistent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var entries []contracts.Contract
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary == "snow" {
				entries = append(entries, entry)
			}
		}
	}
	if len(entries) == 0 {
		t.Fatal("no snow contracts loaded")
	}
	for _, entry := range entries {
		got := kb.ContractsFor(entry.Method, entry.Arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want exactly one",
				entry.Method, entry.Arity, len(got))
			continue
		}
		if got[0].SourceLibrary != "snow" {
			t.Errorf("%q resolved to library %q, want snow", entry.Method, got[0].SourceLibrary)
		}
		if len(entry.ParameterTypes) != entry.Arity {
			t.Errorf("%q declares %d parameter types at arity %d",
				entry.Method, len(entry.ParameterTypes), entry.Arity)
		}
	}
}

// TestSnowContractKeysArePinnedByName is the check the consistency test above
// cannot be: every key is named here as a literal, so a typo in the YAML, a
// changed arity or a deleted entry fails. It is the only assertion covering the
// blocks the builder cannot reach — a `Result`-wrapped return loses its inner
// type, so nothing downstream of `build_initiator().unwrap()` can be typed, and
// the HandshakeState, TransportState, StatelessTransportState and Session keys
// are therefore unreachable from a chain.
//
// Each entry was read from the crate sources; the version and file are in the
// contract header.
func TestSnowContractKeysArePinnedByName(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type key struct {
		method string
		arity  int
		role   string
	}
	want := []key{
		// The 0.3.0+ builder.
		{"snow::Builder.new", 1, "factory"},
		{"snow::Builder.with_resolver", 2, "factory"},
		{"snow::Builder.generate_keypair", 0, "factory"},
		{"snow::Builder.build_initiator", 0, "factory"},
		{"snow::Builder.build_responder", 0, "factory"},
		{"snow::Builder.psk", 2, "config"},
		{"snow::Builder.local_private_key", 1, "config"},
		{"snow::Builder.remote_public_key", 1, "config"},
		{"snow::Builder.prologue", 1, "config"},
		{"snow::Builder.fixed_ephemeral_key_for_testing_only", 1, "config"},
		// The 0.1.x/0.2.x builder. NOT an alias: the key generator has a
		// different name and returns a bare private key.
		{"snow::NoiseBuilder.new", 1, "factory"},
		{"snow::NoiseBuilder.with_resolver", 2, "factory"},
		{"snow::NoiseBuilder.generate_private_key", 0, "factory"},
		{"snow::NoiseBuilder.build_initiator", 0, "factory"},
		{"snow::NoiseBuilder.build_responder", 0, "factory"},
		{"snow::NoiseBuilder.psk", 2, "config"},
		{"snow::NoiseBuilder.local_private_key", 1, "config"},
		{"snow::NoiseBuilder.remote_public_key", 1, "config"},
		{"snow::NoiseBuilder.prologue", 1, "config"},
		{"snow::NoiseBuilder.fixed_ephemeral_key_for_testing_only", 1, "config"},
		// What the 0.0.1-preview.0 to 0.3.0 builder returns.
		{"snow::Session.write_message", 2, "operation"},
		{"snow::Session.read_message", 2, "operation"},
		{"snow::Session.rekey", 2, "operation"},
		{"snow::Session.set_psk", 2, "config"},
		{"snow::Session.into_transport_mode", 0, "factory"},
		{"snow::Session.get_handshake_hash", 0, "output"},
		{"snow::Session.is_handshake_finished", 0, "output"},
		// 0.6.0 onwards.
		{"snow::HandshakeState.write_message", 2, "operation"},
		{"snow::HandshakeState.read_message", 2, "operation"},
		{"snow::HandshakeState.into_transport_mode", 0, "factory"},
		{"snow::HandshakeState.into_stateless_transport_mode", 0, "factory"},
		{"snow::HandshakeState.get_handshake_hash", 0, "output"},
		{"snow::HandshakeState.is_handshake_finished", 0, "output"},
		{"snow::TransportState.write_message", 2, "operation"},
		{"snow::TransportState.read_message", 2, "operation"},
		{"snow::TransportState.rekey_outgoing", 0, "operation"},
		{"snow::TransportState.rekey_incoming", 0, "operation"},
		{"snow::TransportState.rekey_manually", 2, "operation"},
		{"snow::TransportState.rekey_initiator_manually", 1, "operation"},
		{"snow::TransportState.rekey_responder_manually", 1, "operation"},
		// The stateless variant manages nonces itself, so read/write take one
		// more argument than the stateful pair above.
		{"snow::StatelessTransportState.write_message", 3, "operation"},
		{"snow::StatelessTransportState.read_message", 3, "operation"},
		{"snow::StatelessTransportState.rekey_outgoing", 0, "operation"},
		{"snow::StatelessTransportState.rekey_incoming", 0, "operation"},
		{"snow::StatelessTransportState.rekey_manually", 2, "operation"},
		{"snow::StatelessTransportState.rekey_initiator_manually", 1, "operation"},
		{"snow::StatelessTransportState.rekey_responder_manually", 1, "operation"},
		// Not root-re-exported, so its key carries the module segment.
		{"snow::params::NoiseParams.from_str", 1, "factory"},
	}

	for _, w := range want {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want exactly one",
				w.method, w.arity, len(got))
			continue
		}
		if got[0].SourceLibrary != "snow" {
			t.Errorf("%q resolved to library %q, want snow", w.method, got[0].SourceLibrary)
		}
		if got[0].Role != w.role {
			t.Errorf("%q role = %q, want %q", w.method, got[0].Role, w.role)
		}
	}

	// And nothing beyond that list: an entry added without an assertion is the
	// way an invented method reached the first round of review.
	declared := 0
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary == "snow" {
				declared++
			}
		}
	}
	if declared != len(want) {
		t.Errorf("the KB declares %d snow contracts and this test names %d; every entry needs an assertion",
			declared, len(want))
	}
}
