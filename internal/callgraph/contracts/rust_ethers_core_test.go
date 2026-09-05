// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// ethers-core exports `Signature` and `PrivateKey` from its `types` module and
// reaches the `Eip712` trait through three submodules, so the call graph emits
// `ethers_core::types.Signature.recover` and
// `ethers_core::types::transaction::eip712.Eip712.encode_eip712` while the KB
// file authors both with the second-to-last dot moved to "::" — rustAuthoredKey
// does that at load time. Its FREE FUNCTIONS carry only ONE dot, so
// `ethers_core::utils.keccak256` has no separator to move and is authored
// verbatim. Both shapes are exercised below, and
// TestEthersCoreEmittedCallSiteKeysResolve pins the spellings the parser
// actually looks up.
//
// The set is compared EXACTLY. A per-key assertion cannot see an entry that
// should not be there, an entry that was dropped, or a field that was
// corrupted; only a whole-set comparison does. The rendering deliberately
// includes the `parameters` block and the arity, because a renamed contributed
// property or a changed derivation loads cleanly through the schema's presence
// checks and would otherwise pass an "exact" test unchanged.
func renderEthersCoreContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "ethers-core" {
				continue
			}
			var params strings.Builder
			for _, p := range c.Parameters {
				idx := -1
				if p.Index != nil {
					idx = *p.Index
				}
				prop, der := "", ""
				if p.Contributes != nil {
					prop, der = p.Contributes.Property, p.Contributes.Derivation
				}
				fmt.Fprintf(&params, "{%d:%s:%s:%s:%s}", idx, p.Name, p.Role, prop, der)
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence, params.String()))
		}
	}
	sort.Strings(got)
	return got
}

// The three eip712 FREE functions carry `role: operation`, not `output`, and
// that is load-bearing rather than cosmetic: export.go branches on Role, and
// every non-operation role is computed from `receiverType(c.Method)` against a
// builder or return type. A free function has no receiver, so an `output` role
// makes the entry unemittable as a supporting call -- which is why the two
// free functions in `utils` were already `operation`.
var wantEthersCoreContracts = []string{
	"ethers_core::types::PrivateKey.new#1/factory/ethers_core::types::PrivateKey/ethers_core::types::PrivateKey/[&mut R]/high/{0:rng:metadata-contributing:keyMaterial:argument_type}",
	"ethers_core::types::PrivateKey.sign#1/operation/ethers_core::types::Signature/ethers_core::types::Signature/[S]/high/{0:message:operation-determining:signatureAlgorithm:argument_type}",
	"ethers_core::types::PrivateKey.sign_transaction#2/operation/ethers_core::types::Transaction/core::result::Result<ethers_core::types::Transaction, ethers_core::types::TxError>/[ethers_core::types::TransactionRequest,core::option::Option<u64>]/high/{1:chain_id:metadata-contributing:parameterSet:argument_value}",
	"ethers_core::types::Signature.recover#1/operation/ethers_core::types::Address/core::result::Result<ethers_core::types::Address, ethers_core::types::SignatureError>/[M]/high/{0:message:operation-determining:signatureAlgorithm:argument_type}",
	"ethers_core::types::Signature.recover_typed_data#1/operation/ethers_core::types::Address/core::result::Result<ethers_core::types::Address, ethers_core::types::SignatureError>/[T]/high/{0:payload:operation-determining:signatureAlgorithm:argument_type}",
	"ethers_core::types::Signature.verify#2/operation/()/core::result::Result<(), ethers_core::types::SignatureError>/[M,A]/high/{1:address:metadata-contributing:keyMaterial:argument_value}",
	"ethers_core::types::transaction::eip712.hash_struct#3/operation/[u8; 32]/core::result::Result<[u8; 32], ethers_core::types::transaction::eip712::Eip712Error>/[&str,&serde_json::Value,&ethers_core::types::transaction::eip712::Types]/high/",
	"ethers_core::types::transaction::eip712.hash_type#2/operation/[u8; 32]/core::result::Result<[u8; 32], ethers_core::types::transaction::eip712::Eip712Error>/[&str,&ethers_core::types::transaction::eip712::Types]/high/",
	"ethers_core::types::transaction::eip712.make_type_hash#2/operation/[u8; 32]/[u8; 32]/[alloc::string::String,&[(alloc::string::String, ethabi::ParamType)]]/high/",
	"ethers_core::types::transaction::eip712::EIP712Domain.separator#0/output/[u8; 32]/[u8; 32]/[]/high/",
	"ethers_core::types::transaction::eip712::Eip712.domain_separator#0/output/[u8; 32]/core::result::Result<[u8; 32], Self::Error>/[]/medium/",
	"ethers_core::types::transaction::eip712::Eip712.encode_eip712#0/output/[u8; 32]/core::result::Result<[u8; 32], Self::Error>/[]/medium/",
	"ethers_core::types::transaction::eip712::Eip712.struct_hash#0/output/[u8; 32]/core::result::Result<[u8; 32], Self::Error>/[]/medium/",
	"ethers_core::types::transaction::eip712::Eip712.type_hash#0/output/[u8; 32]/core::result::Result<[u8; 32], Self::Error>/[]/medium/",
	"ethers_core::utils.hash_message#1/operation/ethers_core::types::H256/ethers_core::types::H256/[]/high/{0:message:operation-determining:digestLength:argument_type}",
	"ethers_core::utils.keccak256#1/operation/[u8; 32]/[u8; 32]/[]/high/{0:bytes:operation-determining:digestLength:argument_type}",
}

func TestLoadEmbeddedRustEthersCoreContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderEthersCoreContracts(t)
	want := append([]string(nil), wantEthersCoreContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("ethers-core contracts: got %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("unexpected ethers-core contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing ethers-core contract:    %s", w)
		}
	}
}

// The `library:` block is parsed and then never consulted by any other
// assertion, so corrupting the coordinates, the version range or the
// description leaves an otherwise-exact contract test green. Measured on this
// family: every one of those four fields can be changed without any other test
// in this file failing. Pin them by loading the single YAML directly —
// LoadEmbedded merges every rust KB and drops Library to nil, so the merged
// knowledge base cannot see them.
func TestEthersCoreLibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("rust", "ethers-core.yaml"))
	if err != nil {
		t.Fatalf("read ethers-core.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(ethers-core.yaml): %v", err)
	}
	if kb.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want 2", kb.SchemaVersion)
	}
	if kb.Ecosystem != "rust" {
		t.Errorf("ecosystem = %q, want rust", kb.Ecosystem)
	}
	if kb.Library == nil {
		t.Fatal("library block did not load")
	}
	if kb.Library.Name != "ethers-core" {
		t.Errorf("library.name = %q, want ethers-core", kb.Library.Name)
	}
	if got := strings.Join(kb.Library.Coordinates, ","); got != "ethers-core" {
		t.Errorf("library.coordinates = %q, want ethers-core", got)
	}
	// The committed matrix lists 61 releases, 0.1.0 through 2.0.14.
	if kb.Library.VersionRange != ">=0.1.0-0,<2.1.0" {
		t.Errorf("library.version_range = %q, want >=0.1.0-0,<2.1.0", kb.Library.VersionRange)
	}
	if !strings.Contains(kb.Library.Description, "Keccak-256") ||
		strings.Contains(kb.Library.Description, "SHA3") {
		t.Errorf("library.description must name Keccak-256 and must not claim SHA-3; got %q",
			kb.Library.Description)
	}
	if len(kb.Contracts) == 0 {
		t.Fatal("no contracts loaded from ethers-core.yaml")
	}
}

// THE DOT-JOINED SPELLING THE CALL GRAPH EMITS MUST RESOLVE, because that — not
// the authored spelling — is what the parser looks up. Read off the exported
// call graph of a probe consumer that calls each API the way a real consumer
// does. Two shapes are present and they normalise differently: a free function
// carries one dot and is looked up verbatim, a method carries two and has its
// second-to-last dot rewritten.
//
// Arities exclude the receiver: `Signature::verify(&self, message, address)` is
// 2, `Eip712::encode_eip712(&self)` is 0.
func TestEthersCoreEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := map[string]int{
		// free functions — ONE dot, no separator to move
		"ethers_core::utils.keccak256":                           1,
		"ethers_core::utils.hash_message":                        1,
		"ethers_core::types::transaction::eip712.hash_struct":    3,
		"ethers_core::types::transaction::eip712.hash_type":      2,
		"ethers_core::types::transaction::eip712.make_type_hash": 2,
		// methods — TWO dots, rustAuthoredKey moves the second-to-last
		"ethers_core::types.Signature.recover":                            1,
		"ethers_core::types.Signature.verify":                             2,
		"ethers_core::types.Signature.recover_typed_data":                 1,
		"ethers_core::types.PrivateKey.new":                               1,
		"ethers_core::types.PrivateKey.sign":                              1,
		"ethers_core::types.PrivateKey.sign_transaction":                  2,
		"ethers_core::types::transaction::eip712.Eip712.encode_eip712":    0,
		"ethers_core::types::transaction::eip712.Eip712.struct_hash":      0,
		"ethers_core::types::transaction::eip712.Eip712.type_hash":        0,
		"ethers_core::types::transaction::eip712.Eip712.domain_separator": 0,
		"ethers_core::types::transaction::eip712.EIP712Domain.separator":  0,
	}

	for key, arity := range emitted {
		got := kb.ContractsFor(key, arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) returned %d contracts, want 1", key, arity, len(got))
			continue
		}
		if got[0].SourceLibrary != "ethers-core" {
			t.Errorf("ContractsFor(%q, %d) resolved to library %q, want ethers-core",
				key, arity, got[0].SourceLibrary)
		}
	}

	// A wrong arity must NOT resolve, or the assertion above would pass for a
	// contract declared at any arity at all.
	if got := kb.ContractsFor("ethers_core::types.Signature.verify", 1); len(got) != 0 {
		t.Errorf("Signature.verify at arity 1 resolved to %d contracts, want 0", len(got))
	}
	// A key that was never declared must not resolve either.
	if got := kb.ContractsFor("ethers_core::utils.id", 1); len(got) != 0 {
		t.Errorf("utils.id is deliberately uncontracted but resolved to %d contracts", len(got))
	}
}
