// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// THE FILE NAME ENDS IN `_kb_test.go` AND THAT IS LOAD-BEARING. Go reads a
// trailing `_GOARCH` on a source file name as a build constraint, and `wasm` is
// a GOARCH -- so `node_bls_eth_wasm_test.go` compiles ONLY on GOARCH=wasm and
// is excluded everywhere else in silence: no error, no warning, `go test -run`
// simply reports "no tests to run" and passes. Measured here before the rename,
// and it is exactly the shape of failure this campaign keeps finding: a gate
// that reports success because it never ran.
//
// Measured on a consumer exercising the whole key flow, with this KB present:
// `bls.init(bls.BLS12_381)` resolves to `bls-eth-wasm.init`, and
// `sec.setByCSPRNG()`, `sec.getPublicKey()`, `sec.sign(m)` and
// `pub.verify(sig, m)` all stay on the consumer's own module. One of five.
//
// With six Node families now measured the rule is exact and has no exceptions:
// a call reached through the IMPORTED BINDING resolves to the coordinate, a
// call on an INSTANCE does not, because a contract's return type is not
// propagated to a variable receiver.
//
//	blakejs             module-level functions   joins completely
//	bcrypt, bcryptjs    module-level functions   keys are the emitted ones
//	bitcoinjs-lib       mixed                    5 of 7
//	bls-eth-wasm        objects                  1 of 5
//	@azure/keyvault-keys client instance         0
//
// The 26 SecretKey/PublicKey/Signature entries below are correct and inert
// until receiver typing lands.
func TestLoadEmbeddedNodeBlsEthWasm(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
		want   string
	}{
		// The one that joins today. init selects the CURVE, and this library
		// builds BN254, BN381_1 and BN_SNARK1 besides BLS12-381.
		{"bls-eth-wasm.init", 1, "void"},

		// THE TWO THAT CARRY THE TYPE ACROSS STATEMENTS. Without them the
		// second half of every consumer's key flow is unrelated calls on
		// untyped variables.
		{"bls-eth-wasm.SecretKey.getPublicKey", 0, "bls-eth-wasm.PublicKey"},
		{"bls-eth-wasm.SecretKey.sign", 1, "bls-eth-wasm.Signature"},

		{"bls-eth-wasm.PublicKey.verify", 2, "boolean"},
		{"bls-eth-wasm.Signature.aggregate", 1, "boolean"},
		{"bls-eth-wasm.SecretKey.<init>", 0, "bls-eth-wasm.SecretKey"},

		// MUTATORS RETURN NOTHING, and saying otherwise would type a variable
		// as something the runtime never produces -- the same error as
		// declaring bcryptjs's async twins chainable.
		{"bls-eth-wasm.SecretKey.setByCSPRNG", 0, "void"},
		{"bls-eth-wasm.SecretKey.share", 2, "void"},
		{"bls-eth-wasm.SecretKey.recover", 2, "void"},
		{"bls-eth-wasm.SecretKey.deserialize", 1, "void"},
		{"bls-eth-wasm.SecretKey.serialize", 0, "Uint8Array"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d) resolved nothing", tc.method, tc.arity)
			continue
		}
		if got[0].Return.Type != tc.want {
			t.Errorf("ContractsFor(%q, %d) returns %q, want %q", tc.method, tc.arity, got[0].Return.Type, tc.want)
		}
	}

	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"bls-eth-wasm.SecretKey.sign", 0},
		{"bls-eth-wasm.PublicKey.verify", 1},
		{"bls-eth-wasm.SecretKey.setByCSPRNG", 1},
		{"bls-eth-wasm.init", 3},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "bls-eth-wasm.") {
			n++
		}
	}
	if n != 27 {
		t.Errorf("bls-eth-wasm contributes %d keys, want 27", n)
	}
}
