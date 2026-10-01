// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSnarkjs(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		typ    string
		role   string
	}
	for _, w := range []want{
		// 0.3 and later, one namespace per proof system. The logger and the
		// options are optional trailing arguments.
		{"snarkjs.groth16.fullProve", 3, "snarkjs.ProofResult", "operation"},
		{"snarkjs.groth16.fullProve", 6, "snarkjs.ProofResult", "operation"},
		{"snarkjs.groth16.prove", 2, "snarkjs.ProofResult", "operation"},
		{"snarkjs.groth16.verify", 3, "boolean", "operation"},
		{"snarkjs.plonk.setup", 3, "void", "operation"},
		{"snarkjs.plonk.fullProve", 4, "snarkjs.ProofResult", "operation"},
		{"snarkjs.plonk.verify", 4, "boolean", "operation"},
		{"snarkjs.fflonk.setup", 4, "number", "operation"},
		{"snarkjs.fflonk.prove", 4, "snarkjs.ProofResult", "operation"},
		{"snarkjs.fflonk.verify", 3, "boolean", "operation"},
		{"snarkjs.zKey.newZKey", 3, "Uint8Array", "operation"},
		{"snarkjs.zKey.contribute", 5, "Uint8Array", "operation"},
		{"snarkjs.zKey.beacon", 5, "Uint8Array", "operation"},
		{"snarkjs.zKey.exportVerificationKey", 1, "snarkjs.VerificationKey", "operation"},
		{"snarkjs.zKey.verifyFromInit", 3, "boolean", "operation"},
		{"snarkjs.zKey.verifyFromR1cs", 4, "boolean", "operation"},
		{"snarkjs.powersOfTau.newAccumulator", 3, "Uint8Array", "operation"},
		{"snarkjs.powersOfTau.contribute", 4, "Uint8Array", "operation"},
		{"snarkjs.powersOfTau.beacon", 6, "Uint8Array", "operation"},
		{"snarkjs.powersOfTau.preparePhase2", 2, "void", "operation"},
		{"snarkjs.powersOfTau.verify", 1, "boolean", "operation"},
		// 0.2: the three protocols under their own namespaces.
		{"snarkjs.original.setup", 1, "snarkjs.SetupResult", "operation"},
		{"snarkjs.groth.genProof", 2, "snarkjs.ProofResult", "operation"},
		{"snarkjs.kimleeoh.isValid", 3, "boolean", "operation"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
	}

	// groth16 has no setup of its own: zKey.newZKey is its circuit setup. The
	// export, conversion and serialization helpers compute nothing of their own.
	for _, unwanted := range []string{
		"snarkjs.groth16.setup#3",
		"snarkjs.groth16.exportSolidityCallData#2",
		"snarkjs.plonk.exportSolidityCallData#2",
		"snarkjs.fflonk.exportSolidityVerifier#2",
		"snarkjs.zKey.exportJson#1",
		"snarkjs.zKey.exportBellman#3",
		"snarkjs.powersOfTau.exportChallenge#3",
		"snarkjs.powersOfTau.convert#3",
		"snarkjs.r1cs.info#2",
		"snarkjs.wtns.calculate#3",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "snarkjs", "snarkjs.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "snarkjs.") {
			n++
		}
	}
	if n != 62 {
		t.Errorf("snarkjs contributes %d keys, want 62", n)
	}
}
