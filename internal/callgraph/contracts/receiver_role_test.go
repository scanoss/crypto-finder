// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func receiverContract(parameter string) []byte {
	return []byte(`
schema_version: "2"
ecosystem: go
library:
  name: test-receiver
contracts:
  - method: example.com/curve.(Curve).Generate
    arity: 1
    return:
      type: example.com/curve.Key
      confidence: high
    parameters:
      - ` + parameter + `
hierarchy: {}
`)
}

func TestContract_ReceiverRoleLoads(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load(receiverContract(`{ receiver: true, role: operation-determining, contributes: { property: keySize, derivation: argument_curve_bits } }`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	matches := kb.ContractsFor("example.com/curve.(Curve).Generate", 1)
	if len(matches) != 1 || len(matches[0].Parameters) != 1 {
		t.Fatalf("contract parameters = %#v", matches)
	}
	got := matches[0].Parameters[0]
	if !got.Receiver || got.Index != nil || got.Contributes == nil || got.Contributes.Derivation != "argument_curve_bits" {
		t.Fatalf("receiver role = %#v", got)
	}
}

func TestContract_ReceiverRoleRejectsAmbiguousShapes(t *testing.T) {
	t.Parallel()

	for name, parameter := range map[string]string{
		"with index":           `{ receiver: true, index: 0, role: operation-determining, contributes: { property: keySize, derivation: argument_curve_bits } }`,
		"with name":            `{ receiver: true, name: c, role: operation-determining, contributes: { property: keySize, derivation: argument_curve_bits } }`,
		"without contribution": `{ receiver: true, role: operation-determining }`,
		"with a value unit":    `{ receiver: true, role: operation-determining, contributes: { property: keySize, derivation: argument_value } }`,
	} {
		_, err := contracts.Load(receiverContract(parameter))
		if err == nil {
			t.Errorf("%s: expected a load error", name)
			continue
		}
		if !strings.Contains(err.Error(), "example.com/curve.(Curve).Generate") || !strings.Contains(err.Error(), "receiver") {
			t.Errorf("%s: error should name the method and the receiver field, got: %v", name, err)
		}
	}
}
