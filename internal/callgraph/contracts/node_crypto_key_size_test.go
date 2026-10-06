// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// nodeCryptoOptionUnits is the unit of each options-object property a Node
// crypto contract reads its key size from, as nodejs/node doc/api/crypto.md
// documents it: modulusLength "Key size in bits (RSA, DSA)", primeLength "Prime
// length in bits (DH)", length "The bit length of the key to generate", and
// namedCurve "Name of the curve to use (EC)", whose size is looked up.
var nodeCryptoOptionUnits = map[string]keySizeUnit{
	"modulusLength": unitBits,
	"primeLength":   unitBits,
	"length":        unitBits,
	"namedCurve":    unitCurve,
}

// TestNodeCryptoKeySizeRolesAreUnitAudited pins that every keySize role of the
// node KB names the options property it reads and that the derivation agrees
// with that property's documented unit.
func TestNodeCryptoKeySizeRolesAreUnitAudited(t *testing.T) {
	t.Parallel()
	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}
	seen := make(map[string]bool, len(nodeCryptoOptionUnits))
	roles := 0
	for _, group := range kb.Contracts {
		for _, contract := range group {
			for _, parameter := range contract.Parameters {
				if parameter.Contributes == nil || parameter.Contributes.Property != "keySize" {
					continue
				}
				roles++
				property := parameter.Contributes.ArgumentProperty
				unit, ok := nodeCryptoOptionUnits[property]
				if !ok {
					t.Errorf("%s contributes keySize from argument property %q, which has no audited unit", contract.Method, property)
					continue
				}
				seen[property] = true
				if string(unit) != parameter.Contributes.Derivation {
					t.Errorf("%s reads %s with derivation %s, audited unit requires %s", contract.Method, property, parameter.Contributes.Derivation, unit)
				}
				if contract.When == nil {
					t.Errorf("%s reads %s without a key-type condition: the property belongs to one key type", contract.Method, property)
				}
			}
		}
	}
	if roles == 0 {
		t.Fatal("node KB declares no keySize role")
	}
	for property := range nodeCryptoOptionUnits {
		if !seen[property] {
			t.Errorf("%s is audited but no node contract reads it any more", property)
		}
	}
}

// TestNodeCryptoKeySizeSpellingsAgree pins that the bare and node:-prefixed
// module spellings declare the same key-size roles, so the import form a
// consumer picks never changes which size is read.
func TestNodeCryptoKeySizeSpellingsAgree(t *testing.T) {
	t.Parallel()
	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}
	signature := func(c contracts.Contract) string {
		role := ""
		for _, p := range c.Parameters {
			if p.Contributes != nil && p.Contributes.Property == "keySize" {
				role = p.Contributes.ArgumentProperty + ":" + p.Contributes.Derivation
			}
		}
		return strings.Join(c.When.ArgValueIn, ",") + "|" + role
	}
	signatures := func(group []contracts.Contract) []string {
		out := make([]string, 0, len(group))
		for _, c := range group {
			out = append(out, signature(c))
		}
		slices.Sort(out)
		return out
	}
	for key, group := range kb.Contracts {
		if !strings.HasPrefix(key, "crypto.") {
			continue
		}
		prefixed := kb.Contracts["node:"+key]
		want, got := signatures(group), signatures(prefixed)
		if !slices.Equal(want, got) {
			t.Errorf("%s declares %v, node:%s declares %v", key, want, key, got)
		}
	}
}

func TestLoadRejectsMalformedArgumentProperty(t *testing.T) {
	t.Parallel()
	const template = `schema_version: "2"
ecosystem: %s
library:
  name: "probe"
contracts:
  - method: "probe.make"
    arity: 2
    return: { type: "void", confidence: high }
    parameters:
      - index: 1
        role: metadata-contributing
        contributes: { property: keySize, derivation: argument_value, argument_property: %s }
`
	for _, tc := range []struct {
		name, ecosystem, property, wantErr string
	}{
		{"node identifier loads", "node", "modulusLength", ""},
		{"node dollar identifier loads", "node", "$bits", ""},
		{"expression is rejected", "node", `"a.b"`, "not a plain identifier"},
		{"leading digit is rejected", "node", "2048", "not a plain identifier"},
		{"python is rejected", "python", "modulusLength", "valid only in the node ecosystem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := contracts.Load([]byte(fmt.Sprintf(template, tc.ecosystem, tc.property)))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
