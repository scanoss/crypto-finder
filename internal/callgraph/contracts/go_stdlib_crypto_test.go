// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesStdlibCryptoContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	var inventory []string
	roles := make(map[string]int)
	parameterRoles := 0
	for _, candidates := range kb.Contracts {
		for _, contract := range candidates {
			if contract.SourceLibrary != "go-stdlib-crypto" {
				continue
			}
			roles[contract.Role]++
			line := fmt.Sprintf("%s#%d|%s|%s", contract.Method, contract.Arity, contract.Return.Type, contract.Role)
			for _, parameter := range contract.Parameters {
				index := -1
				if parameter.Index != nil {
					index = *parameter.Index
				}
				if parameter.Contributes == nil {
					line += fmt.Sprintf("|%d:%s:%s", index, parameter.Name, parameter.Role)
					continue
				}
				parameterRoles++
				line += fmt.Sprintf("|%d:%s:%s:%s:%s", index, parameter.Name, parameter.Role, parameter.Contributes.Property, parameter.Contributes.Derivation)
			}
			inventory = append(inventory, line)
		}
	}

	sort.Strings(inventory)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(inventory, "\n"))))
	if len(inventory) != 177 || roles["factory"] != 70 || roles["config"] != 9 || roles["operation"] != 72 || roles["output"] != 26 || parameterRoles != 211 || digest != "76be0ee5b97504ebd43fdb6fa9a4049a018d2a8227bab36179791d5b971384dc" {
		t.Fatalf("stdlib inventory = %d contracts, roles %#v, %d parameter roles, digest %s", len(inventory), roles, parameterRoles, digest)
	}

	tests := []struct {
		method, role, property string
		arity                  int
	}{
		{"crypto/aes.NewCipher", "factory", "keySize", 1},
		{"crypto/cipher.(AEAD).Seal", "operation", "plaintext", 4},
		{"crypto/ecdh.(Curve).GenerateKey", "factory", "", 1},
		{"crypto/elliptic.P256", "factory", "", 0},
		{"crypto/ecdsa.Verify", "operation", "signature", 4},
		{"crypto/hkdf.Key", "operation", "algorithm", 5},
		{"crypto/sha3.(*SHAKE).Read", "output", "", 1},
		{"crypto/mlkem.(*DecapsulationKey768).Decapsulate", "operation", "ciphertext", 1},
		{"crypto/rsa.SignPSS", "operation", "options", 5},
		{"crypto/tls.LoadX509KeyPair", "factory", "", 2},
		{"crypto/x509.(*Certificate).Verify", "operation", "verificationOptions", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 || got[0].SourceLibrary != "go-stdlib-crypto" || got[0].Role != tt.role {
				t.Fatalf("ContractsFor(%q, %d) = %#v, want go-stdlib-crypto %s", tt.method, tt.arity, got, tt.role)
			}
			if tt.property == "" {
				return
			}
			for _, parameter := range got[0].Parameters {
				if parameter.Contributes != nil && parameter.Contributes.Property == tt.property {
					return
				}
			}
			t.Fatalf("contract parameters = %#v, want contribution for %q", got[0].Parameters, tt.property)
		})
	}

	if got := kb.ContractsFor("crypto/ed25519.GenerateKey", 1); len(got) != 0 {
		t.Fatalf("ed25519.GenerateKey contracts = %#v, want none: schema v2 cannot select a later tuple result", got)
	}
	if got := kb.ContractsFor("io.(Reader).Read", 1); len(got) != 0 {
		t.Fatalf("io.Reader.Read contracts = %#v, want none: a generic reader contract would over-classify non-crypto reads", got)
	}
}
