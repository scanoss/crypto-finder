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

func TestLoadEmbeddedGoIncludesXCryptoContracts(t *testing.T) {
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
			if contract.SourceLibrary != "golang-x-crypto" {
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
	if len(inventory) != 190 || roles["factory"] != 68 || roles["config"] != 3 || roles["operation"] != 93 || roles["output"] != 26 || parameterRoles != 294 || digest != "e058674bd4e54cf4a2d5702af6ebcca6916ba3433618fcb55d85b35a51caedaa" {
		t.Fatalf("x/crypto inventory = %d contracts, roles %#v, %d parameter roles, digest %s", len(inventory), roles, parameterRoles, digest)
	}
	if got := kb.ContractsFor("golang.org/x/crypto/blake2s.Sum128", 1); len(got) != 0 {
		t.Fatalf("ContractsFor(blake2s.Sum128, 1) = %#v, want nonexistent API omitted", got)
	}

	tests := []struct {
		method                                    string
		arity, parameterIndex                     int
		role, parameterRole, property, derivation string
	}{
		{"golang.org/x/crypto/argon2.IDKey", 6, 3, "operation", "metadata-contributing", "memory", "argument_value"},
		{"golang.org/x/crypto/pbkdf2.Key", 5, 4, "operation", "operation-determining", "algorithm", "argument_type"},
		{"golang.org/x/crypto/blowfish.NewCipher", 1, 0, "factory", "metadata-contributing", "keySize", "argument_bit_length"},
		{"golang.org/x/crypto/chacha20.(*Cipher).SetCounter", 1, 0, "config", "metadata-contributing", "counter", "argument_value"},
		{"golang.org/x/crypto/otr.(*PublicKey).Fingerprint", 0, -1, "output", "", "", ""},
		{"golang.org/x/crypto/acme.(*Client).UpdateReg", 2, -1, "operation", "", "", ""},
		{"golang.org/x/crypto/acme.(*Client).DeactivateReg", 1, -1, "operation", "", "", ""},
		{"golang.org/x/crypto/acme.(*Client).AccountKeyRollover", 2, 1, "operation", "metadata-contributing", "key", "argument_type"},
		{"golang.org/x/crypto/acme.(*Client).CreateCert", 4, 1, "operation", "metadata-contributing", "csr", "argument_value"},
		{"golang.org/x/crypto/ssh.ParsePrivateKeyWithPassphrase", 2, 1, "factory", "metadata-contributing", "passphrase", "argument_value"},
		{"golang.org/x/crypto/openpgp.Encrypt", 5, 4, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.SymmetricallyEncrypt", 4, 3, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.ReadMessage", 4, 3, "factory", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.Sign", 4, 3, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.DetachSign", 4, 3, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.DetachSignText", 4, 3, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.ArmoredDetachSign", 4, 3, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.ArmoredDetachSignText", 4, 3, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.NewEntity", 4, 3, "factory", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.(*Entity).SignIdentity", 3, 2, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/openpgp.(*Entity).SerializePrivate", 2, 1, "output", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/nacl/box.GenerateKey", 1, -1, "factory", "", "", ""},
		{"golang.org/x/crypto/nacl/box.Seal", 5, 2, "operation", "metadata-contributing", "nonce", "argument_value"},
		{"golang.org/x/crypto/nacl/box.OpenAfterPrecomputation", 4, 3, "operation", "metadata-contributing", "keySize", "argument_bit_length"},
		{"golang.org/x/crypto/nacl/box.SealAnonymous", 4, 2, "operation", "metadata-contributing", "publicKey", "argument_value"},
		{"golang.org/x/crypto/nacl/box.Precompute", 3, 2, "operation", "metadata-contributing", "privateKey", "argument_value"},
		{"golang.org/x/crypto/nacl/sign.GenerateKey", 1, -1, "factory", "", "", ""},
		{"golang.org/x/crypto/nacl/sign.Open", 3, 2, "operation", "metadata-contributing", "publicKey", "argument_value"},
		{"golang.org/x/crypto/nacl/auth.Sum", 2, 1, "operation", "metadata-contributing", "keySize", "argument_bit_length"},
		{"golang.org/x/crypto/nacl/auth.Verify", 3, 0, "operation", "metadata-contributing", "mac", "argument_value"},
		{"golang.org/x/crypto/salsa20.XORKeyStream", 4, 2, "operation", "operation-determining", "nonceSize", "argument_bit_length"},
		{"golang.org/x/crypto/openpgp/elgamal.Encrypt", 3, 1, "operation", "metadata-contributing", "publicKey", "argument_value"},
		{"golang.org/x/crypto/openpgp/elgamal.Decrypt", 3, 0, "operation", "metadata-contributing", "privateKey", "argument_value"},
		{"golang.org/x/crypto/openpgp/clearsign.EncodeMulti", 3, 2, "operation", "metadata-contributing", "cryptoConfig", "argument_value"},
		{"golang.org/x/crypto/ssh/knownhosts.HashHostname", 1, 0, "operation", "metadata-contributing", "input", "argument_value"},
		{"golang.org/x/crypto/ssh.NewSignerWithAlgorithms", 2, 1, "factory", "operation-determining", "algorithm", "argument_value"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 || got[0].SourceLibrary != "golang-x-crypto" || got[0].Role != tt.role {
				t.Fatalf("ContractsFor(%q, %d) = %#v, want golang-x-crypto %s", tt.method, tt.arity, got, tt.role)
			}
			if tt.parameterIndex < 0 {
				if len(got[0].Parameters) != 0 {
					t.Fatalf("contract parameters = %#v, want none", got[0].Parameters)
				}
				return
			}
			for _, parameter := range got[0].Parameters {
				if parameter.Index == nil || *parameter.Index != tt.parameterIndex {
					continue
				}
				if parameter.Role != tt.parameterRole || parameter.Contributes == nil || parameter.Contributes.Property != tt.property || parameter.Contributes.Derivation != tt.derivation {
					t.Fatalf("parameter %d = %#v, want role %q contribution %q via %q", tt.parameterIndex, parameter, tt.parameterRole, tt.property, tt.derivation)
				}
				return
			}
			t.Fatalf("contract parameters = %#v, want parameter %d", got[0].Parameters, tt.parameterIndex)
		})
	}

	for _, skipped := range []struct {
		method string
		arity  int
	}{
		{"golang.org/x/crypto/ed25519.GenerateKey", 1},
		{"golang.org/x/crypto/ssh.ParseKnownHosts", 1},
		{"golang.org/x/crypto/cryptobyte.String", 1},
		{"golang.org/x/crypto/openpgp/clearsign.Decode", 1},
	} {
		if got := kb.ContractsFor(skipped.method, skipped.arity); len(got) != 0 {
			t.Fatalf("ContractsFor(%q, %d) = %#v, want unsupported API omitted", skipped.method, skipped.arity, got)
		}
	}
}
