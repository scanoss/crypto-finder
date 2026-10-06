// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// nodeOptionsHeader gives every case below the three import spellings the
// rules recognize. The call under test is always on line 5.
const nodeOptionsHeader = `const crypto = require('crypto');
const nodeCrypto = require('node:crypto');
const { generateKeyPairSync, generateKeyPair, generateKeySync } = require('node:crypto');

`

// TestNodeOptionsKeyLength_ExactBitsThroughSupportingCallIDs pins that a Node
// key-generation call states its size in an options-object property chosen by
// the key type, and that the size is reachable through the finding graph's
// supporting_call_ids, live and stitched.
func TestNodeOptionsKeyLength_ExactBitsThroughSupportingCallIDs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		call     string
		wantFunc string
		wantBits int
	}{
		{"rsa", `crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });`, "crypto.generateKeyPairSync", 3072},
		{"rsa double quotes and quoted key", `crypto.generateKeyPairSync("rsa", { "modulusLength": 1024 });`, "crypto.generateKeyPairSync", 1024},
		{"rsa-pss", `nodeCrypto.generateKeyPairSync('rsa-pss', { modulusLength: 4096, hashAlgorithm: 'sha256' });`, "node:crypto.generateKeyPairSync", 4096},
		{"dsa reads the modulus, not the divisor", `crypto.generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 });`, "crypto.generateKeyPairSync", 2048},
		{"dh reads primeLength", `crypto.generateKeyPairSync('dh', { primeLength: 2048 });`, "crypto.generateKeyPairSync", 2048},
		{"ec prime256v1", `crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });`, "crypto.generateKeyPairSync", 256},
		{"ec secp384r1", `crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });`, "crypto.generateKeyPairSync", 384},
		{"ec NIST name", `crypto.generateKeyPairSync('ec', { namedCurve: 'P-521' });`, "crypto.generateKeyPairSync", 521},
		{"ec secp256k1", `crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });`, "crypto.generateKeyPairSync", 256},
		{"destructured name", `generateKeyPairSync('rsa', { modulusLength: 2560, publicExponent: 65537 });`, "node:crypto.generateKeyPairSync", 2560},
		{"async form with a named callback", `generateKeyPair('rsa', { modulusLength: 3584 }, onKey);`, "node:crypto.generateKeyPair", 3584},
		{"async ec with a named callback", `crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, onKey);`, "crypto.generateKeyPair", 256},
		{"aes 192", `crypto.generateKeySync('aes', { length: 192 });`, "crypto.generateKeySync", 192},
		{"hmac multiple of 8", `crypto.generateKeySync('hmac', { length: 8 });`, "crypto.generateKeySync", 8},
		{"brainpool curve spelling", `crypto.generateKeyPairSync('ec', { namedCurve: 'brainpoolP256r1' });`, "crypto.generateKeyPairSync", 256},
		{"largest modulusLength", `crypto.generateKeyPairSync('rsa', { modulusLength: 4294967295 });`, "crypto.generateKeyPairSync", 4294967295},
		{"aes secret key", `crypto.generateKeySync('aes', { length: 256 });`, "crypto.generateKeySync", 256},
		{"hmac secret key", `generateKeySync('hmac', { length: 512 });`, "node:crypto.generateKeySync", 512},
		{"aes secret key with a named callback", `crypto.generateKey('aes', { length: 128 }, onKey);`, "crypto.generateKey", 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exports := nodeOptionsExports(t, tc.call)
			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, tc.wantFunc),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, tc.wantFunc),
			} {
				if got == nil || got.Bits == nil || *got.Bits != tc.wantBits {
					t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, tc.wantBits)
				}
				if got.Provenance != keyLengthProvenanceConstant || got.SourceCall.ParameterIndex != 1 || got.SourceCall.Line != 5 {
					t.Fatalf("%s: provenance/source = %#v, want constant at parameter 1 line 5", name, got)
				}
			}
			assertNoTerminalKeyLength(t, exports.live, exports.findingID)
		})
	}
}

// TestNodeOptionsKeyLength_UnresolvableStaysAbsent pins that a size the text
// does not state outright reports no bits: absent beats wrong. Every case here
// reads a plausible number if the reader guesses.
func TestNodeOptionsKeyLength_UnresolvableStaysAbsent(t *testing.T) {
	for _, tc := range []struct {
		name string
		call string
	}{
		{"key type is a variable", `crypto.generateKeyPairSync(process.env.KEY_TYPE, { modulusLength: 2048 });`},
		{"size is a variable", `crypto.generateKeyPairSync('rsa', { modulusLength: bits });`},
		{"size is an expression", `crypto.generateKeyPairSync('rsa', { modulusLength: 1024 * 2 });`},
		{"size is a hex literal", `crypto.generateKeyPairSync('rsa', { modulusLength: 0x800 });`},
		{"size is a string", `crypto.generateKeyPairSync('rsa', { modulusLength: '2048' });`},
		{"options is a variable", `crypto.generateKeyPairSync('rsa', sharedOptions);`},
		{"options is a spread", `crypto.generateKeyPairSync('rsa', { ...sharedOptions });`},
		{"spread after the size", `crypto.generateKeyPairSync('rsa', { modulusLength: 2048, ...sharedOptions });`},
		{"computed key", `crypto.generateKeyPairSync('rsa', { ['modulus' + 'Length']: 2048 });`},
		{"shorthand size", `crypto.generateKeyPairSync('rsa', { modulusLength });`},
		{"size given twice", `crypto.generateKeyPairSync('rsa', { modulusLength: 2048, modulusLength: 4096 });`},
		{"no options", `crypto.generateKeyPairSync('rsa');`},
		{"empty options", `crypto.generateKeyPairSync('rsa', {});`},
		{"rsa property on an ec key", `crypto.generateKeyPairSync('ec', { modulusLength: 2048 });`},
		{"ec property on an rsa key", `crypto.generateKeyPairSync('rsa', { namedCurve: 'P-256' });`},
		{"curve is a variable", `crypto.generateKeyPairSync('ec', { namedCurve: process.env.CURVE });`},
		{"curve the table does not list", `crypto.generateKeyPairSync('ec', { namedCurve: 'not-a-curve' });`},
		{"dh named group", `crypto.generateKeyPairSync('dh', { groupName: 'modp14' });`},
		{"key type without a size", `crypto.generateKeyPairSync('ed25519', {});`},
		{"secret key spread", `crypto.generateKeySync('aes', { ...sharedOptions });`},
		{"secret key length variable", `crypto.generateKeySync('hmac', { length: bits });`},
		{"secret key type variable", `crypto.generateKeySync(keyType, { length: 256 });`},
		{"escaped duplicate key", `crypto.generateKeyPairSync('rsa', { modulusLength: 2048, "modulus\u004Cength": 4096 });`},
		{"aes length Node rejects", `crypto.generateKeySync('aes', { length: 100 });`},
		{"aes length 512", `crypto.generateKeySync('aes', { length: 512 });`},
		{"hmac length not a multiple of 8", `crypto.generateKeySync('hmac', { length: 12 });`},
		{"hmac length zero", `crypto.generateKeySync('hmac', { length: 0 });`},
		{"hmac length above 2^31-1", `crypto.generateKeySync('hmac', { length: 2147483656 });`},
		{"modulusLength above uint32", `crypto.generateKeyPairSync('rsa', { modulusLength: 4294967296 });`},
		{"modulusLength zero", `crypto.generateKeyPairSync('rsa', { modulusLength: 0 });`},
		{"primeLength above uint32", `crypto.generateKeyPairSync('dh', { primeLength: 99999999999 });`},
		{"curve with surrounding spaces", `crypto.generateKeyPairSync('ec', { namedCurve: ' P-256 ' });`},
		{"NIST curve in lower case", `crypto.generateKeyPairSync('ec', { namedCurve: 'p-256' });`},
		{"SEC curve in upper case", `crypto.generateKeyPairSync('ec', { namedCurve: 'PRIME256V1' });`},
		{"ssh curve alias", `crypto.generateKeyPairSync('ec', { namedCurve: 'nistp256' });`},
		{"async options variable", `crypto.generateKeyPair('rsa', sharedOptions, onKey);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exports := nodeOptionsExports(t, tc.call)
			fn := strings.SplitN(tc.call, "(", 2)[0]
			switch {
			case strings.HasPrefix(fn, "crypto."):
			case strings.HasPrefix(fn, "nodeCrypto."):
				fn = "node:crypto." + strings.TrimPrefix(fn, "nodeCrypto.")
			default:
				fn = "node:crypto." + fn
			}
			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, fn),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, fn),
			} {
				if got != nil && got.Bits != nil {
					t.Fatalf("%s: resolved_key_length bits = %d, want none for %s", name, *got.Bits, tc.call)
				}
			}
		})
	}
}

func nodeOptionsExports(t *testing.T, call string) terminalExportResult {
	t.Helper()
	fn := strings.SplitN(call, "(", 2)[0]
	api := "crypto." + fn[strings.LastIndex(fn, ".")+1:]
	return terminalExports(t, "node", "k.js", nodeOptionsHeader+call+"\n", 5, strings.TrimSuffix(call, ";"), api, "")
}

// TestNodeOptionsKeyLength_ImportForms pins that ES module and TypeScript
// imports of the module, whole or destructured, read the same size as require.
func TestNodeOptionsKeyLength_ImportForms(t *testing.T) {
	for _, tc := range []struct {
		name, file, header, call, wantFunc string
	}{
		{"default import", "k.js", "import crypto from 'crypto';\n\n\n\n", `crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });`, "crypto.generateKeyPairSync"},
		{"namespace import of node:crypto", "k.ts", "import * as crypto from 'node:crypto';\n\n\n\n", `crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });`, "node:crypto.generateKeyPairSync"},
		{"named import", "k.ts", "import { generateKeyPairSync } from 'crypto';\n\n\n\n", `generateKeyPairSync('dh', { primeLength: 4096 });`, "crypto.generateKeyPairSync"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := map[string]int{"rsa": 3072, "secp384r1": 384, "dh": 4096}
			var bits int
			for key, v := range want {
				if strings.Contains(tc.call, key) {
					bits = v
				}
			}
			fn := strings.SplitN(tc.call, "(", 2)[0]
			api := "crypto." + fn[strings.LastIndex(fn, ".")+1:]
			exports := terminalExports(t, "node", tc.file, tc.header+tc.call+"\n", 5, strings.TrimSuffix(tc.call, ";"), api, "")
			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, tc.wantFunc),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, tc.wantFunc),
			} {
				if got == nil || got.Bits == nil || *got.Bits != bits {
					t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, bits)
				}
			}
		})
	}
}

// TestNodeOptionsKeyLength_ContributionExportsArgumentProperty pins that a
// Node role's parameter_roles entry names the options property it reads, on
// both the live and the graph-fragment shapes.
func TestNodeOptionsKeyLength_ContributionExportsArgumentProperty(t *testing.T) {
	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatal(err)
	}
	roles := parameterRolesFromContracts(kb.Contracts["crypto.generateKeyPairSync#2"][:1])
	if len(roles) == 0 || roles[0].Contributes == nil || roles[0].Contributes.ArgumentProperty == "" {
		t.Fatalf("live parameter role = %#v, want a contribution naming its argument property", roles)
	}
	want := roles[0].Contributes.ArgumentProperty
	if got := toGraphFragmentParameterRoles(roles)[0].Contributes.ArgumentProperty; got != want {
		t.Fatalf("fragment ArgumentProperty = %q, want %q", got, want)
	}
	encoded, err := json.Marshal(roles)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"argument_property":"`+want+`"`) {
		t.Fatalf("live parameter_roles JSON = %s, want argument_property %s", encoded, want)
	}
}
