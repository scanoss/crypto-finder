// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// Consumers of the PyCrypto-compatible pycryptodome modules and the python-jose
// key classes: the call on each factory's result must carry its contract role.
var coverageConsumers = []struct {
	name    string
	source  string
	anchors map[int]string
	want    map[int][2]string // line -> {supporting call, category}
}{
	{
		name: "pycryptodome Cipher.PKCS1_v1_5, Hash.SHA, ARC4 and DSA",
		source: `from Crypto.Cipher import PKCS1_v1_5, ARC4
from Crypto.Hash import SHA
from Crypto.PublicKey import DSA


def use(key, data):
    cipher = PKCS1_v1_5.new(key)
    cipher.encrypt(data)
    h = SHA.new()
    h.update(data)
    stream = ARC4.new(key)
    stream.encrypt(data)
    dsa = DSA.generate(2048)
    return dsa.export_key()
`,
		anchors: map[int]string{
			7:  "Crypto.Cipher.PKCS1_v1_5.new",
			9:  "Crypto.Hash.SHA.new",
			11: "Crypto.Cipher.ARC4.new",
			13: "Crypto.PublicKey.DSA.generate",
		},
		want: map[int][2]string{
			8:  {"Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher.encrypt", "operation"},
			10: {"Crypto.Hash.SHA1.SHA1Hash.update", "operation"},
			12: {"Crypto.Cipher.ARC4.ARC4Cipher.encrypt", "operation"},
			14: {"Crypto.PublicKey.DSA.DsaKey.export_key", "output"},
		},
	},
	{
		name: "python-jose from-imported HMACKey",
		source: `from jose.jwk import HMACKey


def sign(secret, msg):
    key = HMACKey(secret, "HS256")
    key.sign(msg)
    return key
`,
		anchors: map[int]string{5: "jose.jwk.HMACKey"},
		want:    map[int][2]string{6: {"jose.backends.HMACKey.sign", "operation"}},
	},
	{
		name: "python-jose jwk.HMACKey",
		source: `from jose import jwk


def sign(secret, msg):
    key = jwk.HMACKey(secret, "HS256")
    key.sign(msg)
    return key
`,
		anchors: map[int]string{5: "jose.jwk.HMACKey"},
		want:    map[int][2]string{6: {"jose.backends.HMACKey.sign", "operation"}},
	},
}

func TestPython_CoverageConsumersCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range coverageConsumers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines := strings.Split(tc.source, "\n")
			assets := make([]entities.CryptographicAsset, 0, len(tc.anchors))
			for line, api := range tc.anchors {
				assets = append(assets, entities.CryptographicAsset{
					StartLine: line, EndLine: line,
					Match:    strings.TrimSpace(lines[line-1]),
					Rules:    []entities.RuleInfo{{ID: "python.coverage.test"}},
					Metadata: map[string]string{"api": api, "assetType": "algorithm"},
				})
			}
			report := &entities.InterimReport{
				Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
				Rules: entities.RulesInfo{Version: "v-test"},
				Findings: []entities.Finding{{
					FilePath: "app.py", Language: "python", CryptographicAssets: assets,
				}},
			}
			graph, dir := buildPythonGraph(t, tc.source)
			engine.EnsureFindingSources(report)
			engine.AssignFindingIDs(report)
			export := buildGraphFragmentExport(&engine.DepScanResult{
				Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "mypkg", Ecosystem: "python",
			})
			got := map[int]map[string]string{}
			for _, s := range export.SupportingCalls {
				if s.SupportingCall == nil {
					continue
				}
				if got[s.StartLine] == nil {
					got[s.StartLine] = map[string]string{}
				}
				got[s.StartLine][s.SupportingCall.FunctionName] = s.Category
			}
			for line, w := range tc.want {
				category, ok := got[line][w[0]]
				if !ok {
					t.Errorf("line %d: no supporting call %s; got %v", line, w[0], got[line])
					continue
				}
				if category != w[1] {
					t.Errorf("line %d: %s category = %q, want %q", line, w[0], category, w[1])
				}
			}
		})
	}
}

// coverageKeys lists every name this coverage adds as module:rest#arity.
var coverageKeys = []string{
	"Crypto.Cipher.ARC2:ARC2Cipher.decrypt#1",
	"Crypto.Cipher.ARC2:ARC2Cipher.encrypt#1",
	"Crypto.Cipher.ARC2:new#2",
	"Crypto.Cipher.ARC4:ARC4Cipher.decrypt#1",
	"Crypto.Cipher.ARC4:ARC4Cipher.encrypt#1",
	"Crypto.Cipher.ARC4:new#1",
	"Crypto.Cipher.Blowfish:BlowfishCipher.decrypt#1",
	"Crypto.Cipher.Blowfish:BlowfishCipher.encrypt#1",
	"Crypto.Cipher.Blowfish:new#2",
	"Crypto.Cipher.CAST:CASTCipher.decrypt#1",
	"Crypto.Cipher.CAST:CASTCipher.encrypt#1",
	"Crypto.Cipher.CAST:new#2",
	"Crypto.Cipher.PKCS1_v1_5:PKCS115_Cipher.decrypt#2",
	"Crypto.Cipher.PKCS1_v1_5:PKCS115_Cipher.decrypt#3",
	"Crypto.Cipher.PKCS1_v1_5:PKCS115_Cipher.encrypt#1",
	"Crypto.Cipher.PKCS1_v1_5:new#1",
	"Crypto.Hash.MD5:MD5Hash.copy#0",
	"Crypto.Hash.MD5:MD5Hash.digest#0",
	"Crypto.Hash.MD5:MD5Hash.hexdigest#0",
	"Crypto.Hash.MD5:MD5Hash.update#1",
	"Crypto.Hash.MD5:new#0",
	"Crypto.Hash.RIPEMD160:RIPEMD160Hash.copy#0",
	"Crypto.Hash.RIPEMD160:RIPEMD160Hash.digest#0",
	"Crypto.Hash.RIPEMD160:RIPEMD160Hash.hexdigest#0",
	"Crypto.Hash.RIPEMD160:RIPEMD160Hash.update#1",
	"Crypto.Hash.RIPEMD160:new#0",
	"Crypto.Hash.RIPEMD:new#0",
	"Crypto.Hash.SHA1:SHA1Hash.copy#0",
	"Crypto.Hash.SHA1:SHA1Hash.digest#0",
	"Crypto.Hash.SHA1:SHA1Hash.hexdigest#0",
	"Crypto.Hash.SHA1:SHA1Hash.update#1",
	"Crypto.Hash.SHA1:new#0",
	"Crypto.Hash.SHA:new#0",
	"Crypto.PublicKey.DSA:DsaKey.exportKey#0",
	"Crypto.PublicKey.DSA:DsaKey.export_key#0",
	"Crypto.PublicKey.DSA:DsaKey.public_key#0",
	"Crypto.PublicKey.DSA:DsaKey.publickey#0",
	"Crypto.PublicKey.DSA:construct#1",
	"Crypto.PublicKey.DSA:generate#1",
	"Crypto.PublicKey.DSA:importKey#1",
	"Crypto.PublicKey.DSA:import_key#1",
	"Crypto.PublicKey.ElGamal:ElGamalKey.publickey#0",
	"Crypto.PublicKey.ElGamal:construct#1",
	"Crypto.PublicKey.ElGamal:generate#2",
	"Cryptodome.Cipher.ARC2:ARC2Cipher.decrypt#1",
	"Cryptodome.Cipher.ARC2:ARC2Cipher.encrypt#1",
	"Cryptodome.Cipher.ARC2:new#2",
	"Cryptodome.Cipher.ARC4:ARC4Cipher.decrypt#1",
	"Cryptodome.Cipher.ARC4:ARC4Cipher.encrypt#1",
	"Cryptodome.Cipher.ARC4:new#1",
	"Cryptodome.Cipher.Blowfish:BlowfishCipher.decrypt#1",
	"Cryptodome.Cipher.Blowfish:BlowfishCipher.encrypt#1",
	"Cryptodome.Cipher.Blowfish:new#2",
	"Cryptodome.Cipher.CAST:CASTCipher.decrypt#1",
	"Cryptodome.Cipher.CAST:CASTCipher.encrypt#1",
	"Cryptodome.Cipher.CAST:new#2",
	"Cryptodome.Cipher.PKCS1_v1_5:PKCS115_Cipher.decrypt#2",
	"Cryptodome.Cipher.PKCS1_v1_5:PKCS115_Cipher.decrypt#3",
	"Cryptodome.Cipher.PKCS1_v1_5:PKCS115_Cipher.encrypt#1",
	"Cryptodome.Cipher.PKCS1_v1_5:new#1",
	"Cryptodome.Hash.MD5:MD5Hash.copy#0",
	"Cryptodome.Hash.MD5:MD5Hash.digest#0",
	"Cryptodome.Hash.MD5:MD5Hash.hexdigest#0",
	"Cryptodome.Hash.MD5:MD5Hash.update#1",
	"Cryptodome.Hash.MD5:new#0",
	"Cryptodome.Hash.RIPEMD160:RIPEMD160Hash.copy#0",
	"Cryptodome.Hash.RIPEMD160:RIPEMD160Hash.digest#0",
	"Cryptodome.Hash.RIPEMD160:RIPEMD160Hash.hexdigest#0",
	"Cryptodome.Hash.RIPEMD160:RIPEMD160Hash.update#1",
	"Cryptodome.Hash.RIPEMD160:new#0",
	"Cryptodome.Hash.RIPEMD:new#0",
	"Cryptodome.Hash.SHA1:SHA1Hash.copy#0",
	"Cryptodome.Hash.SHA1:SHA1Hash.digest#0",
	"Cryptodome.Hash.SHA1:SHA1Hash.hexdigest#0",
	"Cryptodome.Hash.SHA1:SHA1Hash.update#1",
	"Cryptodome.Hash.SHA1:new#0",
	"Cryptodome.Hash.SHA:new#0",
	"Cryptodome.PublicKey.DSA:DsaKey.exportKey#0",
	"Cryptodome.PublicKey.DSA:DsaKey.export_key#0",
	"Cryptodome.PublicKey.DSA:DsaKey.public_key#0",
	"Cryptodome.PublicKey.DSA:DsaKey.publickey#0",
	"Cryptodome.PublicKey.DSA:construct#1",
	"Cryptodome.PublicKey.DSA:generate#1",
	"Cryptodome.PublicKey.DSA:importKey#1",
	"Cryptodome.PublicKey.DSA:import_key#1",
	"Cryptodome.PublicKey.ElGamal:ElGamalKey.publickey#0",
	"Cryptodome.PublicKey.ElGamal:construct#1",
	"Cryptodome.PublicKey.ElGamal:generate#2",
	"jose.backends:AESKey.decrypt#1",
	"jose.backends:AESKey.encrypt#1",
	"jose.backends:AESKey.to_dict#0",
	"jose.backends:AESKey.unwrap_key#1",
	"jose.backends:AESKey.wrap_key#1",
	"jose.backends:ECKey.public_key#0",
	"jose.backends:ECKey.sign#1",
	"jose.backends:ECKey.to_dict#0",
	"jose.backends:ECKey.to_pem#0",
	"jose.backends:ECKey.verify#2",
	"jose.backends:HMACKey.sign#1",
	"jose.backends:HMACKey.to_dict#0",
	"jose.backends:HMACKey.verify#2",
	"jose.backends:RSAKey.public_key#0",
	"jose.backends:RSAKey.sign#1",
	"jose.backends:RSAKey.to_dict#0",
	"jose.backends:RSAKey.to_pem#0",
	"jose.backends:RSAKey.unwrap_key#1",
	"jose.backends:RSAKey.verify#2",
	"jose.backends:RSAKey.wrap_key#1",
	"jose.jwk:AESKey.<init>#2",
	"jose.jwk:ECKey.<init>#2",
	"jose.jwk:HMACKey.<init>#2",
	"jose.jwk:RSAKey.<init>#2",
}

func TestPython_EveryCoverageNameResolvesToItsContract(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	for _, key := range coverageKeys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			source, want := olderReleaseConsumer(key)
			const line = 5
			graph, _ := buildPythonGraph(t, source)
			var calls []string
			for _, fn := range graph.Functions {
				for _, c := range fn.Calls {
					if c.Line != line {
						continue
					}
					callee := strings.Join(nonEmpty(c.Callee.Package, c.Callee.Type, c.Callee.Name), ".")
					calls = append(calls, fmt.Sprintf("%s#%d", callee, len(c.Arguments)))
					if callee == want && len(kb.ContractsFor(callee, len(c.Arguments))) > 0 {
						return
					}
				}
			}
			t.Errorf("%s: line %d resolved to %v\n%s", key, line, calls, source)
		})
	}
}
