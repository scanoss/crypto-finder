// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package exports

import (
	"strings"
	"testing"

	"github.com/scanoss/static-engine/engine"
	"github.com/scanoss/static-engine/entities"
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
	{
		name: "stdlib hashlib and hmac",
		source: `import hashlib
import hmac


def use(key, data):
    h = hashlib.new("blake2b", data)
    h.digest()
    x = hashlib.shake_128(data)
    x.hexdigest(32)
    m = hmac.new(key, data, hashlib.sha256)
    m.update(data)
    return m.digest()
`,
		anchors: map[int]string{
			6:  "hashlib.new",
			8:  "hashlib.shake_128",
			10: "hmac.new",
		},
		want: map[int][2]string{
			7:  {"_blake2.blake2b.digest", "output"},
			9:  {"_hashlib.HASHXOF.hexdigest", "output"},
			11: {"hmac.HMAC.update", "operation"},
			12: {"hmac.HMAC.digest", "output"},
		},
	},
	{
		name: "stdlib ssl context and socket",
		source: `import ssl


def connect(sock, host):
    ctx = ssl.create_default_context()
    ctx.set_ciphers("ECDHE+AESGCM")
    ctx.load_cert_chain("client.pem")
    tls = ctx.wrap_socket(sock, server_hostname=host)
    return tls.version()
`,
		anchors: map[int]string{5: "ssl.create_default_context"},
		want: map[int][2]string{
			6: {"ssl.SSLContext.set_ciphers", "config"},
			7: {"ssl.SSLContext.load_cert_chain", "config"},
			8: {"ssl.SSLContext.wrap_socket", "factory"},
			9: {"ssl.SSLSocket.version", "output"},
		},
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
