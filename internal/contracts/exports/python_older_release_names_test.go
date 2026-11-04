// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package exports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/static-engine/callgraph"
	"github.com/scanoss/static-engine/engine"
	"github.com/scanoss/static-engine/entities"
	"github.com/scanoss/static-engine/javaruntime"
)

// buildPythonGraph builds the call graph of one consumer file.
func buildPythonGraph(t *testing.T, source string) (*callgraph.CallGraph, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewParserForEcosystem("python"))
	b.SetTypeResolver(callgraph.NewTypeResolverForEcosystem("python", javaruntime.Config{}))
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "mypkg"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph, dir
}

// Consumers of older releases: each factory call carries a synthetic finding,
// and the call on the object it returns must surface with its contract role.
var olderReleaseConsumers = []struct {
	name    string
	source  string
	anchors map[int]string
	want    map[int][2]string // line -> {supporting call, category}
}{
	{
		name: "pyjwt 1.0 to 1.1, from jwt.api import PyJWT",
		source: `from jwt.api import PyJWT


def token(payload, key):
    codec = PyJWT()
    codec.encode(payload, key)
    codec.decode(payload)
    return codec
`,
		anchors: map[int]string{5: "jwt.api.PyJWT"},
		want: map[int][2]string{
			6: {"jwt.api.PyJWT.encode", "operation"},
			7: {"jwt.api.PyJWT.decode", "operation"},
		},
	},
	{
		name: "pyjwt 1.0 to 1.1, jwt.api.PyJWT",
		source: `from jwt import api


def token(payload, key):
    codec = api.PyJWT()
    codec.encode(payload, key)
    return codec
`,
		anchors: map[int]string{5: "jwt.api.PyJWT"},
		want:    map[int][2]string{6: {"jwt.api.PyJWT.encode", "operation"}},
	},
	{
		name: "certbot 1.0 to 1.2, ocsp.RevocationChecker",
		source: `from certbot._internal import ocsp


def revoked(cert):
    checker = ocsp.RevocationChecker()
    checker.ocsp_revoked(cert)
    return checker
`,
		anchors: map[int]string{5: "certbot._internal.ocsp.RevocationChecker"},
		want:    map[int][2]string{6: {"certbot._internal.ocsp.RevocationChecker.ocsp_revoked", "output"}},
	},
	{
		name: "certbot 5.5 on, from-imported RevocationChecker",
		source: `from certbot._internal.ocsp import RevocationChecker


def revoked(cert_path, chain_path):
    checker = RevocationChecker()
    checker.ocsp_revoked_by_paths(cert_path, chain_path)
    return checker
`,
		anchors: map[int]string{5: "certbot._internal.ocsp.RevocationChecker"},
		want:    map[int][2]string{6: {"certbot._internal.ocsp.RevocationChecker.ocsp_revoked_by_paths", "output"}},
	},
	{
		name: "pycryptodome PyCrypto-compatible signatures",
		source: `from Crypto.Signature import PKCS1_v1_5, PKCS1_PSS


def sign(key, h, sig):
    signer = PKCS1_v1_5.new(key)
    signer.sign(h)
    pss_signer = PKCS1_PSS.new(key)
    pss_signer.verify(h, sig)
    return signer
`,
		anchors: map[int]string{5: "Crypto.Signature.PKCS1_v1_5.new", 7: "Crypto.Signature.PKCS1_PSS.new"},
		want: map[int][2]string{
			6: {"Crypto.Signature.PKCS1_v1_5.PKCS115_SigScheme.sign", "operation"},
			8: {"Crypto.Signature.PKCS1_PSS.PSS_SigScheme.verify", "operation"},
		},
	},
	{
		name: "pycryptodomex PyCrypto-compatible signatures",
		source: `from Cryptodome.Signature import PKCS1_v1_5


def sign(key, h):
    signer = PKCS1_v1_5.new(key)
    signer.sign(h)
    return signer
`,
		anchors: map[int]string{5: "Cryptodome.Signature.PKCS1_v1_5.new"},
		want:    map[int][2]string{6: {"Cryptodome.Signature.PKCS1_v1_5.PKCS115_SigScheme.sign", "operation"}},
	},
	{
		name: "cryptography before 37, signer and its context",
		source: `from cryptography.hazmat.primitives.asymmetric import rsa


def sign(data, pad, alg):
    key = rsa.generate_private_key(65537, 2048)
    ctx = key.signer(pad, alg)
    ctx.update(data)
    return ctx.finalize()
`,
		anchors: map[int]string{5: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key"},
		want: map[int][2]string{
			6: {"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.signer", "factory"},
			7: {"cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext.update", "operation"},
			8: {"cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext.finalize", "operation"},
		},
	},
	{
		// Control: resolved before the older-release names were added.
		name: "python-jose jwk.construct",
		source: `from jose import jwk


def sign(key, msg):
    k = jwk.construct(key)
    k.sign(msg)
    return k
`,
		anchors: map[int]string{5: "jose.jwk.construct"},
		want:    map[int][2]string{6: {"jose.backends.base.Key.sign", "operation"}},
	},
}

func TestPython_OlderReleaseConsumersCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range olderReleaseConsumers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines := strings.Split(tc.source, "\n")
			assets := make([]entities.CryptographicAsset, 0, len(tc.anchors))
			for line, api := range tc.anchors {
				assets = append(assets, entities.CryptographicAsset{
					StartLine: line, EndLine: line,
					Match:    strings.TrimSpace(lines[line-1]),
					Rules:    []entities.RuleInfo{{ID: "python.older-release.test"}},
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
