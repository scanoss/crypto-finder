// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

const pycaPrimitives = "cryptography.hazmat.primitives."

type pycaSupportingCall struct {
	line     int
	symbol   string
	category string
}

// pycaTracers are child-sized consumers, one per API area. A synthetic finding
// sits on each anchor line; the calls on the objects it produces are its
// supporting calls, where a contract role surfaces for a consumer.
var pycaTracers = []struct {
	name    string
	source  string
	anchors []int
	want    []pycaSupportingCall
}{
	{
		name: "symmetric and KDF",
		source: `from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def run(key, iv, data, salt):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    h = hashes.Hash(hashes.SHA256())
    h.update(ct)
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.verify(ct)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return kdf.derive(key)
`,
		anchors: []int{7, 9, 11, 13, 15},
		want: []pycaSupportingCall{
			{8, pycaPrimitives + "padding.PaddingContext.update", "operation"},
			{10, pycaPrimitives + "ciphers.CipherContext.update", "operation"},
			{10, pycaPrimitives + "ciphers.CipherContext.finalize", "operation"},
			{12, pycaPrimitives + "hashes.Hash.update", "operation"},
			{14, pycaPrimitives + "hmac.HMAC.verify", "operation"},
			{16, pycaPrimitives + "kdf.pbkdf2.PBKDF2HMAC.derive", "operation"},
		},
	},
	{
		name: "asymmetric and signature",
		source: `from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding


def run(data, pem):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    pub.verify(data, data, padding.PKCS1v15(), hashes.SHA256())
    ed = ed25519.Ed25519PrivateKey.generate()
    ed.sign(data)
    ek = ec.generate_private_key(ec.SECP256R1())
    ek.exchange(ec.ECDH(), pub)
    loaded = serialization.load_pem_private_key(pem, password=None)
    return loaded.sign(data, padding.PKCS1v15(), hashes.SHA256())
`,
		anchors: []int{6, 9, 11, 13},
		want: []pycaSupportingCall{
			{7, pycaPrimitives + "asymmetric.rsa.RSAPrivateKey.public_key", "factory"},
			{8, pycaPrimitives + "asymmetric.rsa.RSAPublicKey.verify", "operation"},
			{10, pycaPrimitives + "asymmetric.ed25519.Ed25519PrivateKey.sign", "operation"},
			{12, pycaPrimitives + "asymmetric.ec.EllipticCurvePrivateKey.exchange", "operation"},
			{14, pycaPrimitives + "asymmetric.types.PrivateKeyTypes.sign", "operation"},
		},
	},
	{
		name: "X.509",
		source: `from cryptography import x509
from cryptography.hazmat.primitives import hashes


def run(key, name, pem):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    cert = builder.sign(key, hashes.SHA256())
    loaded = x509.load_pem_x509_certificate(pem)
    loaded.fingerprint(hashes.SHA256())
    return loaded.public_bytes(None)
`,
		anchors: []int{6, 9},
		want: []pycaSupportingCall{
			{7, "cryptography.x509.CertificateBuilder.subject_name", "config"},
			{8, "cryptography.x509.CertificateBuilder.sign", "operation"},
			{10, "cryptography.x509.Certificate.fingerprint", "operation"},
			{11, "cryptography.x509.Certificate.public_bytes", "output"},
		},
	},
}

func TestPycaCryptography_SupportingCallsCarryTheirLifecycleRole(t *testing.T) {
	t.Parallel()

	for _, tracer := range pycaTracers {
		t.Run(tracer.name, func(t *testing.T) {
			t.Parallel()
			lines := strings.Split(tracer.source, "\n")
			assets := make([]entities.CryptographicAsset, 0, len(tracer.anchors))
			for _, line := range tracer.anchors {
				assets = append(assets, entities.CryptographicAsset{
					StartLine: line, EndLine: line,
					Match:    strings.TrimSpace(lines[line-1]),
					Rules:    []entities.RuleInfo{{ID: "python.cryptography.test"}},
					Metadata: map[string]string{"assetType": "algorithm"},
				})
			}
			report := &entities.InterimReport{
				Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
				Rules: entities.RulesInfo{Version: "v-test"},
				Findings: []entities.Finding{{
					FilePath: "app.py", Language: "python", CryptographicAssets: assets,
				}},
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(tracer.source), 0o600); err != nil {
				t.Fatal(err)
			}
			b := callgraph.NewBuilderForEcosystem("python", callgraph.NewParserForEcosystem("python"))
			b.SetTypeResolver(callgraph.NewTypeResolverForEcosystem("python", javaruntime.Config{}))
			graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "mypkg"}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
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
			for _, want := range tracer.want {
				category, ok := got[want.line][want.symbol]
				if !ok {
					t.Errorf("line %d: no supporting call %s; got %v", want.line, want.symbol, got[want.line])
					continue
				}
				if category != want.category {
					t.Errorf("line %d: %s category = %q, want %q", want.line, want.symbol, category, want.category)
				}
			}
		})
	}
}
