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

// pythonRuleAPIConsumer calls the pyca/cryptography and PyCryptodome APIs the
// detection rules added for AES-CCM, X25519, Fernet, the CSR builder, DES,
// Triple DES, Salsa20 and RSA-OAEP, in the spellings their docs use. The
// constructors and factories are the findings below, so every later call is a
// supporting call whose category comes from its contract alone.
const pythonRuleAPIConsumer = `import os

from Crypto.Cipher import DES, DES3, PKCS1_OAEP, Salsa20
from Cryptodome.Cipher import DES as XDES
from cryptography import x509
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def pyca(data, aad, peer, name, rsa_key):
    ccm = AESCCM(AESCCM.generate_key(bit_length=128))
    nonce = os.urandom(13)
    ccm.decrypt(nonce, ccm.encrypt(nonce, data, aad), aad)
    private = X25519PrivateKey.generate()
    private.public_key()
    private.exchange(peer)
    token = Fernet(Fernet.generate_key())
    token.decrypt(token.encrypt(data))
    token.decrypt_at_time(token.encrypt_at_time(data, 0), 60, 0)
    rotating = MultiFernet([token])
    rotating.decrypt(rotating.encrypt(data))
    rotating.rotate(data)
    csr = x509.CertificateSigningRequestBuilder()
    csr = csr.subject_name(name)
    csr.sign(rsa_key, hashes.SHA256())


def pycryptodome(key8, key24, key32, nonce, rsa_key, data):
    des = DES.new(key8, DES.MODE_CBC)
    des.decrypt(des.encrypt(data))
    tdes = DES3.new(key24, DES3.MODE_CBC)
    tdes.decrypt(tdes.encrypt(data))
    stream = Salsa20.new(key=key32, nonce=nonce)
    stream.decrypt(stream.encrypt(data))
    oaep = PKCS1_OAEP.new(rsa_key)
    oaep.decrypt(oaep.encrypt(data))
    xdes = XDES.new(key8, XDES.MODE_ECB)
    xdes.encrypt(data)
`

func TestPythonRuleAPIsResolveToTheirContracts(t *testing.T) {
	t.Parallel()

	var assets []entities.CryptographicAsset
	for i, line := range strings.Split(pythonRuleAPIConsumer, "\n") {
		for _, ctor := range []string{
			"= AESCCM(", "= X25519PrivateKey.generate(", "= Fernet(", "= MultiFernet(",
			"= x509.CertificateSigningRequestBuilder(", "= DES.new(", "= DES3.new(", "= Salsa20.new(",
			"= PKCS1_OAEP.new(", "= XDES.new(",
		} {
			if strings.Contains(line, ctor) {
				assets = append(assets, entities.CryptographicAsset{
					StartLine: i + 1, EndLine: i + 1, Match: strings.TrimSpace(line),
					Rules:    []entities.RuleInfo{{ID: "python.synth"}},
					Metadata: map[string]string{"api": "synth", "assetType": "algorithm"},
				})
			}
		}
	}
	report := &entities.InterimReport{
		Tool:     entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules:    entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{FilePath: "app.py", Language: "python", CryptographicAssets: assets}},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pythonRuleAPIConsumer), 0o600); err != nil {
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

	got := map[string]string{}
	for _, s := range export.SupportingCalls {
		if s.SupportingCall != nil {
			got[s.SupportingCall.FunctionName] = s.Category
		}
	}
	const aead = "cryptography.hazmat.primitives.ciphers.aead.AESCCM."
	const x25519 = "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey."
	for symbol, category := range map[string]string{
		aead + "encrypt":                                                  "operation",
		aead + "decrypt":                                                  "operation",
		x25519 + "public_key":                                             "factory",
		x25519 + "exchange":                                               "operation",
		"cryptography.fernet.Fernet.encrypt":                              "operation",
		"cryptography.fernet.Fernet.decrypt":                              "operation",
		"cryptography.fernet.Fernet.encrypt_at_time":                      "operation",
		"cryptography.fernet.Fernet.decrypt_at_time":                      "operation",
		"cryptography.fernet.MultiFernet.encrypt":                         "operation",
		"cryptography.fernet.MultiFernet.decrypt":                         "operation",
		"cryptography.fernet.MultiFernet.rotate":                          "operation",
		"cryptography.x509.CertificateSigningRequestBuilder.subject_name": "config",
		"cryptography.x509.CertificateSigningRequestBuilder.sign":         "operation",
		"Crypto.Cipher.DES.DESCipher.encrypt":                             "operation",
		"Crypto.Cipher.DES.DESCipher.decrypt":                             "operation",
		"Crypto.Cipher.DES3.DES3Cipher.encrypt":                           "operation",
		"Crypto.Cipher.DES3.DES3Cipher.decrypt":                           "operation",
		"Crypto.Cipher.Salsa20.Salsa20Cipher.encrypt":                     "operation",
		"Crypto.Cipher.Salsa20.Salsa20Cipher.decrypt":                     "operation",
		"Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.encrypt":               "operation",
		"Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.decrypt":               "operation",
		"Cryptodome.Cipher.DES.DESCipher.encrypt":                         "operation",
	} {
		have, ok := got[symbol]
		if !ok {
			t.Errorf("no supporting call %s; got %v", symbol, got)
			continue
		}
		if have != category {
			t.Errorf("%s: category = %q, want %q", symbol, have, category)
		}
	}
}
