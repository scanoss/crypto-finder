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

// pycryptodomeConsumer is written against the `Crypto` namespace; the
// pycryptodomex run substitutes `Cryptodome`. A synthetic finding sits on
// every factory call; the calls on the object it returns are its supporting
// calls, which is where a contract role surfaces for a consumer.
const pycryptodomeConsumer = `from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256, SHA3_256, HMAC
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss, DSS
from Crypto.Protocol import KDF
from Crypto.Protocol.KDF import PBKDF2, scrypt


def symmetric(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(b"header")
    ct, tag = cipher.encrypt_and_digest(data)
    box = ChaCha20_Poly1305.new(key=key)
    box.encrypt(data)
    return AES.new(key, AES.MODE_GCM)


def public_key(msg_hash, sig):
    key = RSA.generate(2048)
    pub = key.public_key()
    pub.export_key()
    signer = pss.new(key)
    signer.sign(msg_hash)
    ecc = ECC.generate(curve="P-256")
    verifier = DSS.new(ecc, "fips-186-3")
    verifier.verify(msg_hash, sig)
    return RSA.generate(2048)


def hash_and_kdf(password, salt, data):
    h = SHA256.new()
    h.update(data)
    h.hexdigest()
    s3 = SHA3_256.new()
    s3.digest()
    mac = HMAC.new(password, digestmod=SHA256)
    mac.verify(data)
    PBKDF2(password, salt, 32)
    KDF.HKDF(password, 32, salt, SHA256)
    return scrypt(password, salt, 32, 2**14, 8, 1)
`

func TestPycryptodome_SupportingCallsCarryTheirLifecycleRole(t *testing.T) {
	t.Parallel()

	for _, ns := range []string{"Crypto", "Cryptodome"} {
		t.Run(ns, func(t *testing.T) {
			t.Parallel()
			source := strings.ReplaceAll(pycryptodomeConsumer, "Crypto", ns)
			lines := strings.Split(source, "\n")
			anchors := map[int]string{
				10: "Cipher.AES.new", 13: "Cipher.ChaCha20_Poly1305.new", 19: "PublicKey.RSA.generate",
				22: "Signature.pss.new", 25: "Signature.DSS.new", 31: "Hash.SHA256.new",
				34: "Hash.SHA3_256.new", 36: "Hash.HMAC.new",
			}
			assets := make([]entities.CryptographicAsset, 0, len(anchors))
			for line, api := range anchors {
				assets = append(assets, entities.CryptographicAsset{
					StartLine: line, EndLine: line,
					Match:    strings.TrimSpace(lines[line-1]),
					Rules:    []entities.RuleInfo{{ID: "python.pycryptodome.test"}},
					Metadata: map[string]string{"api": ns + "." + api, "assetType": "algorithm"},
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
			if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(source), 0o600); err != nil {
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
			for _, want := range []struct {
				line     int
				symbol   string
				category string
			}{
				{11, "Cipher.AES.AESCipher.update", "config"},
				{12, "Cipher.AES.AESCipher.encrypt_and_digest", "operation"},
				{14, "Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.encrypt", "operation"},
				{20, "PublicKey.RSA.RsaKey.public_key", "factory"},
				{21, "PublicKey.RSA.RsaKey.export_key", "output"},
				{23, "Signature.pss.PSS_SigScheme.sign", "operation"},
				{26, "Signature.DSS.DssSigScheme.verify", "operation"},
				{32, "Hash.SHA256.SHA256Hash.update", "operation"},
				{33, "Hash.SHA256.SHA256Hash.hexdigest", "output"},
				{35, "Hash.SHA3_256.SHA3_256Hash.digest", "output"},
				{37, "Hash.HMAC.HMAC.verify", "operation"},
			} {
				symbol := ns + "." + want.symbol
				category, ok := got[want.line][symbol]
				if !ok {
					t.Errorf("line %d: no supporting call %s; got %v", want.line, symbol, got[want.line])
					continue
				}
				if category != want.category {
					t.Errorf("line %d: %s category = %q, want %q", want.line, symbol, category, want.category)
				}
			}
		})
	}
}
