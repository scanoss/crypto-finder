// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// m2cryptoConsumer calls each of the 31 M2Crypto functions the crypto_rules
// python/m2crypto rules name as their api and no contract covered, on a
// receiver built by a contracted constructor or loader, the way the M2Crypto
// docs write them. Only the constructors are findings below, so every later
// call is a supporting call whose category comes from its contract alone.
const m2cryptoConsumer = `from M2Crypto import BIO, DH, DSA, EC, EVP, RSA, SMIME, SSL, X509, m2urllib


def keys(data, sig, digest):
    rsa = RSA.load_key("rsa.pem")
    rsa.verify(data, sig, "sha256")
    rsa.verify_rsassa_pss(data, sig, "sha256", 32)
    dsa = DSA.load_key("dsa.pem")
    dsa.gen_key()
    dsa.verify(digest, sig, sig)
    ec = EC.load_key("ec.pem")
    ec.gen_key()
    ec.verify_dsa(digest, sig, sig)
    pub = EC.load_pub_key("ecpub.pem")
    pub.get_key()
    dh = DH.gen_params(2048, 2)
    dh.gen_key()


def evp(data, sig, key, rsa, ec):
    md = EVP.MessageDigest("sha256")
    md.update(data)
    mac = EVP.HMAC(key, "sha256")
    mac.update(data)
    pkey = EVP.PKey()
    pkey.assign_rsa(rsa)
    pkey.assign_ec(ec)
    pkey.sign_update(data)
    pkey.verify_final(sig)
    pkey.digest_verify(sig, data)
    pkey.get_ec()
    stream = BIO.CipherStream(BIO.MemoryBuffer())
    stream.set_cipher("aes_128_cbc", key, key, 1)


def certs(pkey, pkcs7, data_bio):
    cert = X509.X509()
    cert.sign(pkey, "sha256")
    cert.verify(pkey)
    req = X509.Request()
    req.sign(pkey, "sha256")
    req.verify(pkey)
    crl = X509.load_crl("crl.pem")
    crl.verify(pkey)
    store_ctx = X509.X509_Store_Context()
    store_ctx.verify_cert()
    s = SMIME.SMIME()
    s.load_key("key.pem", "cert.pem")
    s.encrypt(data_bio)
    s.decrypt(pkcs7)


def tls(opener, url):
    ctx = SSL.Context("tls")
    ctx.load_cert("cert.pem", "key.pem")
    ctx.load_cert_chain("chain.pem", "key.pem")
    ctx.load_verify_locations("ca.pem")
    ctx.set_client_CA_list_from_file("ca.pem")
    resp = m2urllib.open_https(opener, url, None, ctx)
    return resp
`

func m2cryptoFinding(line int, match string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: line,
		EndLine:   line,
		Match:     match,
		Rules:     []entities.RuleInfo{{ID: "python.m2crypto.synth"}},
		Metadata:  map[string]string{"api": "M2Crypto.synth", "assetType": "algorithm", "library": "M2Crypto"},
	}
}

func TestPythonM2Crypto_RuleAPIsResolveToTheirContracts(t *testing.T) {
	t.Parallel()

	lines := strings.Split(m2cryptoConsumer, "\n")
	var assets []entities.CryptographicAsset
	for i, line := range lines {
		for _, ctor := range []string{"RSA.load_key(", "DSA.load_key(", "EC.load_key(", "EC.load_pub_key(", "DH.gen_params(",
			"EVP.MessageDigest(", "EVP.HMAC(", "EVP.PKey(", "BIO.CipherStream(", "X509.X509(", "X509.Request(",
			"X509.load_crl(", "X509.X509_Store_Context(", "SMIME.SMIME(", "SSL.Context("} {
			if strings.Contains(line, "= "+ctor) {
				assets = append(assets, m2cryptoFinding(i+1, strings.TrimSpace(line)))
			}
		}
	}
	report := &entities.InterimReport{
		Tool:     entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules:    entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{FilePath: "app.py", Language: "python", CryptographicAssets: assets}},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(m2cryptoConsumer), 0o600); err != nil {
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

	// Hand-written from the 0.40.0 and 0.48.0 sources, not read from the YAML.
	for symbol, category := range map[string]string{
		"M2Crypto.RSA.RSA.verify":                                   "operation",
		"M2Crypto.RSA.RSA.verify_rsassa_pss":                        "operation",
		"M2Crypto.DSA.DSA.gen_key":                                  "operation",
		"M2Crypto.DSA.DSA.verify":                                   "operation",
		"M2Crypto.EC.EC.gen_key":                                    "operation",
		"M2Crypto.EC.EC.verify_dsa":                                 "operation",
		"M2Crypto.EC.EC_pub.get_key":                                "output",
		"M2Crypto.DH.DH.gen_key":                                    "operation",
		"M2Crypto.EVP.MessageDigest.update":                         "operation",
		"M2Crypto.EVP.HMAC.update":                                  "operation",
		"M2Crypto.EVP.PKey.assign_rsa":                              "config",
		"M2Crypto.EVP.PKey.assign_ec":                               "config",
		"M2Crypto.EVP.PKey.sign_update":                             "operation",
		"M2Crypto.EVP.PKey.verify_final":                            "operation",
		"M2Crypto.EVP.PKey.digest_verify":                           "operation",
		"M2Crypto.EVP.PKey.get_ec":                                  "output",
		"M2Crypto.BIO.CipherStream.set_cipher":                      "config",
		"M2Crypto.X509.X509.sign":                                   "operation",
		"M2Crypto.X509.X509.verify":                                 "operation",
		"M2Crypto.X509.Request.sign":                                "operation",
		"M2Crypto.X509.Request.verify":                              "operation",
		"M2Crypto.X509.CRL.verify":                                  "operation",
		"M2Crypto.X509.X509_Store_Context.verify_cert":              "operation",
		"M2Crypto.SMIME.SMIME.load_key":                             "config",
		"M2Crypto.SMIME.SMIME.encrypt":                              "operation",
		"M2Crypto.SMIME.SMIME.decrypt":                              "operation",
		"M2Crypto.SSL.Context.Context.load_cert":                    "config",
		"M2Crypto.SSL.Context.Context.load_cert_chain":              "config",
		"M2Crypto.SSL.Context.Context.load_verify_locations":        "config",
		"M2Crypto.SSL.Context.Context.set_client_CA_list_from_file": "config",
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

	// open_https is a module function that takes the context as an argument,
	// so it is not part of the context's lifecycle and never becomes one of
	// its supporting calls. In a real scan it is a finding of its own; here it
	// must resolve to its module path and to its contract.
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	var opened bool
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if fullFunctionName(call.Callee) != "M2Crypto.m2urllib.open_https" {
				continue
			}
			opened = true
			matches := kb.ContractsForTolerant("M2Crypto.m2urllib.open_https", len(call.Arguments))
			if len(matches) != 1 || matches[0].SourceLibrary != "m2crypto" || matches[0].Role != "operation" {
				t.Errorf("open_https contracts = %v, want one m2crypto operation", matches)
			}
		}
	}
	if !opened {
		t.Error("m2urllib.open_https(..) did not resolve to M2Crypto.m2urllib.open_https")
	}
}
