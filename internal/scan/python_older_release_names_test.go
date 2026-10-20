// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
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

// Calls that take no factory finding (annotated receivers, imported functions)
// must resolve to a name the embedded contract declares.
var olderReleaseCallKeys = []struct {
	name   string
	source string
	want   map[int]string // line -> resolved callee
}{
	{
		name: "python-jose 1.x, annotated jose.jwk.Key",
		source: `from jose.jwk import Key


def sign(k: Key, msg, sig):
    k.sign(msg)
    return k.verify(msg, sig)
`,
		want: map[int]string{5: "jose.jwk.Key.sign", 6: "jose.jwk.Key.verify"},
	},
	{
		name: "cryptography before 1.0, annotated interfaces.CipherContext",
		source: `from cryptography.hazmat.primitives.interfaces import CipherContext


def feed(ctx: CipherContext, data):
    ctx.update(data)
    return ctx.finalize()
`,
		want: map[int]string{
			5: "cryptography.hazmat.primitives.interfaces.CipherContext.update",
			6: "cryptography.hazmat.primitives.interfaces.CipherContext.finalize",
		},
	},
	{
		name: "cryptography, annotated RSAPrivateKeyWithSerialization",
		source: `from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization


def dump(key: RSAPrivateKeyWithSerialization, encoding, fmt, enc):
    return key.private_bytes(encoding, fmt, enc)
`,
		want: map[int]string{5: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.private_bytes"},
	},
	{
		name: "pynacl 0.2, nacl.c",
		source: `from nacl.c import crypto_sign, crypto_sign_open


def sign(sk, pk, message):
    signed = crypto_sign(sk, message)
    return crypto_sign_open(pk, signed)
`,
		want: map[int]string{5: "nacl.c.crypto_sign", 6: "nacl.c.crypto_sign_open"},
	},
	{
		name: "pynacl 0.2, nacl.c.crypto_sign",
		source: `from nacl.c.crypto_sign import crypto_sign


def sign(sk, message):
    return crypto_sign(sk, message)
`,
		want: map[int]string{5: "nacl.c.crypto_sign.crypto_sign"},
	},
	{
		name: "fastecdsa 1.1.0 to 1.1.2, ecdsa.gen_keypair",
		source: `from fastecdsa import ecdsa
from fastecdsa.curve import P256


def keys():
    priv, pub = ecdsa.gen_keypair(P256)
    return ecdsa.gen_keypair()
`,
		want: map[int]string{6: "fastecdsa.ecdsa.gen_keypair", 7: "fastecdsa.ecdsa.gen_keypair"},
	},
	{
		name: "py-ecc 1.6 to 1.7, pre-RFC hash_to_G2",
		source: `from py_ecc.bls.utils import hash_to_G2
from py_ecc.bls import api


def h(message_hash, domain):
    point = hash_to_G2(message_hash, domain)
    return api.hash_to_G2(message_hash, domain)
`,
		want: map[int]string{6: "py_ecc.bls.utils.hash_to_G2", 7: "py_ecc.bls.api.hash_to_G2"},
	},
}

func TestPython_OlderReleaseCallsResolveToContractKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	for _, tc := range olderReleaseCallKeys {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph, _ := buildPythonGraph(t, tc.source)
			got := map[int]callgraph.FunctionCall{}
			for _, fn := range graph.Functions {
				for _, c := range fn.Calls {
					got[c.Line] = c
				}
			}
			for line, want := range tc.want {
				c, ok := got[line]
				if !ok {
					t.Errorf("line %d: no call", line)
					continue
				}
				callee := strings.Join(nonEmpty(c.Callee.Package, c.Callee.Type, c.Callee.Name), ".")
				if callee != want {
					t.Errorf("line %d: callee = %q, want %q", line, callee, want)
					continue
				}
				if len(kb.ContractsFor(callee, len(c.Arguments))) == 0 {
					t.Errorf("line %d: %s#%d has no contract", line, callee, len(c.Arguments))
				}
			}
		})
	}
}

func nonEmpty(parts ...string) []string {
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// olderReleaseKeys lists every name added for older releases as module:rest#arity.
var olderReleaseKeys = []string{
	"Crypto.Signature.PKCS1_PSS:PSS_SigScheme.sign#1",
	"Crypto.Signature.PKCS1_PSS:PSS_SigScheme.verify#2",
	"Crypto.Signature.PKCS1_PSS:new#1",
	"Crypto.Signature.PKCS1_v1_5:PKCS115_SigScheme.sign#1",
	"Crypto.Signature.PKCS1_v1_5:PKCS115_SigScheme.verify#2",
	"Crypto.Signature.PKCS1_v1_5:new#1",
	"Cryptodome.Signature.PKCS1_PSS:PSS_SigScheme.sign#1",
	"Cryptodome.Signature.PKCS1_PSS:PSS_SigScheme.verify#2",
	"Cryptodome.Signature.PKCS1_PSS:new#1",
	"Cryptodome.Signature.PKCS1_v1_5:PKCS115_SigScheme.sign#1",
	"Cryptodome.Signature.PKCS1_v1_5:PKCS115_SigScheme.verify#2",
	"Cryptodome.Signature.PKCS1_v1_5:new#1",
	"certbot._internal.ocsp:RevocationChecker#1",
	"certbot._internal.ocsp:RevocationChecker.<init>#0",
	"certbot._internal.ocsp:RevocationChecker.ocsp_revoked#1",
	"certbot._internal.ocsp:RevocationChecker.ocsp_revoked_by_paths#2",
	"cryptography.hazmat.primitives.asymmetric:AsymmetricSignatureContext.finalize#0",
	"cryptography.hazmat.primitives.asymmetric:AsymmetricSignatureContext.update#1",
	"cryptography.hazmat.primitives.asymmetric:AsymmetricVerificationContext.update#1",
	"cryptography.hazmat.primitives.asymmetric:AsymmetricVerificationContext.verify#0",
	"cryptography.hazmat.primitives.asymmetric.dsa:DSAPrivateKey.signer#1",
	"cryptography.hazmat.primitives.asymmetric.dsa:DSAPrivateKeyWithSerialization.public_key#0",
	"cryptography.hazmat.primitives.asymmetric.dsa:DSAPrivateKeyWithSerialization.sign#2",
	"cryptography.hazmat.primitives.asymmetric.dsa:DSAPrivateKeyWithSerialization.signer#1",
	"cryptography.hazmat.primitives.asymmetric.dsa:DSAPublicKey.verifier#2",
	"cryptography.hazmat.primitives.asymmetric.dsa:DSAPublicKeyWithSerialization.verifier#2",
	"cryptography.hazmat.primitives.asymmetric.dsa:DSAPublicKeyWithSerialization.verify#3",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePrivateKey.signer#1",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePrivateKeyWithSerialization.exchange#2",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePrivateKeyWithSerialization.private_bytes#3",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePrivateKeyWithSerialization.public_key#0",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePrivateKeyWithSerialization.sign#2",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePrivateKeyWithSerialization.signer#1",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePublicKey.verifier#2",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePublicKeyWithSerialization.verifier#2",
	"cryptography.hazmat.primitives.asymmetric.ec:EllipticCurvePublicKeyWithSerialization.verify#3",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPrivateKey.generate#3",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPrivateKey.signer#2",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPrivateKeyWithSerialization.decrypt#2",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPrivateKeyWithSerialization.private_bytes#3",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPrivateKeyWithSerialization.public_key#0",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPrivateKeyWithSerialization.sign#3",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPrivateKeyWithSerialization.signer#2",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPublicKey.verifier#3",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPublicKeyWithSerialization.encrypt#2",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPublicKeyWithSerialization.public_bytes#2",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPublicKeyWithSerialization.verifier#3",
	"cryptography.hazmat.primitives.asymmetric.rsa:RSAPublicKeyWithSerialization.verify#4",
	"cryptography.hazmat.primitives.asymmetric.types:PrivateKeyTypes.signer#1",
	"cryptography.hazmat.primitives.asymmetric.types:PrivateKeyTypes.signer#2",
	"cryptography.hazmat.primitives.asymmetric.types:PublicKeyTypes.verifier#2",
	"cryptography.hazmat.primitives.asymmetric.types:PublicKeyTypes.verifier#3",
	"cryptography.hazmat.primitives.interfaces:AEADCipherContext.authenticate_additional_data#1",
	"cryptography.hazmat.primitives.interfaces:AsymmetricSignatureContext.finalize#0",
	"cryptography.hazmat.primitives.interfaces:AsymmetricSignatureContext.update#1",
	"cryptography.hazmat.primitives.interfaces:AsymmetricVerificationContext.update#1",
	"cryptography.hazmat.primitives.interfaces:AsymmetricVerificationContext.verify#0",
	"cryptography.hazmat.primitives.interfaces:CipherContext.finalize#0",
	"cryptography.hazmat.primitives.interfaces:CipherContext.update#1",
	"cryptography.hazmat.primitives.interfaces:DSAPrivateKey.public_key#0",
	"cryptography.hazmat.primitives.interfaces:DSAPrivateKey.signer#1",
	"cryptography.hazmat.primitives.interfaces:DSAPublicKey.verifier#2",
	"cryptography.hazmat.primitives.interfaces:EllipticCurvePrivateKey.public_key#0",
	"cryptography.hazmat.primitives.interfaces:EllipticCurvePrivateKey.signer#1",
	"cryptography.hazmat.primitives.interfaces:EllipticCurvePublicKey.verifier#2",
	"cryptography.hazmat.primitives.interfaces:PaddingContext.finalize#0",
	"cryptography.hazmat.primitives.interfaces:PaddingContext.update#1",
	"cryptography.hazmat.primitives.interfaces:RSAPrivateKey.decrypt#2",
	"cryptography.hazmat.primitives.interfaces:RSAPrivateKey.public_key#0",
	"cryptography.hazmat.primitives.interfaces:RSAPrivateKey.signer#2",
	"cryptography.hazmat.primitives.interfaces:RSAPublicKey.encrypt#2",
	"cryptography.hazmat.primitives.interfaces:RSAPublicKey.verifier#3",
	"cryptography.hazmat.primitives.interfaces:X509Certificate.fingerprint#1",
	"cryptography.hazmat.primitives.interfaces:X509Certificate.public_key#0",
	"cryptography.hazmat.primitives.serialization:load_pem_pkcs8_private_key#3",
	"cryptography.hazmat.primitives.serialization:load_pem_traditional_openssl_private_key#3",
	"fastecdsa.ecdsa:gen_keypair#0",
	"fastecdsa.ecdsa:gen_keypair#1",
	"jose.jwk:Key.decrypt#1",
	"jose.jwk:Key.encrypt#1",
	"jose.jwk:Key.public_key#0",
	"jose.jwk:Key.sign#1",
	"jose.jwk:Key.sign#2",
	"jose.jwk:Key.to_dict#0",
	"jose.jwk:Key.to_pem#0",
	"jose.jwk:Key.unwrap_key#1",
	"jose.jwk:Key.verify#2",
	"jose.jwk:Key.verify#3",
	"jose.jwk:Key.wrap_key#1",
	"jwt.api:PyJWT#0",
	"jwt.api:PyJWT.<init>#0",
	"jwt.api:PyJWT.decode#1",
	"jwt.api:PyJWT.encode#2",
	"jwt.api:decode#1",
	"jwt.api:encode#2",
	"nacl.c:crypto_sign#2",
	"nacl.c.crypto_sign:crypto_sign#2",
	"nacl.c.crypto_sign:crypto_sign_open#2",
	"nacl.c:crypto_sign_open#2",
	"py_ecc.bls.api:hash_to_G2#2",
	"py_ecc.bls.utils:hash_to_G2#2",
}

// olderReleaseConsumer writes a consumer that calls module:rest the way an
// import spells it: a method through a from-imported annotation, a function or
// constructor through a from-import, a class call through its module.
func olderReleaseConsumer(entry string) (source, callee string) {
	spec, arityText, _ := strings.Cut(entry, "#")
	module, rest, _ := strings.Cut(spec, ":")
	arity, _ := strconv.Atoi(arityText)
	args := make([]string, arity)
	for i := range args {
		args[i] = fmt.Sprintf("a%d", i)
	}
	list := strings.Join(args, ", ")
	cls, member, isMember := strings.Cut(rest, ".")
	switch {
	case !isMember && unicode.IsUpper(rune(rest[0])):
		parent, leaf := module[:strings.LastIndex(module, ".")], module[strings.LastIndex(module, ".")+1:]
		source = fmt.Sprintf("from %s import %s\n\n\ndef f(%s):\n    return %s.%s(%s)\n", parent, leaf, list, leaf, rest, list)
	case !isMember:
		source = fmt.Sprintf("from %s import %s\n\n\ndef f(%s):\n    return %s(%s)\n", module, rest, list, rest, list)
	case member == "<init>":
		source = fmt.Sprintf("from %s import %s\n\n\ndef f(%s):\n    return %s(%s)\n", module, cls, list, cls, list)
	default:
		params := strings.Join(append([]string{"x: " + cls}, args...), ", ")
		source = fmt.Sprintf("from %s import %s\n\n\ndef f(%s):\n    return x.%s(%s)\n", module, cls, params, member, list)
	}
	return source, module + "." + rest
}

func TestPython_EveryOlderReleaseNameResolvesToItsContract(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	for _, key := range olderReleaseKeys {
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
