// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package wiring

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/scanoss/static-engine/callgraph"
	"github.com/scanoss/static-engine/callgraph/contracts"
	"github.com/scanoss/static-engine/javaruntime"
)

// Moved from static-engine's scan package: these pin that every Python name
// the KB adds for older library releases and pycryptodome/python-jose
// coverage is what the parser emits for a consumer's call, at the arity the
// contract declares.

// buildPythonConsumerGraph builds the call graph of one consumer file.
func buildPythonConsumerGraph(t *testing.T, source string) *callgraph.CallGraph {
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
	return graph
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

	kb, err := contracts.Load("python")
	if err != nil {
		t.Fatalf("Load(python): %v", err)
	}
	for _, tc := range olderReleaseCallKeys {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildPythonConsumerGraph(t, tc.source)
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

	kb, err := contracts.Load("python")
	if err != nil {
		t.Fatalf("Load(python): %v", err)
	}
	for _, key := range olderReleaseKeys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			source, want := olderReleaseConsumer(key)
			const line = 5
			graph := buildPythonConsumerGraph(t, source)
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

	kb, err := contracts.Load("python")
	if err != nil {
		t.Fatalf("Load(python): %v", err)
	}
	for _, key := range coverageKeys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			source, want := olderReleaseConsumer(key)
			const line = 5
			graph := buildPythonConsumerGraph(t, source)
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

func nonEmpty(parts ...string) []string {
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
