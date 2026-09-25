// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// parseGoCallKeys parses one Go source and returns every resolved callee as
// "<method>#<argument count>".
func parseGoCallKeys(t *testing.T, src string) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				call := &analysis.Functions[i].Calls[j]
				keys[call.Callee.String()+"#"+strconv.Itoa(len(call.Arguments))] = true
			}
		}
	}
	return keys
}

// The x/crypto contracts added for the NaCl box, sign and auth packages,
// salsa20, elgamal, clearsign, knownhosts and NewSignerWithAlgorithms key on
// the identity the Go parser gives each call.
func TestXCryptoNaClAndSigningContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	keys := parseGoCallKeys(t, `package main

import (
	"crypto/rand"
	"io"
	"math/big"

	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/elgamal"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func naclBox(msg []byte, nonce *[24]byte, peer, priv, shared *[32]byte) {
	box.GenerateKey(rand.Reader)
	box.Precompute(shared, peer, priv)
	sealed := box.Seal(nil, msg, nonce, peer, priv)
	box.Open(nil, sealed, nonce, peer, priv)
	pre := box.SealAfterPrecomputation(nil, msg, nonce, shared)
	box.OpenAfterPrecomputation(nil, pre, nonce, shared)
	anon, _ := box.SealAnonymous(nil, msg, peer, rand.Reader)
	box.OpenAnonymous(nil, anon, peer, priv)
}

func naclSign(msg []byte, pub *[32]byte, priv *[64]byte, key *[32]byte) {
	sign.GenerateKey(rand.Reader)
	signed := sign.Sign(nil, msg, priv)
	sign.Open(nil, signed, pub)
	tag := auth.Sum(msg, key)
	auth.Verify(tag[:], msg, key)
}

func stream(out, in, nonce []byte, key *[32]byte) {
	salsa20.XORKeyStream(out, in, nonce, key)
}

func elgamalRoundTrip(pub *elgamal.PublicKey, priv *elgamal.PrivateKey, msg []byte) {
	c1, c2, _ := elgamal.Encrypt(rand.Reader, pub, msg)
	elgamal.Decrypt(priv, c1, c2)
	_ = new(big.Int)
}

func cleartext(w io.Writer, key *packet.PrivateKey, keys []*packet.PrivateKey) {
	clearsign.Encode(w, key, nil)
	clearsign.EncodeMulti(w, keys, nil)
}

func sshSigning(signer ssh.AlgorithmSigner, host string) {
	ssh.NewSignerWithAlgorithms(signer, []string{ssh.KeyAlgoRSASHA256})
	knownhosts.HashHostname(host)
}
`)

	const x = "golang.org/x/crypto/"
	want := map[string]string{
		x + "nacl/box.GenerateKey#1":             "factory",
		x + "nacl/box.Precompute#3":              "operation",
		x + "nacl/box.Seal#5":                    "operation",
		x + "nacl/box.Open#5":                    "operation",
		x + "nacl/box.SealAfterPrecomputation#4": "operation",
		x + "nacl/box.OpenAfterPrecomputation#4": "operation",
		x + "nacl/box.SealAnonymous#4":           "operation",
		x + "nacl/box.OpenAnonymous#4":           "operation",
		x + "nacl/sign.GenerateKey#1":            "factory",
		x + "nacl/sign.Sign#3":                   "operation",
		x + "nacl/sign.Open#3":                   "operation",
		x + "nacl/auth.Sum#2":                    "operation",
		x + "nacl/auth.Verify#3":                 "operation",
		x + "salsa20.XORKeyStream#4":             "operation",
		x + "openpgp/elgamal.Encrypt#3":          "operation",
		x + "openpgp/elgamal.Decrypt#3":          "operation",
		x + "openpgp/clearsign.Encode#3":         "operation",
		x + "openpgp/clearsign.EncodeMulti#3":    "operation",
		x + "ssh.NewSignerWithAlgorithms#2":      "factory",
		x + "ssh/knownhosts.HashHostname#1":      "operation",
	}
	for key, role := range want {
		if !keys[key] {
			t.Errorf("no parsed call %s; parsed %v", key, keys)
			continue
		}
		method, arity := splitGoCallKey(t, key)
		got := kb.ContractsFor(method, arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want exactly one", method, arity, len(got))
			continue
		}
		if got[0].Role != role || got[0].SourceLibrary != "golang-x-crypto" {
			t.Errorf("%s: role %q library %q, want role %q library golang-x-crypto", key, got[0].Role, got[0].SourceLibrary, role)
		}
	}
}

// A ChaCha20-Poly1305 AEAD sealed in the constructing function and opened in
// another, through a cipher.AEAD parameter, resolves both operations to the
// shared interface contract. The constructor's contract return type is what
// types the local receiver.
func TestXCryptoChaChaAEADOperationsJoinAcrossFunctions(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	src := `package main

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

func encrypt(key, nonce, msg []byte) []byte {
	aead, _ := chacha20poly1305.NewX(key)
	sealed := aead.Seal(nil, nonce, msg, nil)
	return decrypt(aead, nonce, sealed)
}

func decrypt(aead cipher.AEAD, nonce, sealed []byte) []byte {
	out, _ := aead.Open(nil, nonce, sealed, nil)
	return out
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	callees := map[string]bool{}
	for _, key := range goCalleeKeys(g) {
		callees[key] = true
	}
	for _, method := range []string{"crypto/cipher.(AEAD).Seal", "crypto/cipher.(AEAD).Open"} {
		if !callees[method] {
			t.Errorf("no call resolved to %s; callees %v", method, goCalleeKeys(g))
			continue
		}
		got := kb.ContractsFor(method, 4)
		if len(got) != 1 || got[0].Role != "operation" {
			t.Errorf("ContractsFor(%q, 4) = %#v, want one operation contract", method, got)
		}
	}
}

func splitGoCallKey(t *testing.T, key string) (string, int) {
	t.Helper()
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '#' {
			arity, err := strconv.Atoi(key[i+1:])
			if err != nil {
				t.Fatalf("bad key %q", key)
			}
			return key[:i], arity
		}
	}
	t.Fatalf("bad key %q", key)
	return "", 0
}
