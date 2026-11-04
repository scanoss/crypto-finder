// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Methods on unexported or interface types returned by an emmansun/gmsm
// factory must resolve to the keys their contracts are written under.
func TestEmmansunGmsmReceiverMethodsResolveToContracts(t *testing.T) {
	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}
	g := buildGoGraph(t, `package app

import (
	stdcipher "crypto/cipher"
	"io"

	gcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/sm9"
)

func keyExchange(priv *sm9.EncryptPrivateKey, r io.Reader, uid, peer []byte) {
	ke := priv.NewKeyExchange(uid, peer, 16, true)
	data, _ := ke.InitKeyExchange(r, 1)
	ke.ConfirmInitiator(data)
}

func hctr(key, tweak, hkey, data []byte) {
	b, _ := sm4.NewCipher(key)
	h, _ := gcipher.NewHCTR(b, tweak, hkey)
	h.EncryptBytes(data, data)
	h.DecryptBytes(data, data)
}

func gxm(stream stdcipher.Stream, hkey, data []byte) {
	a, _ := gcipher.NewGXM(stream, hkey)
	sealed := a.Seal(nil, data, nil)
	a.Open(nil, sealed, nil)
}
`)
	for key, arity := range map[string]int{
		"github.com/emmansun/gmsm/sm9.(*keyExchange).InitKeyExchange":         2,
		"github.com/emmansun/gmsm/sm9.(*keyExchange).ConfirmInitiator":        1,
		"github.com/emmansun/gmsm/cipher.(LengthPreservingMode).EncryptBytes": 2,
		"github.com/emmansun/gmsm/cipher.(LengthPreservingMode).DecryptBytes": 2,
		"github.com/emmansun/gmsm/cipher.(*gxm).Seal":                         3,
		"github.com/emmansun/gmsm/cipher.(*gxm).Open":                         3,
	} {
		assertGoCall(t, g, key)
		if got := kb.ContractsFor(key, arity); len(got) != 1 || got[0].Role != "operation" {
			t.Errorf("ContractsFor(%q, %d) = %#v, want one operation contract", key, arity, got)
		}
	}
}
