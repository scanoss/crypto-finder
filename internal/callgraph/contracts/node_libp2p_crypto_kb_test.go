// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The cipher factories are keyed where each release publishes them: AES-GCM as
// '/ciphers' AES_GCM.create (5.x), AES-CTR as '/aes' and root aes.create (0.22-3.x).
func TestLoadEmbeddedNodeLibp2pCryptoCiphers(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}
	for _, want := range []string{
		"@libp2p/crypto/ciphers.AES_GCM.create#0",
		"@libp2p/crypto/ciphers.AES_GCM.create#1",
		"@libp2p/crypto/aes.create#2",
		"@libp2p/crypto.aes.create#2",
		"@libp2p/crypto.hmac.create#2",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}
	for _, arity := range []int{0, 1} {
		if got := kb.ContractsFor("@libp2p/crypto/ciphers.create", arity); len(got) != 0 {
			t.Errorf("@libp2p/crypto/ciphers.create#%d resolved; no release exports create on '/ciphers'", arity)
		}
	}
}
