// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNode(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}
	if kb.Ecosystem != "node" || kb.Library == nil || kb.Library.Name != "node-bootstrap" {
		t.Fatalf("LoadEmbedded(node) = %#v, want node-bootstrap KB", kb)
	}
}
