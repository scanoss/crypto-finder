// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// assertLibraryOwnsItsKeys fails when a contract contributed by library is keyed
// outside prefix.
//
// Each library's test asks whether that library claims a neighbor's
// coordinates. Scanning the merged KB for the neighbor's prefix answers a
// different question, because LoadEmbedded merges every YAML in the ecosystem:
// the scan passes only while the neighbor has no KB of its own, and adding one
// is the ordinary way this catalog grows. Adding jsonwebtoken.yaml failed the
// fast-jwt test for exactly that reason, though fast-jwt had not changed.
// SourceLibrary answers the intended question and keeps answering it.
func assertLibraryOwnsItsKeys(t *testing.T, kb *contracts.KnowledgeBase, library, prefix string) {
	t.Helper()
	for key, cs := range kb.Contracts {
		for i := range cs {
			if cs[i].SourceLibrary == library && !strings.HasPrefix(key, prefix) {
				t.Errorf("%s contributes key %q, outside its own %q coordinates", library, key, prefix)
			}
		}
	}
}
