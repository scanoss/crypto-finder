// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// assertLibraryOwnsPrefix fails when the merged ecosystem knowledge base keys a
// contract under prefix that another library authored, or keys one of library's
// own contracts outside prefix.
//
// A KB test asserting instead that the packages its library competes with are
// ABSENT from the merged set only passes until one of them gets a KB of its own.
// LoadEmbedded merges every library in the ecosystem, so a sibling's keys are
// supposed to be there. That assertion put main into a red state the day the
// jsonwebtoken KB landed (#534). Ownership is the invariant that survives the
// next KB.
func assertLibraryOwnsPrefix(t *testing.T, kb *contracts.KnowledgeBase, library, prefix string) {
	t.Helper()
	for key, declared := range kb.Contracts {
		for _, contract := range declared {
			under := strings.HasPrefix(key, prefix)
			switch {
			case under && contract.SourceLibrary != library:
				t.Errorf("key %q sits under %q but %q authored it", key, prefix, contract.SourceLibrary)
			case !under && contract.SourceLibrary == library:
				t.Errorf("key %q was authored by %q and belongs under %q", key, library, prefix)
			}
		}
	}
}

func TestNodeKnowledgeBaseLibrariesOwnTheirPrefixes(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}
	for library, prefix := range map[string]string{
		"fast-jwt":     "fast-jwt.",
		"elliptic":     "elliptic.",
		"jsonwebtoken": "jsonwebtoken.",
	} {
		assertLibraryOwnsPrefix(t, kb, library, prefix)
	}
}
