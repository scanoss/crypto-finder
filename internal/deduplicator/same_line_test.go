// Copyright 2025 SCANOSS
//
// SPDX-License-Identifier: Apache-2.0

package deduplicator

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func bcryptMatch(startCol, endCol int) entities.CryptographicAsset {
	return callAsset(startCol, endCol, "python.bcrypt", map[string]string{
		"assetType": "algorithm", "algorithmName": "bcrypt", "algorithmFamily": "bcrypt", "algorithmPrimitive": "kdf",
	})
}

// CF-GEN-002: one rule matching two calls side by side on one line reports two
// operations, not one.
func TestDeduplicate_SameLineCallsAtDifferentColumnsStayApart(t *testing.T) {
	// a = bcrypt.hashpw(x, s); b = bcrypt.hashpw(y, s)
	if got := dedupFile(bcryptMatch(9, 30), bcryptMatch(36, 57)); len(got) != 2 {
		t.Fatalf("two calls at different columns of one line, want 2 assets, got %q", got)
	}
}

// CF-GEN-002: bcrypt.hashpw(password, bcrypt.gensalt(rounds=12)) gives one
// rule two matches on one line, gensalt nested in hashpw's arguments. A rule
// reports one call once, so its two matches are two calls, not one call seen
// by two rules.
func TestDeduplicate_NestedCallMatchedBySameRuleStaysApart(t *testing.T) {
	if got := dedupFile(bcryptMatch(14, 64), bcryptMatch(38, 63)); len(got) != 2 {
		t.Fatalf("hashpw and the gensalt nested in it, want 2 assets, got %q", got)
	}
}

// Without columns the deduplicator cannot tell two calls on one line apart and
// groups by line, as before.
func TestDeduplicate_SameLineWithoutColumnsStillMerges(t *testing.T) {
	if got := dedupFile(bcryptMatch(0, 0), bcryptMatch(0, 0)); len(got) != 1 {
		t.Fatalf("line-only matches of one asset, want 1 merged asset, got %q", got)
	}
}

// The same span reported twice is one asset whatever the columns.
func TestDeduplicate_SameSpanMerges(t *testing.T) {
	if got := dedupFile(bcryptMatch(14, 64), bcryptMatch(14, 64)); len(got) != 1 {
		t.Fatalf("one span reported twice, want 1 asset, got %q", got)
	}
}
