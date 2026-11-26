// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cards

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/cardmatch"
)

// The matcher keeps reading its two debugging environment variables, now
// through the options crypto-finder passes it.
func TestMatcherOptionsReadTheEnvironment(t *testing.T) {
	t.Setenv("CRYPTO_FINDER_CARDS_CONSTANT_COMPARISONS", "all")
	t.Setenv("CRYPTO_FINDER_CARDS_PY_MEMBERSHIP", "off")
	opts := MatcherOptions()
	if opts.MetadataKey != "crypto" || opts.LanguageOf("/r/cards/python/a.cards") != "python" {
		t.Errorf("options = %+v", opts)
	}
	if opts.ConstantComparisons != cardmatch.ComparisonsAll || opts.PyMembership != cardmatch.ComparisonsOff {
		t.Errorf("policies = %q, %q", opts.ConstantComparisons, opts.PyMembership)
	}
}
