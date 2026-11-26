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

package cards

import (
	"os"

	"github.com/scanoss/reach/cardmatch"

	"github.com/scanoss/crypto-finder/internal/config"
)

// MatcherOptions are the options crypto-finder runs the card matcher with:
// the rules' metadata.crypto, card languages from the ruleset layout, and the
// debugging overrides of two environment variables:
//
//   - CRYPTO_FINDER_CARDS_CONSTANT_COMPARISONS=all reports every constant a
//     comparison, an equals call or a case label reads, as OpenGrep does, and
//     =off none;
//   - CRYPTO_FINDER_CARDS_PY_MEMBERSHIP=all reports every Python constant
//     read in an `in` test (OpenGrep's Python rules exclude them).
func MatcherOptions() cardmatch.Options {
	return cardmatch.Options{
		MetadataKey:         "crypto",
		LanguageOf:          config.CardsLanguage,
		ConstantComparisons: cardmatch.ComparisonPolicy(os.Getenv("CRYPTO_FINDER_CARDS_CONSTANT_COMPARISONS")),
		PyMembership:        cardmatch.ComparisonPolicy(os.Getenv("CRYPTO_FINDER_CARDS_PY_MEMBERSHIP")),
	}
}
