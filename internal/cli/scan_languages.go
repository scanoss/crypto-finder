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

package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
	"github.com/scanoss/crypto-finder/internal/version"
)

// cryptoLanguage maps a language name detection or --languages gives (any
// spelling: typescript, tsx, ts, c++) to the canonical name of a language
// of the cards table, the languages crypto-finder detects cryptography in or
// will in later versions; "" for any other language (xml, markdown, shell,
// ...), which carries no cryptography a ruleset names and is neither scanned
// nor reported.
func cryptoLanguage(language string) string {
	lang, ok := cards.ForName(cards.Canonical(language))
	if !ok {
		return ""
	}
	return lang.Name
}

// scannedEcosystems returns the ecosystems a target is scanned for, the
// scanned languages of the cards table, in the order languages names them (detection orders them by file
// count, so the first is the primary ecosystem), and the target's other
// crypto languages, sorted, which this version does not scan. A target
// holding both Java and Python is scanned for both, each against its own
// rules, cards and call graph, as main scans every ecosystem with source.
func scannedEcosystems(languages []string) (ecosystems, unsupported []string) {
	unsupported, _ = unsupportedLanguages(languages)
	for _, language := range languages {
		lang, ok := cards.ForName(cryptoLanguage(language))
		if ok && lang.IsScanned() && !slices.Contains(ecosystems, lang.Ecosystem) {
			ecosystems = append(ecosystems, lang.Ecosystem)
		}
	}
	unsupported = slices.DeleteFunc(unsupported, func(l string) bool {
		lang, ok := cards.ForName(l)
		return ok && lang.IsScanned()
	})
	return ecosystems, unsupported
}

// scannedLanguageHints names the scanned ecosystems as rule files and card
// directories do (javascript and typescript, not the node ecosystem): the rule
// filter matches the hints against a rule's languages and a card file's
// directory.
func scannedLanguageHints(ecosystems []string) []string {
	hints := make([]string, 0, len(ecosystems))
	for _, ecosystem := range ecosystems {
		lang, ok := cards.ForEcosystem(ecosystem)
		if !ok {
			hints = append(hints, ecosystem)
			continue
		}
		hints = append(hints, lang.Name)
		hints = append(hints, lang.Aliases...)
	}
	return hints
}

// unsupportedLanguages returns, sorted and without repeats, the crypto
// languages of languages other than Java, and whether languages hold Java.
// Python among them is scanned too (scannedEcosystems).
func unsupportedLanguages(languages []string) (unsupported []string, java bool) {
	for _, language := range languages {
		switch crypto := cryptoLanguage(language); crypto {
		case "":
		case ecosystemJava:
			java = true
		default:
			if !slices.Contains(unsupported, crypto) {
				unsupported = append(unsupported, crypto)
			}
		}
	}
	slices.Sort(unsupported)
	return unsupported, java
}

// languageNotSupported is the failure of a scan whose target holds source
// only in languages this version cannot scan.
func languageNotSupported(unsupported []string) error {
	return failure.New(
		failure.CodeLanguageNotSupported,
		failure.StageScan,
		fmt.Sprintf("crypto-finder %s detects cryptography in Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++ and C# only; %s %s not supported by this version",
			version.Version, strings.Join(unsupported, ", "), pluralIs(len(unsupported))),
		failure.WithDetail("languages", strings.Join(unsupported, ",")),
	)
}

func pluralIs(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
