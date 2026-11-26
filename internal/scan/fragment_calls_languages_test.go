// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/scanner/cards"
)

// portInFlight lists the compiled languages whose fragment does not carry
// the parser's calls yet, each mid-port with nothing annotating its graphs.
// None is now: C++ closed its entry.
var portInFlight = map[string]bool{}

// Every language the cards engine compiles writes its calls into the fragment.
// Annotate re-matches a stored graph with no source, so a language left out of
// fragmentCarriesCalls annotates from the edges alone: no call text, and an
// argument's provenance one hop short. Node, C, Rust and Ruby each shipped that
// way and were fixed after the fact; this fails on the next one instead.
func TestFragmentCarriesCallsCoversEveryCompiledLanguage(t *testing.T) {
	for _, language := range cards.Languages() {
		if !language.Compiled || portInFlight[language.Ecosystem] {
			continue
		}
		if !fragmentCarriesCalls(&exportBuildContext{ecosystem: language.Ecosystem}) {
			t.Errorf("the cards engine compiles %s but a %s fragment leaves the parser's calls out: add its ecosystem to fragmentCarriesCalls",
				language.Name, language.Ecosystem)
		}
	}
}

// A language named in portInFlight that already carries its calls is a stale
// exception: drop it, or the guard stops covering that language.
func TestPortInFlightExceptionsAreStillNeeded(t *testing.T) {
	for ecosystem := range portInFlight {
		if fragmentCarriesCalls(&exportBuildContext{ecosystem: ecosystem}) {
			t.Errorf("%s carries the parser's calls now: remove it from portInFlight", ecosystem)
		}
	}
}
