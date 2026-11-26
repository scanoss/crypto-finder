// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// The 1.21 call data (anchored calls, parameter names, return provenance,
// external signatures) is written for every language the cards scanner
// re-annotates without source. C# was the last one left out; with it ported,
// each ecosystem below carries the data.
func TestGraphFragmentCarriesCallsForCardsLanguages(t *testing.T) {
	t.Parallel()
	for _, ecosystem := range []string{"java", "python", "go", "node", "c", "rust", "cpp", "csharp"} {
		result := elideResult(t)
		result.Ecosystem = ecosystem
		export := buildGraphFragmentExport(result)
		var callees, names, returns int
		for _, anchor := range export.CallAnchors {
			if anchor.Callee != "" || anchor.Arguments != nil || anchor.ArgumentSources != nil {
				callees++
			}
		}
		for _, fn := range export.Functions {
			if fn.ParameterNames != nil {
				names++
			}
			if fn.ReturnSources != nil {
				returns++
			}
		}
		if len(export.CallAnchors) == 0 {
			t.Fatalf("%s: no call anchors", ecosystem)
		}
		if callees == 0 || names == 0 || returns == 0 {
			t.Errorf("%s: anchored calls %d, parameter names %d, return sources %d; want them written", ecosystem, callees, names, returns)
		}
	}
}
