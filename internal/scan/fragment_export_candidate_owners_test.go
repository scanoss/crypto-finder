// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"slices"
	"testing"

	"github.com/scanoss/reach/callgraph"
)

// A C# call names its owner through an on-demand using, so its target is keyed
// on the caller's own namespace: the export hands the stitch the owners the
// usings allow. Java fills the same graph field for its own in-build
// reanchoring, and its fragments must not change.
func TestBuildFragmentExternalCallCandidateOwners(t *testing.T) {
	t.Parallel()
	alternatives := []string{"App.Sm4Engine", "Acme.Crypto.Engines.Sm4Engine"}
	for _, tc := range []struct {
		ecosystem string
		want      []string
	}{
		{ecosystem: ecosystemCSharp, want: alternatives},
		{ecosystem: ecosystemJava, want: nil},
	} {
		call := &callgraph.FunctionCall{OwnerAlternatives: alternatives}
		got := buildFragmentExternalCall(&exportBuildContext{graph: &callgraph.CallGraph{}, ecosystem: tc.ecosystem}, nil, call,
			"App.(Service).Run#1", "App.(Sm4Engine).Init#2", 4, fragmentEdgeResolution{})
		if !slices.Equal(got.CandidateOwners, tc.want) {
			t.Errorf("%s: candidate_owners = %q, want %q", tc.ecosystem, got.CandidateOwners, tc.want)
		}
	}
}
