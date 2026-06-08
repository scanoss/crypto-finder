// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestFragment_ContainingFunction_PicksMatchingFile verifies that a finding is
// mapped to the function in the same file whose line range encloses it, and not
// to a same-named range in a different file.
func TestFragment_ContainingFunction_PicksMatchingFile(t *testing.T) {
	t.Parallel()

	frag := Fragment{
		Functions: []Function{
			{Signature: "a#0", FilePath: "A.java", StartLine: 1, EndLine: 10},
			{Signature: "b#0", FilePath: "B.java", StartLine: 1, EndLine: 10},
		},
	}

	fn, ok := frag.ContainingFunction("B.java", 5)
	if !ok {
		t.Fatal("expected a containing function for B.java:5")
	}
	if fn.Signature != "b#0" {
		t.Fatalf("Signature = %q, want b#0", fn.Signature)
	}
}

// TestFragment_ContainingFunction_PicksTightestRange verifies that when nested
// ranges in the same file enclose the line, the innermost (tightest) range
// wins — the most specific owning function for a finding.
func TestFragment_ContainingFunction_PicksTightestRange(t *testing.T) {
	t.Parallel()

	frag := Fragment{
		Functions: []Function{
			{Signature: "outer#0", FilePath: "A.java", StartLine: 1, EndLine: 100},
			{Signature: "inner#0", FilePath: "A.java", StartLine: 40, EndLine: 60},
			{Signature: "innermost#0", FilePath: "A.java", StartLine: 45, EndLine: 50},
		},
	}

	fn, ok := frag.ContainingFunction("A.java", 47)
	if !ok {
		t.Fatal("expected a containing function for A.java:47")
	}
	if fn.Signature != "innermost#0" {
		t.Fatalf("Signature = %q, want innermost#0 (tightest enclosing range)", fn.Signature)
	}
}

// TestFragment_ContainingFunction_BoundariesInclusive verifies the StartLine and
// EndLine boundaries are inclusive.
func TestFragment_ContainingFunction_BoundariesInclusive(t *testing.T) {
	t.Parallel()

	frag := Fragment{
		Functions: []Function{
			{Signature: "a#0", FilePath: "A.java", StartLine: 5, EndLine: 8},
		},
	}

	for _, line := range []int{5, 8} {
		if _, ok := frag.ContainingFunction("A.java", line); !ok {
			t.Fatalf("expected line %d to be inside [5,8]", line)
		}
	}
}

// TestFragment_ContainingFunction_NoMatch verifies a line outside every range
// (or in a file with no function) returns false.
func TestFragment_ContainingFunction_NoMatch(t *testing.T) {
	t.Parallel()

	frag := Fragment{
		Functions: []Function{
			{Signature: "a#0", FilePath: "A.java", StartLine: 5, EndLine: 8},
		},
	}

	if _, ok := frag.ContainingFunction("A.java", 9); ok {
		t.Fatal("expected no match for line 9 outside [5,8]")
	}
	if _, ok := frag.ContainingFunction("Other.java", 6); ok {
		t.Fatal("expected no match for a file with no functions")
	}
}
