// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

func TestColumnFilterIndices_ExactSpanBeatsFluentChainSibling(t *testing.T) {
	t.Parallel()

	views := []candidateView{
		{StartCol: 16, EndCol: 51, ChainID: "chain", RawLen: 35, Constructor: true}, // constructor
		{StartCol: 16, EndCol: 53, ChainID: "chain", RawLen: 80},                    // setSecureRandom
		{StartCol: 16, EndCol: 46, ChainID: "chain", RawLen: 120},
	}

	got := columnFilterIndices(views, identityIndices(len(views)), 16, 51)
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("columnFilterIndices() = %v, want exact constructor span [0]", got)
	}
}
