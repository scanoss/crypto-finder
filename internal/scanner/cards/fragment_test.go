// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cards

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/cardmatch"
)

// The in-memory conversion gives the matcher every external call field a
// written fragment does: the declared type a Go call on an interface value
// is matched by included.
func TestToMatcherFragment_ExternalCallsAsWritten(t *testing.T) {
	t.Parallel()
	line, start, end := 13, 13, 40
	export := &graphfrag.GraphFragmentExport{ExternalCalls: []graphfrag.GraphFragmentExternal{{
		CallerKey: "example.com/app.f", TargetKey: "example.com/lib.(Curve).GenerateKey", Raw: "lib.X().GenerateKey",
		Line: line, Resolution: "name_only", MethodName: "GenerateKey", Arity: 1, StartCol: start, EndCol: end,
		DeclaredType: "example.com/lib.Curve",
	}}}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	var written cardmatch.FragmentJSON
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}
	got := toMatcherFragment(export)
	if !reflect.DeepEqual(got.ExternalCalls, written.ExternalCalls) {
		t.Errorf("in memory %+v\nwritten   %+v", got.ExternalCalls, written.ExternalCalls)
	}
}
