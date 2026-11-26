// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// A stored Rust fragment's items and imports reach the matcher's read side
// as the exporter wrote them.
func TestFragmentJSONReadsRustItemsAndImports(t *testing.T) {
	t.Parallel()
	export := graphfrag.GraphFragmentExport{
		SchemaVersion: graphfrag.SchemaVersion,
		Imports: map[string][]graphfrag.GraphFragmentImport{
			"src/lib.rs": {{Line: 1, Module: "acme::kdf", Name: "Kdf", StartCol: 1, EndCol: 28, Text: "acme::kdf::{Kdf, self}"}},
		},
		Items: map[string][]graphfrag.GraphFragmentItem{
			"src/lib.rs": {
				{Line: 3, StartCol: 1, EndCol: 2, EndLine: 5, Kind: "fn", Name: "derive"},
				{Line: 7, StartCol: 1, EndCol: 20, Kind: "const", Name: "SALT"},
			},
		},
	}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	var frag FragmentJSON
	if err := json.Unmarshal(data, &frag); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(frag.Items, export.Items) {
		t.Errorf("items\n got %+v\nwant %+v", frag.Items, export.Items)
	}
	if !reflect.DeepEqual(frag.Imports, export.Imports) {
		t.Errorf("imports\n got %+v\nwant %+v", frag.Imports, export.Imports)
	}
}
