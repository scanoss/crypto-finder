// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"reflect"
	"testing"
)

// A served Python graph keeps its exports, which the stitch joins a client's
// public-name call through.
func TestDecodeProducerGraphKeepsExports(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":"graph-fragment-1.24","scan_metadata":{"ecosystem":"python","graph_algo_version":"graph-algo-py-20"},
		"functions":[{"key":"jwt.api_jwt.(PyJWT).encode"}],"exports":{"jwt.encode":"jwt.api_jwt.(PyJWT).encode"}}`)
	frag, err := DecodeProducerGraph(ComponentKey{Purl: "pkg:pypi/pyjwt", Version: "2.13.0"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"jwt.encode": "jwt.api_jwt.(PyJWT).encode"}; !reflect.DeepEqual(frag.Exports, want) {
		t.Fatalf("exports %v, want %v", frag.Exports, want)
	}
}
