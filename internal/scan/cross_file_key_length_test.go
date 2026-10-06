// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const (
	goCrossFileUse = `package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func f() {
	rsa.GenerateKey(rand.Reader, keyBits)
}
`
	goCrossFileConsts = "package main\n\nconst keyBits = 3072\n"
	cCrossFileUse     = `#include <openssl/evp.h>
#include "bits.h"

void f(EVP_PKEY_CTX *ctx) {
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS);
}
`
	cCrossFileHeader = "#ifndef BITS_H\n#define BITS_H\n#define RSA_BITS 4096\n#endif\n"
)

// TestCrossFileConstants_ReachableThroughFindingSupportingCallIDs pins that a
// key size declared in another file of the package (Go const) or in a local
// header (C #define) is exact bits under the shape consumers read, live and
// stitched, and that an ambiguous declaration reports nothing.
func TestCrossFileConstants_ReachableThroughFindingSupportingCallIDs(t *testing.T) {
	const (
		goAPI   = "crypto/rsa.GenerateKey"
		goMatch = "rsa.GenerateKey(rand.Reader, keyBits)"
		cAPI    = "EVP_PKEY_CTX_set_rsa_keygen_bits"
		cMatch  = "EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS);"
	)
	for _, tc := range []struct {
		name      string
		ecosystem string
		file      string
		source    string
		siblings  map[string]string
		line      int
		match     string
		api       string
		wantIndex int
		wantBits  int // 0 means no resolved size may be reported
	}{
		{name: "go const in a sibling file", ecosystem: "go", file: "k.go", source: goCrossFileUse, siblings: map[string]string{"consts.go": goCrossFileConsts}, line: 9, match: goMatch, api: goAPI, wantIndex: 1, wantBits: 3072},
		{name: "go const declared under two build tags", ecosystem: "go", file: "k.go", source: goCrossFileUse, siblings: map[string]string{
			"consts_a.go": "//go:build linux\n\npackage main\n\nconst keyBits = 1024\n",
			"consts_b.go": "//go:build !linux\n\npackage main\n\nconst keyBits = 4096\n",
		}, line: 9, match: goMatch, api: goAPI},
		{name: "go const redeclared as a var elsewhere", ecosystem: "go", file: "k.go", source: goCrossFileUse, siblings: map[string]string{
			"consts.go": goCrossFileConsts,
			"other.go":  "package main\n\nvar keyBits = 1024\n",
		}, line: 9, match: goMatch, api: goAPI},
		{name: "c define in a quoted header", ecosystem: "c", file: "k.c", source: cCrossFileUse, siblings: map[string]string{"bits.h": cCrossFileHeader}, line: 5, match: cMatch, api: cAPI, wantIndex: 1, wantBits: 4096},
		{name: "c define in two headers", ecosystem: "c", file: "k.c", source: "#include <openssl/evp.h>\n#include \"bits.h\"\n#include \"more.h\"\n\nvoid f(EVP_PKEY_CTX *ctx) {\n    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS);\n}\n", siblings: map[string]string{"bits.h": cCrossFileHeader, "more.h": "#define RSA_BITS 1024\n"}, line: 6, match: cMatch, api: cAPI},
		{name: "c define under a header conditional", ecosystem: "c", file: "k.c", source: cCrossFileUse, siblings: map[string]string{"bits.h": "#ifdef BIG\n#define RSA_BITS 4096\n#endif\n"}, line: 5, match: cMatch, api: cAPI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exports := terminalExportsWithSiblings(t, tc.ecosystem, tc.file, tc.source, tc.siblings, tc.line, tc.match, tc.api, "")
			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, tc.api),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, tc.api),
			} {
				if tc.wantBits == 0 {
					if got != nil && got.Bits != nil {
						t.Fatalf("%s: resolved bits = %d, want none", name, *got.Bits)
					}
					continue
				}
				if got == nil || got.Bits == nil || *got.Bits != tc.wantBits {
					t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, tc.wantBits)
				}
				if got.Provenance != keyLengthProvenanceConstant || got.SourceCall.ParameterIndex != tc.wantIndex || got.SourceCall.Line != tc.line {
					t.Fatalf("%s: provenance/source = %#v, want constant at parameter %d line %d", name, got, tc.wantIndex, tc.line)
				}
			}
		})
	}
}
