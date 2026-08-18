// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

func TestResolvedKeyLengthFromContract(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "java",
	})
	keyGeneratorInit := callgraph.FunctionID{Package: "javax.crypto", Type: "KeyGenerator", Name: "init#1"}

	tests := []struct {
		name           string
		argument       string
		resolvedValue  string
		parameterType  string
		wantBits       int
		wantProvenance string
		wantAbsent     bool
	}{
		{
			name:           "literal key bits",
			argument:       "256",
			resolvedValue:  "256",
			parameterType:  "int",
			wantBits:       256,
			wantProvenance: "constant",
		},
		{
			name:           "ambiguous variable remains unresolved",
			argument:       "keyBits",
			parameterType:  "int",
			wantProvenance: "unknown",
		},
		{
			name:          "same arity non-int overload is excluded",
			argument:      "parameters",
			parameterType: "java.security.spec.AlgorithmParameterSpec",
			wantAbsent:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &callgraph.FunctionCall{
				Callee:    keyGeneratorInit,
				FilePath:  "KeyFlow.java",
				Line:      5,
				Arguments: []string{tt.argument},
			}
			parameters := []callGraphParameter{{
				ParameterIndex:     0,
				ArgumentExpression: tt.argument,
				ResolvedValue:      tt.resolvedValue,
			}}
			matches := contractMatchesForCall(ctx, call, len(call.Arguments))
			got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, []string{tt.parameterType})
			if tt.wantAbsent {
				if got != nil {
					t.Fatalf("resolved key length = %#v, want nil for non-int overload", got)
				}
				return
			}
			if got == nil {
				t.Fatal("resolved key length = nil, want contract-scoped evidence")
			}
			if got.Provenance != tt.wantProvenance {
				t.Fatalf("provenance = %q, want %q", got.Provenance, tt.wantProvenance)
			}
			if got.SourceCall.FunctionName != "javax.crypto.KeyGenerator.init" || got.SourceCall.Line != call.Line || got.SourceCall.ParameterIndex != 0 {
				t.Fatalf("source_call = %#v, want init line %d parameter 0", got.SourceCall, call.Line)
			}
			if tt.wantProvenance == "constant" {
				if got.Bits == nil || *got.Bits != tt.wantBits {
					t.Fatalf("bits = %#v, want %d", got.Bits, tt.wantBits)
				}
			} else if got.Bits != nil {
				t.Fatalf("bits = %#v, want nil for unresolved input", got.Bits)
			}
		})
	}
}
