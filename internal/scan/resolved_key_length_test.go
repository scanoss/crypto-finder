// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestBuildCryptoCall_ResolvedKeyLength(t *testing.T) {
	t.Parallel()

	callerID := callgraph.FunctionID{Package: "example", Type: "KeyFlow", Name: "configure#0"}
	keyGeneratorInit := callgraph.FunctionID{Package: "javax.crypto", Type: "KeyGenerator", Name: "init#1"}
	caller := &callgraph.FunctionDecl{ID: callerID, FilePath: "KeyFlow.java", StartLine: 1, EndLine: 8}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{callerID.String(): caller}}
	ctx := newExportBuildContext(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})

	tests := []struct {
		name           string
		call           callgraph.FunctionCall
		parameterType  string
		wantBits       int
		wantProvenance string
		wantAbsent     bool
	}{
		{
			name: "literal key bits",
			call: callgraph.FunctionCall{
				Callee:    keyGeneratorInit,
				FilePath:  "KeyFlow.java",
				Line:      5,
				Arguments: []string{"256"},
				ArgumentSources: [][]callgraph.SourceNode{{
					{Type: "VALUE", Value: "256"},
				}},
			},
			parameterType:  "int",
			wantBits:       256,
			wantProvenance: "constant",
		},
		{
			name: "ambiguous variable remains unresolved",
			call: callgraph.FunctionCall{
				Callee:    keyGeneratorInit,
				FilePath:  "KeyFlow.java",
				Line:      6,
				Arguments: []string{"keyBits"},
				ArgumentSources: [][]callgraph.SourceNode{{
					{Type: "VALUE", Value: "128"},
					{Type: "VALUE", Value: "256"},
				}},
			},
			parameterType:  "int",
			wantProvenance: "unknown",
		},
		{
			name: "same arity non-int overload is excluded",
			call: callgraph.FunctionCall{
				Callee:    keyGeneratorInit,
				FilePath:  "KeyFlow.java",
				Line:      7,
				Arguments: []string{"parameters"},
			},
			parameterType: "java.security.spec.AlgorithmParameterSpec",
			wantAbsent:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller.Calls = []callgraph.FunctionCall{tt.call}
			graph.ExternalMethodSignatures = map[string][]callgraph.ExternalMethodSignature{
				callgraph.ExternalMethodSignatureKey(keyGeneratorInit): {{ParameterTypes: []string{tt.parameterType}, ReturnType: "void"}},
			}
			got := buildCryptoCall(ctx, graph, caller, &tt.call)
			if tt.wantAbsent {
				if got.ResolvedKeyLength != nil {
					t.Fatalf("ResolvedKeyLength = %#v, want nil for non-int overload", got.ResolvedKeyLength)
				}
			} else {
				if got.ResolvedKeyLength == nil {
					t.Fatal("ResolvedKeyLength = nil, want contract-scoped key length evidence")
				}
				if got.ResolvedKeyLength.Provenance != tt.wantProvenance {
					t.Fatalf("ResolvedKeyLength.Provenance = %q, want %q", got.ResolvedKeyLength.Provenance, tt.wantProvenance)
				}
				if tt.wantProvenance == "constant" {
					if got.ResolvedKeyLength.Bits == nil || *got.ResolvedKeyLength.Bits != tt.wantBits {
						t.Fatalf("ResolvedKeyLength.Bits = %#v, want %d", got.ResolvedKeyLength.Bits, tt.wantBits)
					}
				} else if got.ResolvedKeyLength.Bits != nil {
					t.Fatalf("ResolvedKeyLength.Bits = %#v, want nil for unresolved input", got.ResolvedKeyLength.Bits)
				}
				if got.ResolvedKeyLength.SourceCall.FunctionName != "javax.crypto.KeyGenerator.init" ||
					got.ResolvedKeyLength.SourceCall.Line != tt.call.Line ||
					got.ResolvedKeyLength.SourceCall.ParameterIndex != 0 {
					t.Fatalf("ResolvedKeyLength.SourceCall = %#v, want KeyGenerator.init line %d parameter 0", got.ResolvedKeyLength.SourceCall, tt.call.Line)
				}
			}

			fragment := BuildGraphFragmentExport(&engine.DepScanResult{
				CallGraph: graph,
				Ecosystem: "java",
				Report: &entities.InterimReport{Findings: []entities.Finding{{
					FilePath: "KeyFlow.java",
					Language: "java",
					CryptographicAssets: []entities.CryptographicAsset{{
						FindingID: "keygen-init",
						StartLine: tt.call.Line,
						EndLine:   tt.call.Line,
						Match:     "keyGenerator.init(keyBits)",
						Rules:     []entities.RuleInfo{{ID: "java.jca.keygenerator.init"}},
						Metadata:  map[string]string{"api": "javax.crypto.KeyGenerator.init"},
					}},
				}}},
			})
			if len(fragment.CryptoAnnotations) != 1 || fragment.CryptoAnnotations[0].CryptoCall == nil {
				t.Fatalf("fragment crypto annotations = %#v, want one matched call", fragment.CryptoAnnotations)
			}
			fragmentLength := fragment.CryptoAnnotations[0].CryptoCall.ResolvedKeyLength
			if tt.wantAbsent {
				if fragmentLength != nil {
					t.Fatalf("fragment ResolvedKeyLength = %#v, want nil for non-int overload", fragmentLength)
				}
				return
			}
			if fragmentLength == nil || fragmentLength.Provenance != tt.wantProvenance {
				t.Fatalf("fragment ResolvedKeyLength = %#v, want provenance=%q", fragmentLength, tt.wantProvenance)
			}
			if tt.wantProvenance == "constant" {
				if fragmentLength.Bits == nil || *fragmentLength.Bits != tt.wantBits {
					t.Fatalf("fragment ResolvedKeyLength.Bits = %#v, want %d", fragmentLength.Bits, tt.wantBits)
				}
			} else if fragmentLength.Bits != nil {
				t.Fatalf("fragment ResolvedKeyLength.Bits = %#v, want nil", fragmentLength.Bits)
			}
		})
	}
}
