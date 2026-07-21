// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package scan

import (
	"reflect"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

// TestBuildCallSiteParameters verifies that buildCallSiteParameters produces
// the same parameter/source_node output as the inline mergeCallParameters path
// for three representative FunctionCall fixtures.
func TestBuildCallSiteParameters(t *testing.T) {
	t.Parallel()

	calleeID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	callerID := callgraph.FunctionID{Package: "com.app", Type: "Service", Name: "init#0"}

	// A minimal graph: callerID calls calleeID.
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			callerID.String(): {
				ID:        callerID,
				FilePath:  "Service.java",
				StartLine: 1,
				EndLine:   10,
				Calls:     []callgraph.FunctionCall{},
			},
			calleeID.String(): {
				ID:        calleeID,
				FilePath:  "Cipher.java",
				StartLine: 1,
				EndLine:   3,
				Parameters: []callgraph.FunctionParameter{
					{Type: "String"},
				},
				ReturnType: "Cipher",
			},
		},
		Callers: map[string][]string{
			calleeID.String(): {callerID.String()},
		},
	}

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph:   graph,
		ProjectRoot: "/project",
		RootModule:  "com.app:app",
		Ecosystem:   "java",
	})

	tests := []struct {
		name string
		call callgraph.FunctionCall
		want []callGraphParameter
	}{
		{
			name: "no-args",
			call: callgraph.FunctionCall{
				Callee:   calleeID,
				FilePath: "Service.java",
				Line:     5,
			},
			// mergeCallParameters with no args and one declared param type returns one parameter
			// with just the Type field, but only if Type != "".
			want: func() []callGraphParameter {
				callee := graph.Functions[calleeID.String()]
				return mergeCallParameters(ctx, nil, &calleeID, callee, nil, nil, "Service.java", 5)
			}(),
		},
		{
			name: "scalar-arg",
			call: callgraph.FunctionCall{
				Callee:    calleeID,
				FilePath:  "Service.java",
				Line:      5,
				Arguments: []string{`"AES"`},
			},
			want: func() []callGraphParameter {
				callee := graph.Functions[calleeID.String()]
				return mergeCallParameters(ctx, nil, &calleeID, callee, []string{`"AES"`}, nil, "Service.java", 5)
			}(),
		},
		{
			name: "recursive-PARAMETER-CALL_RESULT-source-node",
			call: callgraph.FunctionCall{
				Callee:    calleeID,
				FilePath:  "Service.java",
				Line:      5,
				Arguments: []string{"algo"},
				ArgumentSources: [][]callgraph.SourceNode{
					{
						{
							Type:           "PARAMETER",
							Name:           "algo",
							ParameterIndex: 0,
							SourceNodes: []callgraph.SourceNode{
								{
									Type:       "CALL_RESULT",
									Name:       "getAlgo",
									CallTarget: &callgraph.FunctionID{Package: "com.app", Type: "Util", Name: "getAlgo#0"},
								},
							},
						},
					},
				},
			},
			want: func() []callGraphParameter {
				callee := graph.Functions[calleeID.String()]
				argSources := [][]callgraph.SourceNode{
					{
						{
							Type:           "PARAMETER",
							Name:           "algo",
							ParameterIndex: 0,
							SourceNodes: []callgraph.SourceNode{
								{
									Type:       "CALL_RESULT",
									Name:       "getAlgo",
									CallTarget: &callgraph.FunctionID{Package: "com.app", Type: "Util", Name: "getAlgo#0"},
								},
							},
						},
					},
				}
				return mergeCallParameters(ctx, nil, &calleeID, callee, []string{"algo"}, argSources, "Service.java", 5)
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildCallSiteParameters(ctx, &tc.call)

			if len(got) != len(tc.want) {
				t.Fatalf("buildCallSiteParameters(%q) len = %d, want %d; got = %#v, want = %#v",
					tc.name, len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if got[i].ParameterIndex != tc.want[i].ParameterIndex {
					t.Errorf("[%d] ParameterIndex = %d, want %d", i, got[i].ParameterIndex, tc.want[i].ParameterIndex)
				}
				if got[i].Type != tc.want[i].Type {
					t.Errorf("[%d] Type = %q, want %q", i, got[i].Type, tc.want[i].Type)
				}
				if got[i].ArgumentExpression != tc.want[i].ArgumentExpression {
					t.Errorf("[%d] ArgumentExpression = %q, want %q", i, got[i].ArgumentExpression, tc.want[i].ArgumentExpression)
				}
				if got[i].VariableName != tc.want[i].VariableName {
					t.Errorf("[%d] VariableName = %q, want %q", i, got[i].VariableName, tc.want[i].VariableName)
				}
				if got[i].ResolvedValue != tc.want[i].ResolvedValue {
					t.Errorf("[%d] ResolvedValue = %q, want %q", i, got[i].ResolvedValue, tc.want[i].ResolvedValue)
				}
				if !reflect.DeepEqual(got[i].SourceNodes, tc.want[i].SourceNodes) {
					t.Errorf("[%d] SourceNodes mismatch:\n got: %#v\nwant: %#v", i, got[i].SourceNodes, tc.want[i].SourceNodes)
				}
			}
		})
	}
}
