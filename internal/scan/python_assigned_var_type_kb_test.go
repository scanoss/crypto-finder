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
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

// TestContractMatchesForCall_PythonAssignedVarType_DottedReturnSplits (G1,
// PR #310 phase-2 review) pins that a dotted KB-declared return type
// ("cryptography.hazmat.primitives.ciphers.Cipher") propagated through
// propagatePythonAssignedVarTypesForDecl splits into Package/Type instead
// of being glued whole into Callee.Type — so a later `c.encryptor()` call
// still matches the `Cipher.encryptor` KB contract end to end (scan-level
// contract lookup, keyed by fullFunctionName(call.Callee)).
func TestContractMatchesForCall_PythonAssignedVarType_DottedReturnSplits(t *testing.T) {
	appDir := t.TempDir()
	depDir := t.TempDir()

	// A minimal stand-in for the real cryptography package: __init__ has no
	// declared return type (matching the real library), so
	// PythonContractTypeResolver must fill it in from the embedded KB's
	// dotted `return.type` before propagation can see it.
	depSrc := `class Cipher:
    def __init__(self, algorithm, mode):
        pass

    def encryptor(self):
        pass
`
	appSrc := `from cryptography.hazmat.primitives.ciphers import Cipher


def run(algorithm, mode):
    c = Cipher(algorithm, mode)
    return c.encryptor()
`
	if err := os.WriteFile(filepath.Join(depDir, "__init__.py"), []byte(depSrc), 0o600); err != nil {
		t.Fatalf("write dep __init__.py: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "app.py"), []byte(appSrc), 0o600); err != nil {
		t.Fatalf("write app.py: %v", err)
	}

	builder := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	builder.SetTypeResolver(callgraph.NewPythonTypeResolverChain())
	roots := []callgraph.PackageDir{
		{Dir: appDir, ImportPath: "app"},
		{Dir: depDir, ImportPath: "cryptography.hazmat.primitives.ciphers", Version: "50.0.1"},
	}
	graph, err := builder.BuildFromDirectories(roots, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	run := graph.Functions["app.run"]
	if run == nil {
		t.Fatalf("missing app.run; functions=%v", sortedGraphFunctionKeys(graph))
	}
	var call *callgraph.FunctionCall
	for i := range run.Calls {
		if run.Calls[i].Callee.Name == "encryptor" {
			call = &run.Calls[i]
			break
		}
	}
	if call == nil {
		t.Fatalf("c.encryptor() call not found among %#v", run.Calls)
	}

	wantCallee := callgraph.FunctionID{
		Package: "cryptography.hazmat.primitives.ciphers",
		Type:    "Cipher",
		Name:    "encryptor",
	}
	if call.Callee != wantCallee {
		t.Fatalf("Callee = %+v, want %+v (dotted return type must split into Package/Type)", call.Callee, wantCallee)
	}

	ctx := newExportBuildContext(&engine.DepScanResult{CallGraph: graph, Ecosystem: "python"})
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	if len(matches) == 0 {
		t.Fatal("contractMatchesForCall returned no matches — the dotted-return-type propagation broke the KB chain")
	}
	found := false
	for i := range matches {
		if matches[i].Method == "cryptography.hazmat.primitives.ciphers.Cipher.encryptor" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no match for cryptography.hazmat.primitives.ciphers.Cipher.encryptor among %#v", matches)
	}
}

func sortedGraphFunctionKeys(graph *callgraph.CallGraph) []string {
	keys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		keys = append(keys, key)
	}
	return keys
}
