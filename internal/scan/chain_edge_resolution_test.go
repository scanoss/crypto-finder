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

// TestMaterializeCallChainNodes_RecordsEntryResolution proves each exported
// chain step says how the edge arriving at it was resolved: exact for a call
// whose target is certain, interface_dispatch (with the interface as declared
// type) for an implementation reached through an interface call.
func TestMaterializeCallChainNodes_RecordsEntryResolution(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"com/dep/Sink.java":          "package com.dep;\npublic interface Sink {\n  void run();\n}\n",
		"com/dep/impl/SinkImpl.java": "package com.dep.impl;\nimport com.dep.Sink;\npublic class SinkImpl implements Sink {\n  public void run() {}\n}\n",
		"com/app/App.java":           "package com.app;\nimport com.dep.Sink;\npublic class App {\n  public void go(Sink sink) {\n    sink.run();\n  }\n}\n",
	}
	for rel, src := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := newExportBuildContext(&engine.DepScanResult{CallGraph: graph, ProjectRoot: root, Ecosystem: "java"})

	caller := callgraph.FunctionID{Package: "com.app", Type: "App", Name: "go#1"}
	callerStep := callgraph.CallChainStep{Function: caller, FilePath: filepath.Join(root, "com", "app", "App.java"), Line: 5}
	iface := callgraph.CallChainStep{Function: callgraph.FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"}}
	impl := callgraph.CallChainStep{Function: callgraph.FunctionID{Package: "com.dep.impl", Type: "SinkImpl", Name: "run#0"}}

	chains := materializeCallChainNodes(ctx, []callgraph.CallChain{
		{Steps: []callgraph.CallChainStep{callerStep, iface}},
		{Steps: []callgraph.CallChainStep{callerStep, impl}},
	})

	if got := chains[0][0].EntryResolution; got != "" {
		t.Errorf("first frame entry_resolution = %q, want empty (no call arrives at it)", got)
	}
	if got := chains[0][1].EntryResolution; got != string(callgraph.EdgeKindExact) {
		t.Errorf("interface method frame entry_resolution = %q, want exact", got)
	}
	if got := chains[0][1].EntryDeclaredType; got != "" {
		t.Errorf("exact frame entry_declared_type = %q, want empty", got)
	}
	if got := chains[1][1].EntryResolution; got != string(callgraph.EdgeKindInterfaceDispatch) {
		t.Errorf("implementation frame entry_resolution = %q, want interface_dispatch", got)
	}
	if got := chains[1][1].EntryDeclaredType; got != "com.dep.Sink" {
		t.Errorf("implementation frame entry_declared_type = %q, want com.dep.Sink", got)
	}
}
