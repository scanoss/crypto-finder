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

// Package wiring checks the embedded contracts KB against what the
// static-engine parsers emit: each library's calls must resolve to the
// contracts the KB declares for them.
package wiring

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/static-engine/callgraph"

	cfcontracts "github.com/scanoss/crypto-finder/internal/contracts"
)

// Ecosystem names as the engine spells them.
const (
	ecosystemCPP  = "cpp"
	ecosystemNode = "node"
	ecosystemRust = "rust"
)

func TestMain(m *testing.M) {
	cfcontracts.RegisterAll()
	os.Exit(m.Run())
}

// splitMethodArity returns the KB lookup key (FQN method name) and numeric
// arity of a call identity, the way the engine's inference pass derives them,
// e.g. FunctionID{Package:"javax.crypto", Type:"KeyGenerator",
// Name:"generateKey#0"} gives ("javax.crypto.KeyGenerator.generateKey", 0).
// It mirrors the engine's unexported helper of the same name.
func splitMethodArity(id *callgraph.FunctionID) (string, int) {
	name := id.Name
	arity := -1
	if idx := strings.LastIndex(name, "#"); idx >= 0 {
		arityStr := name[idx+1:]
		n := 0
		valid := arityStr != ""
		for _, ch := range arityStr {
			if ch < '0' || ch > '9' {
				valid = false
				break
			}
			n = n*10 + int(ch-'0')
		}
		if valid {
			arity = n
			name = name[:idx]
		}
	}
	if id.Type != "" {
		name = id.Type + "." + name
	}
	if id.Package == "" {
		return name, arity
	}
	return id.Package + "." + name, arity
}

// cppContractMethod returns the KB key of a C++ member call: its type and
// base method name. It mirrors the engine's unexported helper of the same
// name.
func cppContractMethod(id *callgraph.FunctionID) string {
	if id == nil || id.Type == "" {
		return ""
	}
	return id.Type + "." + callgraph.BaseFunctionName(id.Name)
}

// buildCPPFunctions builds the call graph of one C++ translation unit (include
// followed by body) through the engine's builder, which resolves fluent chain
// links through the registered contracts, and returns its functions.
func buildCPPFunctions(t *testing.T, include, body string) []*callgraph.FunctionDecl {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(include+body), 0o644); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemCPP, callgraph.NewCPPParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fns := make([]*callgraph.FunctionDecl, 0, len(graph.Functions))
	for _, fn := range graph.Functions {
		fns = append(fns, fn)
	}
	return fns
}

// buildGoGraph builds the call graph of one Go source file.
func buildGoGraph(t *testing.T, src string) *callgraph.CallGraph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	g, err := callgraph.NewBuilderForEcosystem("go", callgraph.NewGoParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return g
}

// goCalleeKeys lists the callee identity of every call in the graph.
func goCalleeKeys(g *callgraph.CallGraph) []string {
	var keys []string
	for _, fn := range g.Functions {
		for i := range fn.Calls {
			keys = append(keys, fn.Calls[i].Callee.String())
		}
	}
	return keys
}

// buildNodeGraph builds the call graph of one JavaScript source file.
func buildNodeGraph(t *testing.T, src string) *callgraph.CallGraph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// keysOf returns the keys of m in sorted order.
func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildPythonGraph builds the call graph of the given Python files with the
// contract type resolver.
func buildPythonGraph(t *testing.T, files map[string]string, importPath string) (*callgraph.CallGraph, error) {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	resolver := callgraph.NewPythonContractTypeResolverFromEmbedded()
	b.SetTypeResolver(resolver)
	return b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
}
