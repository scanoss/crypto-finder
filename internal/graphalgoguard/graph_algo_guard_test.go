// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphalgoguard_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/javaruntime"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/internal/scan"
)

var (
	updateGraphAlgoGolden = flag.Bool("update", false, "rewrite the graph algorithm guard golden; refused while an ecosystem whose graph changed keeps the golden's id unless -force")
	forceGraphAlgoGolden  = flag.Bool("force", false, "with -update, rewrite the golden without a graph algorithm id bump: for edits to the guard's fixtures, or a change the PR explains does not invalidate cached graphs")
)

const (
	graphAlgoCorpusDir  = "testdata/graph_algo_guard"
	graphAlgoGoldenPath = "testdata/graph_algo_guard.golden.json"
	graphAlgoRootToken  = "$CORPUS"
)

// graphAlgoCorpus is one application plus one dependency per ecosystem with a
// call graph parser, laid out under graphAlgoCorpusDir/<ecosystem>/{app,dep}
// and handed to the builder the way the dependency scanner does. Java builds
// without its bytecode type resolver: that resolver reads the host JDK and
// ~/.m2, so its output depends on the machine.
var graphAlgoCorpus = []struct {
	ecosystem         string
	appImport         string
	depImport         string
	dependencyVersion string
	typeResolver      bool
}{
	{ecosystem: "c", appImport: "app", depImport: "dep", dependencyVersion: "1.0.0", typeResolver: true},
	{ecosystem: "cpp", appImport: "app", depImport: "dep", dependencyVersion: "1.0.0", typeResolver: true},
	{ecosystem: "go", appImport: "example.com/app", depImport: "example.com/dep", dependencyVersion: "v1.0.0", typeResolver: true},
	{ecosystem: "java", appImport: "com.acme.app", depImport: "com.acme.dep", dependencyVersion: "1.0.0"},
	{ecosystem: "node", appImport: "app", depImport: "dep", dependencyVersion: "1.0.0", typeResolver: true},
	{ecosystem: "python", appImport: "", depImport: "signer", dependencyVersion: "1.0.0", typeResolver: true},
	{ecosystem: "ruby", appImport: "app", depImport: "signer", dependencyVersion: "1.0.0", typeResolver: true},
	{ecosystem: "rust", appImport: "app", depImport: "dep", dependencyVersion: "1.0.0", typeResolver: true},
}

// structuralGraph is the part of a graph-fragment export that consumers cache
// under GraphAlgoVersion. Scan metadata (timestamps, tool and rules versions),
// crypto annotations, supporting calls and crypto entry points are left out:
// they come from detection and are recomputed by annotate against the cached
// structure.
type structuralGraph struct {
	Functions     []graphfrag.GraphFragmentFunction `json:"functions"`
	InternalEdges []graphfrag.GraphFragmentEdge     `json:"internal_edges"`
	ExternalCalls []graphfrag.GraphFragmentExternal `json:"external_calls"`
	// Imports are Python's, Node's, Rust's and C's, exports Python's; a graph
	// without them hashes as before.
	Imports map[string][]graphfrag.GraphFragmentImport `json:"imports,omitempty"`
	Exports map[string]string                          `json:"exports,omitempty"`
	// PythonFacts are the fragment sections only GraphAlgoVersionPython
	// covers (Java's have their schema version), hashed for Python alone.
	PythonFacts *pythonFacts `json:"python_facts,omitempty"`
	// RustFacts are the fragment sections of a Rust graph beyond its calls
	// and imports, which GraphAlgoVersionRust covers, hashed for Rust alone.
	RustFacts *rustFacts `json:"rust_facts,omitempty"`
	// GoFacts are the sections GraphAlgoVersionGo covers beyond the calls,
	// hashed for Go alone.
	GoFacts *goFacts `json:"go_facts,omitempty"`
	// CFacts are the sections GraphAlgoVersionC and GraphAlgoVersionCPP
	// cover beyond the calls and includes, hashed for C and C++ alone.
	CFacts *cFacts `json:"c_facts,omitempty"`
}

// cFacts are the fragment sections of a C or C++ graph beyond its calls and
// includes (graph-fragment-1.37).
type cFacts struct {
	Declarations    []graphfrag.GraphFragmentDeclaration       `json:"declarations,omitempty"`
	AttributeStores []graphfrag.GraphFragmentAttributeStore    `json:"attribute_stores,omitempty"`
	Strings         map[string][]graphfrag.GraphFragmentString `json:"strings,omitempty"`
}

// rustFacts are the fragment sections of a Rust graph beyond its calls and
// imports.
type rustFacts struct {
	Items        map[string][]graphfrag.GraphFragmentItem `json:"items,omitempty"`
	ConstantRefs []graphfrag.GraphFragmentConstantRef     `json:"constant_refs,omitempty"`
	Declarations []graphfrag.GraphFragmentDeclaration     `json:"declarations,omitempty"`
	// PublicTypePaths: the paths `pub use` items re-export types under, and
	// CallAnchors and RebindLines: the parser's calls (graph-algo-rs-13).
	PublicTypePaths map[string][]string                 `json:"public_type_paths,omitempty"`
	CallAnchors     []graphfrag.GraphFragmentCallAnchor `json:"call_anchors,omitempty"`
	RebindLines     []graphfrag.GraphFragmentRebind     `json:"rebind_lines,omitempty"`
}

// goFacts are the fragment sections of a Go graph beyond its calls.
type goFacts struct {
	ConstantRefs []graphfrag.GraphFragmentConstantRef `json:"constant_refs,omitempty"`
	Declarations []graphfrag.GraphFragmentDeclaration `json:"declarations,omitempty"`
	CallAnchors  []graphfrag.GraphFragmentCallAnchor  `json:"call_anchors,omitempty"`
	RebindLines  []graphfrag.GraphFragmentRebind      `json:"rebind_lines,omitempty"`
	// Imports: the import specs of each file (graph-fragment-1.32).
	Imports map[string][]graphfrag.GraphFragmentImport `json:"imports,omitempty"`
	// GoValues: composite literals, new(T) and field stores (graph-fragment-1.34).
	GoValues map[string][]graphfrag.GraphFragmentGoValue `json:"go_values,omitempty"`
}

// pythonFacts are the fragment sections of a Python graph beyond its calls.
type pythonFacts struct {
	ConstantRefs    []graphfrag.GraphFragmentConstantRef    `json:"constant_refs,omitempty"`
	AttributeStores []graphfrag.GraphFragmentAttributeStore `json:"attribute_stores,omitempty"`
	Declarations    []graphfrag.GraphFragmentDeclaration    `json:"declarations,omitempty"`
	Casts           []graphfrag.GraphFragmentCast           `json:"casts,omitempty"`
	CallAnchors     []graphfrag.GraphFragmentCallAnchor     `json:"call_anchors,omitempty"`
	RebindLines     []graphfrag.GraphFragmentRebind         `json:"rebind_lines,omitempty"`
	LocalBindings   []graphfrag.GraphFragmentLocalBinding   `json:"local_bindings,omitempty"`
	PublicPaths     map[string]string                       `json:"public_paths,omitempty"`
}

type ecosystemDigest struct {
	// GraphAlgoVersion is the id the ecosystem's graphs are stamped with
	// (graphfrag.GraphAlgoVersionFor).
	GraphAlgoVersion string `json:"graph_algo_version"`
	SHA256           string `json:"sha256"`
	Functions        int    `json:"functions"`
	InternalEdges    int    `json:"internal_edges"`
	ExternalCalls    int    `json:"external_calls"`
}

type graphAlgoGolden struct {
	Ecosystems map[string]ecosystemDigest `json:"ecosystems"`
}

// TestGraphAlgoVersionGuard fails when the structural graph of an ecosystem's
// fixed corpus changes while that ecosystem's graph algorithm id
// (graphfrag.GraphAlgoVersionFor) stays the same. Consumers such as the mining
// service key cached structural graphs on the id, so a construction change
// without a bump leaves them serving stale graphs; a bump for an ecosystem
// whose graph did not change re-mines its graphs for nothing.
func TestGraphAlgoVersionGuard(t *testing.T) {
	current := graphAlgoGolden{Ecosystems: map[string]ecosystemDigest{}}
	for _, c := range graphAlgoCorpus {
		current.Ecosystems[c.ecosystem] = digestCorpusEcosystem(t, c.ecosystem, c.appImport, c.depImport, c.dependencyVersion, c.typeResolver)
	}

	golden, err := readGraphAlgoGolden()
	if err != nil {
		t.Fatalf("read %s: %v", graphAlgoGoldenPath, err)
	}
	problem := compareGraphAlgoGolden(golden, current)
	if problem == "" {
		return
	}
	if *updateGraphAlgoGolden && (golden == nil || len(unbumpedEcosystems(golden.Ecosystems, current.Ecosystems)) == 0 || *forceGraphAlgoGolden) {
		writeGraphAlgoGolden(t, current)
		t.Logf("rewrote %s", graphAlgoGoldenPath)
		return
	}
	t.Fatal(problem)
}

func compareGraphAlgoGolden(golden *graphAlgoGolden, current graphAlgoGolden) string {
	if golden == nil {
		return fmt.Sprintf("%s is missing; record it with: go test ./internal/graphalgoguard/ -run TestGraphAlgoVersionGuard -update", graphAlgoGoldenPath)
	}
	if unbumped := unbumpedEcosystems(golden.Ecosystems, current.Ecosystems); len(unbumped) > 0 {
		return fmt.Sprintf(`the structural graph changed without a bump of its ecosystem's graph algorithm id.
Changed ecosystems:
%s
Consumers cache structural graphs keyed on the id, so they keep serving the old graph.
Bump the named constant in github.com/scanoss/reach/graphfrag (only that ecosystem's), add a changelog.d fragment, then run:
  go test ./internal/graphalgoguard/ -run TestGraphAlgoVersionGuard -update
If only the guard's fixtures changed, or you can explain in the PR why cached graphs stay valid, run with -update -force instead.`,
			strings.Join(unbumped, "\n"))
	}
	if changed := changedEcosystems(golden.Ecosystems, current.Ecosystems); len(changed) > 0 {
		return fmt.Sprintf(`the graph algorithm ids or graphs differ from %s:
%s
Record them with: go test ./internal/graphalgoguard/ -run TestGraphAlgoVersionGuard -update`, graphAlgoGoldenPath, strings.Join(changed, "\n"))
	}
	return ""
}

// unbumpedEcosystems describes each ecosystem whose structural graph differs
// from the golden while its graph algorithm id does not.
func unbumpedEcosystems(want, got map[string]ecosystemDigest) []string {
	var out []string
	for _, name := range ecosystemNames(want, got) {
		w, g := want[name], got[name]
		if w.GraphAlgoVersion == g.GraphAlgoVersion && !sameGraph(w, g) {
			out = append(out, fmt.Sprintf("  %s (%s, %s): %s", name, graphAlgoConstant(name), g.GraphAlgoVersion, describeGraphChange(w, g)))
		}
	}
	return out
}

// changedEcosystems describes each ecosystem whose id or graph differs from
// the golden.
func changedEcosystems(want, got map[string]ecosystemDigest) []string {
	var out []string
	for _, name := range ecosystemNames(want, got) {
		w, g := want[name], got[name]
		if w != g {
			out = append(out, fmt.Sprintf("  %s: %s -> %s, %s", name, w.GraphAlgoVersion, g.GraphAlgoVersion, describeGraphChange(w, g)))
		}
	}
	return out
}

func ecosystemNames(want, got map[string]ecosystemDigest) []string {
	names := make([]string, 0, len(want)+len(got))
	for name := range want {
		names = append(names, name)
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func sameGraph(a, b ecosystemDigest) bool {
	a.GraphAlgoVersion, b.GraphAlgoVersion = "", ""
	return a == b
}

func describeGraphChange(w, g ecosystemDigest) string {
	return fmt.Sprintf("functions %d -> %d, internal edges %d -> %d, external calls %d -> %d, sha256 %.12s -> %.12s",
		w.Functions, g.Functions, w.InternalEdges, g.InternalEdges, w.ExternalCalls, g.ExternalCalls, w.SHA256, g.SHA256)
}

// graphAlgoConstant names the constant that holds ecosystem's graph algorithm
// id, for the guard's message.
func graphAlgoConstant(ecosystem string) string {
	switch graphfrag.GraphAlgoVersionFor(ecosystem) {
	case graphfrag.GraphAlgoVersionPython:
		return "GraphAlgoVersionPython"
	case graphfrag.GraphAlgoVersionRust:
		return "GraphAlgoVersionRust"
	case graphfrag.GraphAlgoVersionNode:
		return "GraphAlgoVersionNode"
	case graphfrag.GraphAlgoVersionGo:
		return "GraphAlgoVersionGo"
	}
	return "GraphAlgoVersion"
}

func digestCorpusEcosystem(t *testing.T, ecosystem, appImport, depImport, depVersion string, withTypeResolver bool) ecosystemDigest {
	t.Helper()
	root, err := filepath.Abs(filepath.Join(graphAlgoCorpusDir, ecosystem))
	if err != nil {
		t.Fatal(err)
	}
	parser := callgraph.NewParserForEcosystem(ecosystem)
	if parser == nil {
		t.Fatalf("no call graph parser for %s", ecosystem)
	}
	builder := callgraph.NewBuilderForEcosystem(ecosystem, parser)
	if withTypeResolver {
		if resolver := callgraph.NewTypeResolverForEcosystem(ecosystem, javaruntime.Config{}); resolver != nil {
			builder.SetTypeResolver(resolver)
		}
		if ecosystem == "go" {
			// The corpus's own types module stands in for GOROOT, so the digest
			// does not depend on the toolchain installed where the guard runs.
			builder.SetTypeResolver(callgraph.NewGoSourceTypeResolver([]callgraph.GoSourceRoot{
				{Dir: filepath.Join(root, "types"), Module: "example.com/types"},
			}))
		}
	}
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{
		{Dir: filepath.Join(root, "app"), ImportPath: appImport},
		{Dir: filepath.Join(root, "dep"), ImportPath: depImport, Version: depVersion},
	}, nil)
	if err != nil {
		t.Fatalf("%s: build call graph: %v", ecosystem, err)
	}
	export := scan.BuildGraphFragmentExport(&engine.DepScanResult{
		CallGraph:   graph,
		RootModule:  appImport,
		Ecosystem:   ecosystem,
		ProjectRoot: filepath.Join(root, "app"),
	}, &oid.ResolvedReport{})
	if len(export.Functions) == 0 {
		t.Fatalf("%s: corpus produced no functions", ecosystem)
	}
	if got, want := export.ScanMetadata.GraphAlgoVersion, graphfrag.GraphAlgoVersionFor(ecosystem); got != want {
		t.Fatalf("%s: export stamps graph_algo_version %q, want %q", ecosystem, got, want)
	}

	data, err := json.Marshal(structuralGraph{
		Functions:     export.Functions,
		InternalEdges: export.InternalEdges,
		ExternalCalls: export.ExternalCalls,
		Imports:       export.Imports,
		Exports:       export.Exports,
		PythonFacts:   pythonFactsOf(ecosystem, &export),
		RustFacts:     rustFactsOf(ecosystem, &export),
		GoFacts:       goFactsOf(ecosystem, &export),
		CFacts:        cFactsOf(ecosystem, &export),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Dependency paths stay absolute in the export; hash them relative to the
	// corpus so the digest does not depend on where the checkout lives.
	for _, prefix := range []string{root + string(filepath.Separator), filepath.ToSlash(root) + "/"} {
		quoted, err := json.Marshal(prefix)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.ReplaceAll(data, quoted[1:len(quoted)-1], []byte(graphAlgoRootToken+"/"))
	}
	sum := sha256.Sum256(data)
	return ecosystemDigest{
		GraphAlgoVersion: export.ScanMetadata.GraphAlgoVersion,
		SHA256:           hex.EncodeToString(sum[:]),
		Functions:        len(export.Functions),
		InternalEdges:    len(export.InternalEdges),
		ExternalCalls:    len(export.ExternalCalls),
	}
}

// pythonFactsOf is a Python export's pythonFacts, nil for another ecosystem.
func pythonFactsOf(ecosystem string, export *graphfrag.GraphFragmentExport) *pythonFacts {
	if ecosystem != "python" {
		return nil
	}
	return &pythonFacts{
		ConstantRefs: export.ConstantRefs, AttributeStores: export.AttributeStores,
		Declarations: export.Declarations, Casts: export.Casts,
		CallAnchors: export.CallAnchors, RebindLines: export.RebindLines,
		LocalBindings: export.LocalBindings, PublicPaths: export.PublicPaths,
	}
}

// rustFactsOf is a Rust export's rustFacts, nil for another ecosystem.
func rustFactsOf(ecosystem string, export *graphfrag.GraphFragmentExport) *rustFacts {
	if ecosystem != "rust" {
		return nil
	}
	return &rustFacts{
		Items: export.Items, ConstantRefs: export.ConstantRefs, Declarations: export.Declarations,
		PublicTypePaths: export.PublicTypePaths, CallAnchors: export.CallAnchors, RebindLines: export.RebindLines,
	}
}

// goFactsOf is a Go export's goFacts, nil for another ecosystem.
func goFactsOf(ecosystem string, export *graphfrag.GraphFragmentExport) *goFacts {
	if ecosystem != "go" {
		return nil
	}
	return &goFacts{
		ConstantRefs: export.ConstantRefs, Declarations: export.Declarations,
		CallAnchors: export.CallAnchors, RebindLines: export.RebindLines,
		Imports: export.Imports, GoValues: export.GoValues,
	}
}

// cFactsOf is a C or C++ export's cFacts, nil for another ecosystem.
func cFactsOf(ecosystem string, export *graphfrag.GraphFragmentExport) *cFacts {
	if ecosystem != "c" && ecosystem != "cpp" {
		return nil
	}
	return &cFacts{Declarations: export.Declarations, AttributeStores: export.AttributeStores, Strings: export.Strings}
}

func readGraphAlgoGolden() (*graphAlgoGolden, error) {
	data, err := os.ReadFile(graphAlgoGoldenPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var golden graphAlgoGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		return nil, err
	}
	return &golden, nil
}

func writeGraphAlgoGolden(t *testing.T, golden graphAlgoGolden) {
	t.Helper()
	data, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graphAlgoGoldenPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
