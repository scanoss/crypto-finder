// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag_test

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

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

var (
	updateGraphAlgoGolden = flag.Bool("update", false, "rewrite the GraphAlgoVersion guard golden; refused while GraphAlgoVersion still equals the golden's version unless -force")
	forceGraphAlgoGolden  = flag.Bool("force", false, "with -update, rewrite the golden without a GraphAlgoVersion bump: for edits to the guard's fixtures, or a change the PR explains does not invalidate cached graphs")
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
}

type ecosystemDigest struct {
	SHA256        string `json:"sha256"`
	Functions     int    `json:"functions"`
	InternalEdges int    `json:"internal_edges"`
	ExternalCalls int    `json:"external_calls"`
}

type graphAlgoGolden struct {
	GraphAlgoVersion string                     `json:"graph_algo_version"`
	Ecosystems       map[string]ecosystemDigest `json:"ecosystems"`
}

// TestGraphAlgoVersionGuard fails when the structural graph of a fixed corpus
// changes while GraphAlgoVersion stays the same. Consumers such as the mining
// service key cached structural graphs on GraphAlgoVersion, so a construction
// change without a bump leaves them serving stale graphs.
func TestGraphAlgoVersionGuard(t *testing.T) {
	current := graphAlgoGolden{GraphAlgoVersion: graphfrag.GraphAlgoVersion, Ecosystems: map[string]ecosystemDigest{}}
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
	if *updateGraphAlgoGolden && (golden == nil || golden.GraphAlgoVersion != current.GraphAlgoVersion || *forceGraphAlgoGolden) {
		writeGraphAlgoGolden(t, current)
		t.Logf("rewrote %s for %s", graphAlgoGoldenPath, current.GraphAlgoVersion)
		return
	}
	t.Fatal(problem)
}

func compareGraphAlgoGolden(golden *graphAlgoGolden, current graphAlgoGolden) string {
	if golden == nil {
		return fmt.Sprintf("%s is missing; record it with: go test ./pkg/graphfrag/ -run TestGraphAlgoVersionGuard -update", graphAlgoGoldenPath)
	}
	changed := changedEcosystems(golden.Ecosystems, current.Ecosystems)
	if golden.GraphAlgoVersion != current.GraphAlgoVersion {
		return fmt.Sprintf("GraphAlgoVersion is %q but %s pins %q; record the new version with: go test ./pkg/graphfrag/ -run TestGraphAlgoVersionGuard -update",
			current.GraphAlgoVersion, graphAlgoGoldenPath, golden.GraphAlgoVersion)
	}
	if len(changed) == 0 {
		return ""
	}
	return fmt.Sprintf(`the structural graph changed without a GraphAlgoVersion bump.
Changed ecosystems:
%s
Consumers cache structural graphs keyed on GraphAlgoVersion (%s), so they keep serving the old graph.
Bump GraphAlgoVersion in pkg/graphfrag/export.go, add a changelog.d fragment, then run:
  go test ./pkg/graphfrag/ -run TestGraphAlgoVersionGuard -update
If only the guard's fixtures changed, or you can explain in the PR why cached graphs stay valid, run with -update -force instead.`,
		strings.Join(changed, "\n"), current.GraphAlgoVersion)
}

func changedEcosystems(want, got map[string]ecosystemDigest) []string {
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
	var changed []string
	for _, name := range names {
		w, g := want[name], got[name]
		if w == g {
			continue
		}
		changed = append(changed, fmt.Sprintf("  %s: functions %d -> %d, internal edges %d -> %d, external calls %d -> %d, sha256 %.12s -> %.12s",
			name, w.Functions, g.Functions, w.InternalEdges, g.InternalEdges, w.ExternalCalls, g.ExternalCalls, w.SHA256, g.SHA256))
	}
	return changed
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

	data, err := json.Marshal(structuralGraph{
		Functions:     export.Functions,
		InternalEdges: export.InternalEdges,
		ExternalCalls: export.ExternalCalls,
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
		SHA256:        hex.EncodeToString(sum[:]),
		Functions:     len(export.Functions),
		InternalEdges: len(export.InternalEdges),
		ExternalCalls: len(export.ExternalCalls),
	}
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
