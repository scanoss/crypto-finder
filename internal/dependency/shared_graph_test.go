// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

func npmNode(name, version string) resolve.Node {
	return resolve.Node{ID: resolve.NodeID("pkg:npm/" + name + "@" + version), PURL: "pkg:npm/" + name, Version: version}
}

func direct(nodes ...resolve.Node) []resolve.Member {
	members := make([]resolve.Member, len(nodes))
	for i, node := range nodes {
		members[i] = resolve.Member{ID: node.ID, Direct: true}
	}
	return members
}

func indirect(nodes ...resolve.Node) []resolve.Member {
	members := direct(nodes...)
	for i := range members {
		members[i].Direct = false
	}
	return members
}

func edge(from, to resolve.Node) resolve.Edge {
	return resolve.Edge{From: from.ID, To: to.ID}
}

func completeGraph(members []resolve.Member, edges []resolve.Edge, nodes ...resolve.Node) resolve.Graph {
	return resolve.Graph{
		Nodes: nodes,
		Roots: []resolve.Root{{Manifest: "package.json", Status: resolve.StatusComplete, Members: members, Edges: edges}},
	}
}

func deps(refs ...Ref) []Dependency {
	out := make([]Dependency, len(refs))
	for i, ref := range refs {
		out[i] = Dependency{Module: ref.Module, Version: ref.Version}
	}
	return out
}

func assertSteps(t *testing.T, paths map[string]Path, key string, want []PathStep) {
	t.Helper()
	path, ok := paths[key]
	if !ok {
		t.Fatalf("paths[%q] missing; have %v", key, paths)
	}
	if !reflect.DeepEqual(path.Steps, want) {
		t.Errorf("paths[%q].Steps = %+v, want %+v", key, path.Steps, want)
	}
}

func TestResolvedPaths_DirectAndTransitiveCarryVersions(t *testing.T) {
	t.Parallel()
	a, b := npmNode("a", "1.0.0"), npmNode("b", "2.0.0")
	graph := completeGraph(append(direct(a), indirect(b)...), []resolve.Edge{edge(a, b)}, a, b)
	result := &ResolveResult{Dependencies: deps(Ref{"a", "1.0.0"}, Ref{"b", "2.0.0"})}
	parsed := map[string]bool{"a": true, "a@1.0.0": true, "b": true, "b@2.0.0": true}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "node", parsed)

	stepA := PathStep{Module: "a", Version: "1.0.0"}
	stepB := PathStep{Module: "b", Version: "2.0.0"}
	for _, key := range []string{"a", "a@1.0.0"} {
		assertSteps(t, paths, key, []PathStep{stepA})
	}
	for _, key := range []string{"b", "b@2.0.0"} {
		assertSteps(t, paths, key, []PathStep{stepA, stepB})
		if paths[key].WithoutSource {
			t.Errorf("paths[%q].WithoutSource = true, want false: every step was parsed", key)
		}
	}
}

func TestResolvedPaths_LocalWorkspaceNodeIsTheApplication(t *testing.T) {
	t.Parallel()
	workspace := resolve.Node{ID: "pkg:npm/web@0.1.0", PURL: "pkg:npm/web", Version: "0.1.0", Local: true}
	c := npmNode("c", "1.0.0")
	graph := completeGraph(append(direct(workspace), indirect(c)...), []resolve.Edge{edge(workspace, c)}, c, workspace)
	result := &ResolveResult{Dependencies: deps(Ref{"c", "1.0.0"})}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "node", nil)

	assertSteps(t, paths, "c", []PathStep{{Module: "c", Version: "1.0.0", WithoutSource: true}})
	if _, ok := paths["web"]; ok {
		t.Errorf("paths[web] = %+v, want none: a workspace member is the application", paths["web"])
	}
}

func TestResolvedPaths_LocalNodeResolvedAsDependencyStaysOnThePath(t *testing.T) {
	t.Parallel()
	fork := resolve.Node{ID: "pkg:golang/example.com/fork", PURL: "pkg:golang/example.com/fork", Local: true}
	cryptoNode := resolve.Node{ID: "pkg:golang/golang.org/x/crypto@v0.1.0", PURL: "pkg:golang/golang.org/x/crypto", Version: "v0.1.0"}
	graph := completeGraph(append(direct(fork), indirect(cryptoNode)...), []resolve.Edge{edge(fork, cryptoNode)}, cryptoNode, fork)
	result := &ResolveResult{Dependencies: deps(Ref{"example.com/fork", ""}, Ref{"golang.org/x/crypto", "v0.1.0"})}
	parsed := map[string]bool{"example.com/fork": true, "golang.org/x/crypto": true}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "go", parsed)

	assertSteps(t, paths, "golang.org/x/crypto", []PathStep{
		{Module: "example.com/fork"},
		{Module: "golang.org/x/crypto", Version: "v0.1.0"},
	})
}

func TestResolvedPaths_UnattributedMemberGetsNoPath(t *testing.T) {
	t.Parallel()
	a, orphan := npmNode("a", "1.0.0"), npmNode("orphan", "1.0.0")
	graph := completeGraph(append(direct(a), indirect(orphan)...), nil, a, orphan)
	result := &ResolveResult{
		RootModule:   "app",
		Dependencies: deps(Ref{"a", "1.0.0"}, Ref{"orphan", "1.0.0"}),
		Graph:        map[string][]string{"app": {"a", "orphan"}},
	}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "node", nil)

	if _, ok := Paths(result, nil)["orphan"]; !ok {
		t.Fatal("legacy Paths has no orphan entry; the test would not prove the legacy path is refused")
	}
	if path, ok := paths["orphan"]; ok {
		t.Errorf("paths[orphan] = %+v, want none: the shared graph knows it and does not attribute it", path)
	}
}

func TestResolvedPaths_NoUsableRootIsExactlyLegacy(t *testing.T) {
	t.Parallel()
	a, b := npmNode("a", "1.0.0"), npmNode("b", "2.0.0")
	result := &ResolveResult{
		RootModule:   "app",
		Dependencies: deps(Ref{"a", "1.0.0"}, Ref{"b", "2.0.0"}),
		Graph:        map[string][]string{"app": {"b"}, "b": {"a"}},
	}
	parsed := map[string]bool{"b": true}
	unknown := resolve.Graph{Roots: []resolve.Root{{Manifest: "package.json", Status: resolve.StatusUnknown, Reason: resolve.ReasonMalformed}}}
	edgesUnknown := resolve.Graph{
		Nodes: []resolve.Node{a, b},
		Roots: []resolve.Root{{
			Manifest: "build.gradle", Status: resolve.StatusPartial, Reason: resolve.ReasonEdgesUnknown,
			Members: direct(a, b),
		}},
	}

	got := ResolvedPaths([]resolve.Graph{unknown, edgesUnknown}, result, "node", parsed)

	if want := Paths(result, parsed); !reflect.DeepEqual(got, want) {
		t.Errorf("ResolvedPaths = %+v, want the legacy Paths %+v", got, want)
	}
}

func TestResolvedPaths_LegacyFillsOnlyModulesTheSharedGraphLacks(t *testing.T) {
	t.Parallel()
	a := npmNode("a", "1.0.0")
	graph := completeGraph(direct(a), nil, a)
	result := &ResolveResult{
		RootModule:   "app",
		Dependencies: deps(Ref{"a", "1.0.0"}, Ref{"z", "3.0.0"}, Ref{"y", "1.0.0"}),
		Graph:        map[string][]string{"app": {"z", "y"}, "y": {"a"}},
	}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "node", nil)

	assertSteps(t, paths, "z", []PathStep{{Module: "z", WithoutSource: true}})
	assertSteps(t, paths, "a", []PathStep{{Module: "a", Version: "1.0.0", WithoutSource: true}})
}

func TestResolvedPaths_PrefersARouteThroughParsedSource(t *testing.T) {
	t.Parallel()
	x, y, z := npmNode("x", "1.0.0"), npmNode("y", "1.0.0"), npmNode("z", "1.0.0")
	target, behind := npmNode("target", "1.0.0"), npmNode("behind", "1.0.0")
	graph := completeGraph(
		append(direct(x, y), indirect(z, target, behind)...),
		[]resolve.Edge{edge(x, target), edge(x, behind), edge(y, z), edge(z, target)},
		x, y, z, target, behind,
	)
	result := &ResolveResult{Dependencies: deps(Ref{"x", "1.0.0"}, Ref{"y", "1.0.0"}, Ref{"z", "1.0.0"}, Ref{"target", "1.0.0"}, Ref{"behind", "1.0.0"})}
	parsed := map[string]bool{"y": true, "z@1.0.0": true, "target": true, "behind": true}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "node", parsed)

	assertSteps(t, paths, "target", []PathStep{
		{Module: "y", Version: "1.0.0"},
		{Module: "z", Version: "1.0.0"},
		{Module: "target", Version: "1.0.0"},
	})
	if paths["target"].WithoutSource {
		t.Error("paths[target].WithoutSource = true, want false: a parsed route exists")
	}
	assertSteps(t, paths, "behind", []PathStep{
		{Module: "x", Version: "1.0.0", WithoutSource: true},
		{Module: "behind", Version: "1.0.0"},
	})
	if !paths["behind"].WithoutSource {
		t.Error("paths[behind].WithoutSource = false, want true: its only route crosses unparsed x")
	}
}

func TestResolvedPaths_ModuleAtTwoVersionsIsKeyedByVersion(t *testing.T) {
	t.Parallel()
	p, r := npmNode("p", "1.0.0"), npmNode("r", "1.0.0")
	q1, q2, s := npmNode("q", "1.0.0"), npmNode("q", "2.0.0"), npmNode("s", "1.0.0")
	graph := completeGraph(
		append(direct(p, r), indirect(q1, q2, s)...),
		[]resolve.Edge{edge(p, q1), edge(r, q2), edge(q1, s)},
		p, q1, q2, r, s,
	)
	result := &ResolveResult{Dependencies: deps(Ref{"p", "1.0.0"}, Ref{"r", "1.0.0"}, Ref{"q", "1.0.0"}, Ref{"q", "2.0.0"}, Ref{"s", "1.0.0"})}
	parsed := map[string]bool{"p": true, "r": true, "q": true, "q@2.0.0": true, "s": true}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "node", parsed)

	if path, ok := paths["q"]; ok {
		t.Errorf("paths[q] = %+v, want none: q resolves at two versions", path)
	}
	assertSteps(t, paths, "q@2.0.0", []PathStep{{Module: "r", Version: "1.0.0"}, {Module: "q", Version: "2.0.0"}})
	assertSteps(t, paths, "q@1.0.0", []PathStep{{Module: "p", Version: "1.0.0"}, {Module: "q", Version: "1.0.0", WithoutSource: true}})
	if !paths["s"].WithoutSource {
		t.Error("paths[s].WithoutSource = false, want true: q@1.0.0 was not parsed, only q@2.0.0")
	}
}

func TestResolvedPaths_NodeTakesTheDependencySpelling(t *testing.T) {
	t.Parallel()
	yaml := resolve.Node{ID: "pkg:pypi/pyyaml@6.0.1", PURL: "pkg:pypi/pyyaml", Version: "6.0.1"}
	graph := completeGraph(direct(yaml), nil, yaml)
	result := &ResolveResult{Dependencies: deps(Ref{"PyYAML", "6.0.1"})}

	paths := ResolvedPaths([]resolve.Graph{graph}, result, "python", map[string]bool{"PyYAML": true})

	assertSteps(t, paths, "PyYAML", []PathStep{{Module: "PyYAML", Version: "6.0.1"}})
	assertSteps(t, paths, "PyYAML@6.0.1", []PathStep{{Module: "PyYAML", Version: "6.0.1"}})
}

func TestSharedGraphs_PackageLockPathsEndToEnd(t *testing.T) {
	t.Parallel()
	project, empty := t.TempDir(), t.TempDir()
	lock := `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"a": "^1.0.0"}},
    "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}},
    "node_modules/b": {"version": "2.0.0"}
  }
}`
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}

	graphs := SharedGraphs(context.Background(), []string{project, empty}, "node")
	if len(graphs) != 1 {
		t.Fatalf("len(graphs) = %d, want 1: only the project dir holds a lockfile", len(graphs))
	}
	result := &ResolveResult{Dependencies: deps(Ref{"a", "1.0.0"}, Ref{"b", "2.0.0"})}
	paths := ResolvedPaths(graphs, result, "node", map[string]bool{"a": true, "b": true})

	assertSteps(t, paths, "b", []PathStep{{Module: "a", Version: "1.0.0"}, {Module: "b", Version: "2.0.0"}})
	assertSteps(t, paths, "a", []PathStep{{Module: "a", Version: "1.0.0"}})
}
