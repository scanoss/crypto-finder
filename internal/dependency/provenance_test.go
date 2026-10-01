// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"reflect"
	"testing"
)

func pathModules(p Path) []string {
	modules := make([]string, len(p.Steps))
	for i, step := range p.Steps {
		modules[i] = step.Module
	}
	return modules
}

// TestPaths_TransitiveRouteFromTheRoot: the application reaches bcprov through
// tika-parsers and tika-core, and tika-parsers directly. Each dependency gets
// its shortest route, the application not listed and the dependency last.
func TestPaths_TransitiveRouteFromTheRoot(t *testing.T) {
	t.Parallel()
	result := &ResolveResult{
		RootModule: "com.acme:ledger",
		Graph: map[string][]string{
			"com.acme:ledger":         {"org.apache:tika-parsers", "com.nimbus:jose"},
			"org.apache:tika-parsers": {"org.apache:tika-core", "org.bc:bcmail"},
			"org.apache:tika-core":    {"org.bc:bcprov"},
			"org.bc:bcmail":           {"org.bc:bcprov"},
		},
	}
	parsed := map[string]bool{"org.apache:tika-parsers": true, "org.apache:tika-core": true, "org.bc:bcmail": true, "org.bc:bcprov": true, "com.nimbus:jose": true}
	paths := Paths(result, parsed)

	for module, want := range map[string][]string{
		"org.apache:tika-parsers": {"org.apache:tika-parsers"},
		"org.bc:bcprov":           {"org.apache:tika-parsers", "org.apache:tika-core", "org.bc:bcprov"},
		"com.nimbus:jose":         {"com.nimbus:jose"},
	} {
		got, ok := paths[module]
		if !ok {
			t.Fatalf("%s: no path", module)
		}
		if !reflect.DeepEqual(pathModules(got), want) || got.WithoutSource {
			t.Errorf("%s: path %v without source %v, want %v false", module, pathModules(got), got.WithoutSource, want)
		}
	}
	if _, ok := paths["com.acme:ledger"]; ok {
		t.Error("the application has a dependency path")
	}
}

// TestPaths_PrefersARouteThroughParsedSource: tika-core has no source, so the
// route through it cannot carry a call chain. The longer route through bcmail
// can, and is the one named. When every route crosses an unparsed dependency,
// the shortest is named and WithoutSource set.
func TestPaths_PrefersARouteThroughParsedSource(t *testing.T) {
	t.Parallel()
	result := &ResolveResult{
		RootModule: "app",
		Graph: map[string][]string{
			"app":       {"tika-core", "via"},
			"tika-core": {"bcprov", "only-behind"},
			"via":       {"bcmail"},
			"bcmail":    {"bcprov"},
		},
	}
	parsed := map[string]bool{"via": true, "bcmail": true, "bcprov": true, "only-behind": true}
	paths := Paths(result, parsed)

	bcprov := paths["bcprov"]
	if want := []string{"via", "bcmail", "bcprov"}; !reflect.DeepEqual(pathModules(bcprov), want) || bcprov.WithoutSource {
		t.Errorf("bcprov: path %v without source %v, want %v false", pathModules(bcprov), bcprov.WithoutSource, want)
	}
	behind := paths["only-behind"]
	if want := []string{"tika-core", "only-behind"}; !reflect.DeepEqual(pathModules(behind), want) || !behind.WithoutSource {
		t.Errorf("only-behind: path %v without source %v, want %v true", pathModules(behind), behind.WithoutSource, want)
	}
	if !behind.Steps[0].WithoutSource || behind.Steps[1].WithoutSource {
		t.Errorf("only-behind: steps %+v, want tika-core marked without source and only-behind not", behind.Steps)
	}
}

// TestPaths_InferredApplication: a graph that does not name the root module
// still has an application node nothing depends on. A graph source that is
// itself a resolved dependency is a direct dependency, not the application.
func TestPaths_InferredApplication(t *testing.T) {
	t.Parallel()
	result := &ResolveResult{
		RootModule:   "com.acme",
		Dependencies: []Dependency{{Module: "org.example:loose"}, {Module: "org.example:bridge"}, {Module: "org.example:crypto"}},
		Graph: map[string][]string{
			"com.acme:app":       {"org.example:bridge"},
			"org.example:bridge": {"org.example:crypto"},
			"org.example:loose":  {"org.example:crypto"},
		},
	}
	all := map[string]bool{"org.example:loose": true, "org.example:bridge": true, "org.example:crypto": true}
	paths := Paths(result, all)
	if got := pathModules(paths["org.example:crypto"]); !reflect.DeepEqual(got, []string{"org.example:bridge", "org.example:crypto"}) {
		t.Errorf("crypto: path %v", got)
	}
	if got := pathModules(paths["org.example:loose"]); !reflect.DeepEqual(got, []string{"org.example:loose"}) {
		t.Errorf("loose: path %v, want a direct dependency", got)
	}
	if _, ok := paths["com.acme:app"]; ok {
		t.Error("the inferred application has a dependency path")
	}
}

// TestPaths_WorkspaceMembersAreTheApplication: a member that depends on
// another member does not make that member a dependency.
func TestPaths_WorkspaceMembersAreTheApplication(t *testing.T) {
	t.Parallel()
	result := &ResolveResult{
		RootModule:       "root",
		WorkspaceMembers: []WorkspaceMember{{Name: "api"}, {Name: "core"}},
		Graph: map[string][]string{
			"api":  {"core", "serde"},
			"core": {"ring"},
		},
	}
	paths := Paths(result, map[string]bool{"serde": true, "ring": true})
	if _, ok := paths["core"]; ok {
		t.Error("a workspace member has a dependency path")
	}
	if got := pathModules(paths["ring"]); !reflect.DeepEqual(got, []string{"ring"}) {
		t.Errorf("ring: path %v, want a direct dependency of a member", got)
	}
}

func TestPaths_NoGraph(t *testing.T) {
	t.Parallel()
	if got := Paths(&ResolveResult{RootModule: "app"}, nil); got != nil {
		t.Errorf("Paths without a graph = %v, want nil", got)
	}
}
