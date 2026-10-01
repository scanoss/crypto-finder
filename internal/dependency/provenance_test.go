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

// npm resolves lodash at 4.17.21 for the application and at 3.10.1 for legacy.
// Keyed by module name, the graph would call both copies direct. On
// module@version nodes each copy has the route it really has.
func TestPaths_ModuleAtTwoVersionsKeepsEachCopysRoute(t *testing.T) {
	t.Parallel()
	result := npmTwoLodashes()
	parsed := map[string]bool{
		"lodash": true, "lodash@4.17.21": true, "lodash@3.10.1": true,
		"legacy": true, "legacy@1.0.0": true,
	}
	paths := Paths(result, parsed)

	modern := paths["lodash@4.17.21"]
	if want := []string{"lodash"}; !reflect.DeepEqual(pathModules(modern), want) || modern.Steps[0].Version != "4.17.21" {
		t.Errorf("lodash@4.17.21: path %+v, want a one-step path through 4.17.21", modern.Steps)
	}
	nested := paths["lodash@3.10.1"]
	if want := []string{"legacy", "lodash"}; !reflect.DeepEqual(pathModules(nested), want) || nested.Steps[1].Version != "3.10.1" {
		t.Errorf("lodash@3.10.1: path %+v, want legacy then lodash 3.10.1: it is not direct", nested.Steps)
	}
	if _, byModule := paths["lodash"]; byModule {
		t.Error("a module at two versions has a path keyed by its bare name")
	}
}

// A source parsed for one copy says nothing about the other: legacy parsed
// without lodash 3.10.1 marks that step, and a route through an unparsed
// legacy@1.0.0 is without source whatever the other copies hold.
func TestPaths_ModuleAtTwoVersionsReadsSourceByVersion(t *testing.T) {
	t.Parallel()
	parsed := map[string]bool{"lodash": true, "lodash@4.17.21": true, "legacy": true, "legacy@1.0.0": true}
	nested := Paths(npmTwoLodashes(), parsed)["lodash@3.10.1"]
	if len(nested.Steps) != 2 || nested.Steps[0].WithoutSource || !nested.Steps[1].WithoutSource || nested.WithoutSource {
		t.Errorf("lodash@3.10.1 = %+v, want its own step without source though the module is parsed at 4.17.21", nested)
	}

	delete(parsed, "legacy@1.0.0")
	nested = Paths(npmTwoLodashes(), parsed)["lodash@3.10.1"]
	if !nested.WithoutSource || !nested.Steps[0].WithoutSource {
		t.Errorf("lodash@3.10.1 = %+v, want a path without source through the unparsed legacy", nested)
	}
}

// Without a versioned graph the routes of the two copies cannot be told apart,
// so neither copy gets a path, nor does a dependency reached through one. A
// dependency that avoids them keeps its route.
func TestPaths_ModuleAtTwoVersionsWithoutVersionedGraphHasNoPath(t *testing.T) {
	t.Parallel()
	result := npmTwoLodashes()
	result.VersionedGraph = nil
	result.Graph["lodash"] = []string{"deep"}
	result.Dependencies = append(result.Dependencies, Dependency{Module: "deep", Version: "1.0.0"})
	parsed := map[string]bool{"lodash": true, "legacy": true, "deep": true}
	paths := Paths(result, parsed)

	for _, module := range []string{"lodash", "deep", "lodash@4.17.21", "lodash@3.10.1"} {
		if path, ok := paths[module]; ok {
			t.Errorf("%s has path %+v, want none: its route runs through a module of two versions", module, path.Steps)
		}
	}
	if path, ok := paths["legacy"]; !ok || !reflect.DeepEqual(pathModules(path), []string{"legacy"}) {
		t.Errorf("legacy path = %+v (%v), want its one-step route", path.Steps, ok)
	}
}

func npmTwoLodashes() *ResolveResult {
	return &ResolveResult{
		RootModule: "app",
		Dependencies: []Dependency{
			{Module: "lodash", Version: "4.17.21"},
			{Module: "lodash", Version: "3.10.1"},
			{Module: "legacy", Version: "1.0.0"},
		},
		Graph: map[string][]string{
			"app":    {"lodash", "legacy"},
			"legacy": {"lodash"},
		},
		VersionedGraph: map[string][]Ref{
			"app@1.0.0":    {{Module: "lodash", Version: "4.17.21"}, {Module: "legacy", Version: "1.0.0"}},
			"legacy@1.0.0": {{Module: "lodash", Version: "3.10.1"}},
		},
	}
}
