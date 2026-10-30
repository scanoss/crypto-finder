// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// schema618Export is the provenance fixture's interned export, with its
// source files on disk and its application root recognized by a catalog
// entry, so the export carries excerpts, entry_rule and, for the frame of a
// dependency whose file is missing, excerpt_unavailable.
func schema618Export(t *testing.T) map[string]any {
	t.Helper()
	fixture := newProvenanceFixture(t)
	for _, fn := range fixture.result.CallGraph.Functions {
		switch fn.ID.Type {
		case "App":
			fn.EntryKind = callgraph.RootKindFrameworkEntry
			fn.EntryRule = "java/spring:decorator:RequestMapping"
			fn.Calls[0].StartCol, fn.Calls[0].EndCol = 5, 17
			writeSource(t, fn.FilePath, "class App {\n  void main() {\n    Bridge.run();\n    MessageDigest.getInstance(\"SHA-256\");\n  }\n}\n")
		case "Bridge":
			writeSource(t, fn.FilePath, "class Bridge {\n  void run() {\n    Hash.md5();\n  }\n}\n")
		}
	}
	path := filepath.Join(t.TempDir(), "callgraph.json")
	if err := exportCallGraphWithOptions(path, "json", fixture.result, CallGraphExportOptions{InternedFrames: true}); err != nil {
		t.Fatalf("export: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

// TestCallgraphSchema618_ExcerptsOnEveryFrame: each frame of the route from
// the application through two dependencies carries the source around the call
// that leads on, the first frame names the catalog entry that made it an
// entry point, the call into a frame names its column, and a frame whose
// file the scan cannot read says why. The export validates against the 6.18
// schema, which rejects a malformed value of each new field.
func TestCallgraphSchema618_ExcerptsOnEveryFrame(t *testing.T) {
	t.Parallel()
	document := schema618Export(t)
	if got := document["schema_version"]; got != "6.18" {
		t.Fatalf("schema_version = %v, want 6.18", got)
	}

	var export graphfrag.CallgraphExport
	raw, _ := json.Marshal(document)
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	var route []graphfrag.ExportChainNode
	for i := range export.FindingGraphs {
		fg := &export.FindingGraphs[i]
		graphfrag.HydrateChainIdentities(export.Functions, fg.CallChains, fg.CallChainIndexes)
		if fg.FindingID == "hash" && len(fg.CallChains) == 1 {
			route = fg.CallChains[0]
		}
	}
	if len(route) != 3 {
		t.Fatalf("hash finding route = %+v, want App -> Bridge -> Hash", route)
	}
	app, bridge, hash := route[0], route[1], route[2]
	if app.EntryRule != "java/spring:decorator:RequestMapping" || app.RootKind != "framework_entry" {
		t.Errorf("first frame entry_rule %q root_kind %q, want the catalog entry and framework_entry", app.EntryRule, app.RootKind)
	}
	if bridge.EntryRule != "" || hash.EntryRule != "" {
		t.Errorf("entry_rule on a later frame: %q, %q", bridge.EntryRule, hash.EntryRule)
	}
	if got := app.Excerpt; got == nil || got.FocusLine != 3 || got.StartLine != 1 || got.Lines[2] != "    Bridge.run();" {
		t.Errorf("application frame excerpt = %+v, want focus on the Bridge.run() call at line 3", got)
	}
	if got := bridge.Excerpt; bridge.DependencyInfo == nil || got == nil || got.FocusLine != 3 || got.Lines[2] != "    Hash.md5();" {
		t.Errorf("dependency frame %+v excerpt = %+v, want focus on the Hash.md5() call at line 3", bridge.DependencyInfo, got)
	}
	if bridge.EntryCall == nil || bridge.EntryCall.CallSiteColumn != 5 {
		t.Errorf("entry_call into the dependency = %+v, want call_site_column 5", bridge.EntryCall)
	}
	if hash.Excerpt != nil || hash.ExcerptUnavailable != graphfrag.ExcerptNoSource {
		t.Errorf("frame of a missing file = %+v, %q; want no_source", hash.Excerpt, hash.ExcerptUnavailable)
	}

	if result := validateCallgraphDocument(t, "callgraph-schema-6.18.json", document); !result.Valid() {
		t.Fatalf("6.18 export does not match callgraph-schema-6.18.json: %v", result.Errors())
	}
	for _, tc := range []struct {
		within []string
		key    string
		value  any
	}{
		{key: "entry_rule", value: ""},
		{key: "excerpt_unavailable", value: "missing"},
		{within: []string{"entry_call"}, key: "call_site_column", value: 0},
		{within: []string{"excerpt"}, key: "lines", value: "    Bridge.run();"},
		{within: []string{"excerpt"}, key: "focus_line", value: 0},
		{within: []string{"excerpt"}, key: "truncated", value: "no"},
		{key: "excerpt", value: map[string]any{"start_line": 1, "focus_line": 1, "lines": []any{"x"}, "path": "/etc/passwd"}},
	} {
		name := strings.Join(append(tc.within, tc.key), ".")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mutated := schema618Export(t)
			if tc.key == "truncated" && !setFirst(mutated, nil, nil, "excerpt", map[string]any{"start_line": 1, "focus_line": 1, "lines": []any{"x"}, "truncated": true}) {
				t.Fatal("export has no excerpt")
			}
			if !setFirst(mutated, tc.within, nil, tc.key, tc.value) {
				t.Fatalf("export has no %s to corrupt", name)
			}
			if validateCallgraphDocument(t, "callgraph-schema-6.18.json", mutated).Valid() {
				t.Fatalf("callgraph-schema-6.18.json accepted %s = %#v", name, tc.value)
			}
		})
	}
}
