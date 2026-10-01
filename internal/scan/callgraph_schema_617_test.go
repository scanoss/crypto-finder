// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// schema617Export is an interned export that carries every field schema 6.17
// adds. The provenance fixture's export supplies the dependency block,
// dependency_without_source and the route analysis; the finding
// graphs that only a cut or guessed walk produces (unresolved_dispatch,
// traversal_truncated, the no_callers and depth_limit roots) are built by the
// same builder and added to it.
func schema617Export(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "callgraph.json")
	if err := exportCallGraphWithOptions(path, "json", newProvenanceFixture(t).result, CallGraphExportOptions{InternedFrames: true}); err != nil {
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

	dispatchCtx, dispatchTarget := dispatchChainContext(false)
	truncatedCtx, truncatedTarget := depthChainContext("org.lib", 3, map[string]bool{"com.app": true})
	appCutCtx, appCutTarget := depthChainContext("com.app.deep", 3, map[string]bool{"com.app": true})
	noCallers := newEvidenceGraph()
	noCallers.directRoute()
	built := []callGraphExportFinding{
		buildDepthFindingGraph(dispatchCtx, dispatchTarget),
		buildDepthFindingGraph(truncatedCtx, truncatedTarget),
		buildDepthFindingGraph(appCutCtx, appCutTarget),
		buildDepthFindingGraph(noCallers.context(1), noCallers.target),
	}
	graphs, _ := document["finding_graphs"].([]any)
	for i := range built {
		raw, err := json.Marshal(built[i])
		if err != nil {
			t.Fatal(err)
		}
		var fg map[string]any
		if err := json.Unmarshal(raw, &fg); err != nil {
			t.Fatal(err)
		}
		graphs = append(graphs, fg)
	}
	document["finding_graphs"] = graphs
	return document
}

// collectFieldValues lists every object key of a JSON value as "key" and every
// scalar member as "key=value", so a test can ask whether a field, or a field
// holding a given value, appears anywhere in the document.
func collectFieldValues(value any, out map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		for key, member := range v {
			out[key] = true
			switch scalar := member.(type) {
			case string, bool, float64:
				out[fmt.Sprintf("%s=%v", key, scalar)] = true
			}
			collectFieldValues(member, out)
		}
	case []any:
		for _, item := range v {
			collectFieldValues(item, out)
		}
	}
}

func validateCallgraphDocument(t *testing.T, schema string, document any) *gojsonschema.Result {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "schemas", schema))
	if err != nil {
		t.Fatal(err)
	}
	result, err := gojsonschema.Validate(gojsonschema.NewReferenceLoader("file://"+path), gojsonschema.NewGoLoader(document))
	if err != nil {
		t.Fatalf("validate against %s: %v", schema, err)
	}
	return result
}

// setFirst sets key to value on the first object, depth first, that holds key
// and whose path contains every segment of within, and reports whether it
// found one.
func setFirst(value any, within, path []string, key string, replacement any) bool {
	switch v := value.(type) {
	case map[string]any:
		if _, ok := v[key]; ok && containsAll(path, within) {
			v[key] = replacement
			return true
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if setFirst(v[k], within, append(path, k), key, replacement) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if setFirst(item, within, path, key, replacement) {
				return true
			}
		}
	}
	return false
}

func containsAll(path, want []string) bool {
	for _, w := range want {
		found := false
		for _, p := range path {
			found = found || p == w
		}
		if !found {
			return false
		}
	}
	return true
}

// TestCallgraphSchema617_DeclaresEveryNewField: an interned export holding
// every field 6.17 adds is stamped 6.17 and validates against the 6.17
// schema, and the schema constrains each new field: a value of the wrong type
// or outside its vocabulary is rejected, so an undeclared field cannot pass.
func TestCallgraphSchema617_DeclaresEveryNewField(t *testing.T) {
	t.Parallel()
	document := schema617Export(t)

	if got := document["schema_version"]; got != "6.17" {
		t.Fatalf("schema_version = %v, want 6.17", got)
	}
	present := map[string]bool{}
	collectFieldValues(document, present)
	for _, want := range []string{
		"dependency", "relationship=transitive", "path", "without_source=true",
		"root_kind=no_callers", "root_kind=depth_limit",
		"paths_total", "paths_kept", "route_evidence=direct", "route_evidence=name_only", "no_callers_only=true",
		"unresolved_reason=unresolved_dispatch", "unresolved_reason=traversal_truncated", "unresolved_reason=dependency_without_source",
	} {
		if !present[want] {
			t.Errorf("export lacks %s", want)
		}
	}
	if result := validateCallgraphDocument(t, "callgraph-schema-6.17.json", document); !result.Valid() {
		t.Fatalf("6.17 export does not match callgraph-schema-6.17.json: %v", result.Errors())
	}

	for _, tc := range []struct {
		within []string
		key    string
		value  any
	}{
		{key: "dependency", value: "org.b:digest"},
		{within: []string{"dependency"}, key: "relationship", value: "sibling"},
		{within: []string{"path"}, key: "without_source", value: "yes"},
		{key: "root_kind", value: "constructor"},
		{key: "unresolved_reason", value: "gave_up"},
		{within: []string{"analysis"}, key: "paths_total", value: "3"},
		{within: []string{"analysis"}, key: "paths_kept", value: 0},
		{within: []string{"analysis"}, key: "route_evidence", value: "probably"},
		{within: []string{"analysis"}, key: "no_callers_only", value: "true"},
	} {
		name := strings.Join(append(tc.within, tc.key), ".")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mutated := schema617Export(t)
			if !setFirst(mutated, tc.within, nil, tc.key, tc.value) {
				t.Fatalf("export has no %s to corrupt", name)
			}
			if validateCallgraphDocument(t, "callgraph-schema-6.17.json", mutated).Valid() {
				t.Fatalf("callgraph-schema-6.17.json accepted %s = %#v", name, tc.value)
			}
		})
	}
}

// TestCallgraphSchema616_ArtifactStillValidatesAndReads: an interned export
// written by crypto-finder v0.32.0 (schema 6.16) still validates against the
// 6.16 schema, is not mistaken for 6.17, and reads through graphfrag with its
// chain identity hydrated from the catalog and none of the 6.17 fields set.
func TestCallgraphSchema616_ArtifactStillValidatesAndReads(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "callgraph-6.16-v0.32.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if result := validateCallgraphDocument(t, "callgraph-schema-6.16.json", document); !result.Valid() {
		t.Fatalf("v0.32.0 artifact does not match callgraph-schema-6.16.json: %v", result.Errors())
	}
	if validateCallgraphDocument(t, "callgraph-schema-6.17.json", document).Valid() {
		t.Fatal("callgraph-schema-6.17.json accepted a 6.16 artifact")
	}

	var export graphfrag.CallgraphExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("read 6.16 artifact: %v", err)
	}
	if export.SchemaVersion != "6.16" || len(export.ScanMetadata.Ecosystems) != 2 || len(export.FindingGraphs) == 0 {
		t.Fatalf("read schema %q, %d ecosystems, %d finding graphs", export.SchemaVersion, len(export.ScanMetadata.Ecosystems), len(export.FindingGraphs))
	}
	for i := range export.FindingGraphs {
		fg := &export.FindingGraphs[i]
		if !graphfrag.HydrateChainIdentities(export.Functions, fg.CallChains, fg.CallChainIndexes) {
			t.Fatalf("%s: chain indexes do not join the catalog", fg.FindingID)
		}
		for _, chain := range fg.CallChains {
			for _, frame := range chain {
				if frame.FunctionName == "" || frame.RootKind != "" {
					t.Errorf("%s: frame %+v, want hydrated identity and no root_kind", fg.FindingID, frame)
				}
			}
		}
		if fg.Dependency != nil {
			t.Errorf("%s: dependency %+v on a 6.16 artifact", fg.FindingID, fg.Dependency)
		}
		if a := fg.Analysis; a != nil && (a.PathsTotal != 0 || a.RouteEvidence != "" || a.NoCallersOnly) {
			t.Errorf("%s: analysis %+v carries 6.17 fields", fg.FindingID, a)
		}
	}
}
