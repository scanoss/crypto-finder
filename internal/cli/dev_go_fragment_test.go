// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/skip"

	"github.com/scanoss/crypto-finder/internal/entities"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
)

// TestDevGoFragmentExport is the developer probe of Go graph fragments, as
// TestDevPythonFragmentExport is for Python: it writes the fragment of a Go
// target without running detection.
//
//	CRYPTO_FINDER_DEV_GO_TARGET=<dir> CRYPTO_FINDER_DEV_GO_OUT=<fragment.json> \
//	  go test ./internal/cli/ -run TestDevGoFragmentExport -count=1
//
// It also writes <fragment>.restored.json (RestoreElided). Without the
// variables it exports the graph algorithm guard's Go corpus, so the route
// stays exercised.
func TestDevGoFragmentExport(t *testing.T) {
	target, out := os.Getenv("CRYPTO_FINDER_DEV_GO_TARGET"), os.Getenv("CRYPTO_FINDER_DEV_GO_OUT")
	if target == "" {
		target = filepath.Join("..", "graphalgoguard", "testdata", "graph_algo_guard", "go", "app")
		out = filepath.Join(t.TempDir(), "fragment.json")
	}
	if out == "" {
		t.Fatal("CRYPTO_FINDER_DEV_GO_OUT must name the fragment file")
	}
	target, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	graphs := newGraphStore(target, "")
	result, err := buildStandaloneCallGraphResult(graphs, target, report, []string{"go"},
		javaruntime.Config{}, false, "", skip.NewMatcher(nil, true))
	if err != nil {
		t.Fatalf("build Go call graph: %v", err)
	}
	if result.Ecosystem != "go" {
		t.Fatalf("built a %q graph, want go", result.Ecosystem)
	}
	resolved, err := prepareScanOIDProjection(report, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanutil.ExportResolvedGraphFragment(out, "json", result, resolved); err != nil {
		t.Fatalf("export fragment: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var export graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatal(err)
	}
	export.RestoreElided()
	restored, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strings.TrimSuffix(out, ".json")+".restored.json", restored, 0o600); err != nil {
		t.Fatal(err)
	}
	if len(export.Functions) == 0 {
		t.Fatalf("%s: fragment has no functions", target)
	}
	if export.ScanMetadata.GraphAlgoVersion != graphfrag.GraphAlgoVersionFor("go") {
		t.Errorf("fragment graph_algo_version = %q, want %q", export.ScanMetadata.GraphAlgoVersion, graphfrag.GraphAlgoVersionFor("go"))
	}
	t.Logf("%s: %d functions, %d internal edges, %d external calls -> %s",
		target, len(export.Functions), export.ScanMetadata.InternalEdges, export.ScanMetadata.ExternalCalls, out)
}
