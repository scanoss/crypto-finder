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

// TestDevPythonFragmentExport is the developer probe of Python graph
// fragments (E2.7-py.1). The scan command refuses Python targets
// (language_not_supported), and this test is the only way to export one: it
// builds the target's call graph the way `scan --export-graph-fragment` does
// for a standalone Python target (default exclusions, type resolution on, no
// tests, no detection) and writes the fragment. It lives in a test file so the
// shipped binary has no route to it.
//
//	CRYPTO_FINDER_DEV_PY_TARGET=<dir> CRYPTO_FINDER_DEV_PY_OUT=<fragment.json> \
//	  go test ./internal/cli/ -run TestDevPythonFragmentExport -count=1
//
// CRYPTO_FINDER_DEV_PY_TYPE_PACKAGES types the graph with Python type-only
// packages, as --type-packages does.
//
// It also writes <fragment>.restored.json, the document with what the 1.22
// writer elides put back (RestoreElided), for scripts that read sites.
//
// Without the variables it exports the graph algorithm guard's Python corpus
// to a temporary file, so the route stays exercised.
func TestDevPythonFragmentExport(t *testing.T) {
	target, out := os.Getenv("CRYPTO_FINDER_DEV_PY_TARGET"), os.Getenv("CRYPTO_FINDER_DEV_PY_OUT")
	if target == "" {
		target = filepath.Join("..", "graphalgoguard", "testdata", "graph_algo_guard", "python", "app")
		out = filepath.Join(t.TempDir(), "fragment.json")
	}
	if out == "" {
		t.Fatal("CRYPTO_FINDER_DEV_PY_OUT must name the fragment file")
	}
	target, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	graphs := newGraphStore(target, "")
	graphs.typePackages = os.Getenv("CRYPTO_FINDER_DEV_PY_TYPE_PACKAGES")
	result, err := buildStandaloneCallGraphResult(graphs, target, report, []string{ecosystemPython},
		javaruntime.Config{}, false, "", skip.NewMatcher(nil, true))
	if err != nil {
		t.Fatalf("build Python call graph: %v", err)
	}
	if result.Ecosystem != ecosystemPython {
		t.Fatalf("built a %q graph, want python", result.Ecosystem)
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
	if export.ScanMetadata.GraphAlgoVersion != graphfrag.GraphAlgoVersionPython {
		t.Errorf("fragment graph_algo_version = %q, want %q", export.ScanMetadata.GraphAlgoVersion, graphfrag.GraphAlgoVersionPython)
	}
	t.Logf("%s: %d functions, %d internal edges, %d external calls -> %s",
		target, len(export.Functions), export.ScanMetadata.InternalEdges, export.ScanMetadata.ExternalCalls, out)
}
