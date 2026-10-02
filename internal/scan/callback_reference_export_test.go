// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const callbackExportSource = `import hashlib
import threading
from django.db import migrations


def backfill(apps, schema):
    hashlib.md5(b"a")


def worker():
    hashlib.sha1(b"b")


def orphan():
    hashlib.sha256(b"c")


def start():
    threading.Thread(target=worker).start()


class Migration(migrations.Migration):
    operations = [migrations.RunPython(backfill)]
`

// TestExportCallGraph_CallbackReferencesReachTheCallback: a function handed to
// an API that runs it is reachable from the function that registers it, which
// is the chain's root. A function nothing registers or calls is not made
// reachable by the others.
func TestExportCallGraph_CallbackReferencesReachTheCallback(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"app/__init__.py": "", "app/mod.py": callbackExportSource} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	file := "app/mod.py"
	report := &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}}
	for id, needle := range map[string]string{"backfill": `hashlib.md5(`, "worker": `hashlib.sha1(`, "orphan": `hashlib.sha256(`} {
		line := lineContaining(t, filepath.Join(root, file), needle)
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: file,
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: id, StartLine: line, EndLine: line, Match: needle,
				Rules:    []entities.RuleInfo{{ID: "python.crypto." + id}},
				Metadata: map[string]string{"assetType": "algorithm"},
			}},
		})
	}
	fixture := entryRootsFixture{root: root, result: &engine.DepScanResult{
		Report: report, CallGraph: graph, Ecosystem: "python", ProjectRoot: root,
	}}
	graphs := exportEntryRoots(t, fixture, 0)

	for id, frames := range map[string][]string{
		"worker":   {"mod.start", "mod.worker"},
		"backfill": {"Migration.<clinit>", "mod.backfill"},
	} {
		fg := graphs[id]
		if fg.Reachability != graphfrag.ReachabilityReachable {
			t.Errorf("%s reachability = %q, want reachable", id, fg.Reachability)
		}
		if chains := shortChains(fg); !hasChain(chains, string(callgraph.RootKindNoCallers), frames...) {
			t.Errorf("%s chains = %+v, want one from the registrar %v as a no_callers root", id, chains, frames)
		}
		if fg.Analysis == nil || !fg.Analysis.NoCallersOnly || fg.Analysis.RouteEvidence != graphfrag.RouteEvidenceDirect {
			t.Errorf("%s analysis = %+v, want direct route evidence from no_callers roots only", id, fg.Analysis)
		}
	}
	if got := graphs["orphan"].Reachability; got != graphfrag.ReachabilityUnreachable {
		t.Errorf("orphan reachability = %q, want unreachable: nothing registers or calls it", got)
	}
}
