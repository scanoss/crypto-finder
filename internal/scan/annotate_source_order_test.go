// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// The finding is the factory, so its supporting calls are the calls made on the
// object it returns. The fragment lists a function's edges by target, and
// crypto/cipher.(AEAD).Seal sorts before golang.org/x/crypto/chacha20poly1305.NewX,
// so annotate must not read that order as the order of the source.
func TestAnnotateSupportingCallsFollowSourceOrder(t *testing.T) {
	t.Parallel()

	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "main.go",
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 6,
				EndLine:   6,
				Match:     "aead, _ := chacha20poly1305.NewX(key)",
				Rules:     []entities.RuleInfo{{ID: "go.xcrypto.chacha20poly1305.aead-x"}},
				Metadata: map[string]string{
					"api":           "chacha20poly1305.NewX",
					"assetType":     "algorithm",
					"algorithmName": "XChaCha20-Poly1305",
				},
			}},
		}},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(chachaConsumer), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("go", callgraph.NewGoParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "example.com/app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	fragment := buildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "example.com/app", Ecosystem: "go",
	})
	full := make([]string, 0, len(fragment.SupportingCalls))
	for i := range fragment.SupportingCalls {
		full = append(full, fragment.SupportingCalls[i].SupportingID)
	}
	if len(full) == 0 {
		t.Fatal("the full export has no supporting calls for the factory finding")
	}

	cached := decodeFragmentForTest(t, marshalSorted(t, fragment))
	annotate := buildAnnotateExport(prepareOIDFixtureReport(t, report), cached)
	annotated := make([]string, 0, len(annotate.SupportingCalls))
	for i := range annotate.SupportingCalls {
		annotated = append(annotated, annotate.SupportingCalls[i].SupportingID)
	}
	sort.Strings(full)
	sort.Strings(annotated)
	if len(annotated) != len(full) {
		t.Fatalf("annotate supporting ids = %v, full export = %v", annotated, full)
	}
	for i := range full {
		if annotated[i] != full[i] {
			t.Fatalf("annotate supporting ids = %v, full export = %v", annotated, full)
		}
	}
}
