// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/javaruntime"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func writeJavaModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"App.java": "package app;\n\nimport java.security.MessageDigest;\n\nclass App { byte[] run() throws Exception { return MessageDigest.getInstance(\"SHA-256\").digest(new byte[0]); } }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The cards detector builds the target's typed graph before detection; the
// export of the same scan must take that graph instead of building it again.
func TestCardsDetectorAndExportShareOneGraph(t *testing.T) {
	target := writeJavaModule(t)
	graphs := newGraphStore(target, "")

	detect := cardsFragmentBuilder(graphs, target, ecosystemJava, func() (javaruntime.Config, error) { return javaruntime.Config{}, nil }, false, "", nil)
	if _, err := detect(target); err != nil {
		t.Fatalf("detector fragment: %v", err)
	}
	stored, ok := graphs.load(target, ecosystemJava, nil)
	if !ok {
		t.Fatalf("the detector's graph of the target was not kept")
	}

	report := &entities.InterimReport{}
	exported, err := buildStandaloneCallGraphResult(graphs, target, report, []string{ecosystemJava}, javaruntime.Config{}, false, "", nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if exported.CallGraph != stored.CallGraph {
		t.Errorf("the export built a second graph instead of the detector's")
	}
	if exported.Report != report {
		t.Errorf("the export's result must carry the scan's report")
	}
}

func TestGraphStoreKeepsOnlyTheScanTarget(t *testing.T) {
	target, other := writeJavaModule(t), writeJavaModule(t)
	graphs := newGraphStore(target, "")

	detect := cardsFragmentBuilder(graphs, target, ecosystemJava, func() (javaruntime.Config, error) { return javaruntime.Config{}, nil }, false, "", nil)
	if _, err := detect(target); err != nil {
		t.Fatalf("detector fragment: %v", err)
	}
	own, _ := graphs.load(target, ecosystemJava, nil)
	if _, err := detect(other); err != nil {
		t.Fatalf("detector fragment: %v", err)
	}
	if _, ok := graphs.load(other, ecosystemJava, nil); ok {
		t.Errorf("a dependency directory's graph must not be kept")
	}
	if kept, ok := graphs.load(target, ecosystemJava, nil); !ok || own == nil || kept.CallGraph != own.CallGraph {
		t.Errorf("scanning another directory must leave the target's graph in place")
	}
}
