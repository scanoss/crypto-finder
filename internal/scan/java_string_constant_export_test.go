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
)

// A String constant declared in another class resolves to its literal, the
// same as a same-class final field, so rule conditions on the value match.
func TestBuildGraphFragmentExport_ResolvesCrossClassStringConstant(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	files := map[string]string{
		"lib/digest/Algorithms.java": "package lib.digest;\npublic class Algorithms {\n    public static final String SHA_1 = \"SHA-1\";\n}\n",
		"app/Caller.java": `package app;
import java.security.MessageDigest;
import lib.digest.Algorithms;
public class Caller {
    void digest() throws Exception {
        MessageDigest.getInstance(Algorithms.SHA_1);
    }
}
`,
	}
	for rel, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "app/Caller.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: 6, EndLine: 6,
			Match:    "MessageDigest.getInstance(Algorithms.SHA_1)",
			Rules:    []entities.RuleInfo{{ID: "java.digest.sha1"}},
			Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"},
		}},
	}}}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	payload := buildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})
	if len(payload.CryptoAnnotations) != 1 || payload.CryptoAnnotations[0].CryptoCall == nil {
		t.Fatalf("crypto annotations = %#v, want one call annotation", payload.CryptoAnnotations)
	}
	param := payload.CryptoAnnotations[0].CryptoCall.Parameters[0]
	if param.ResolvedValue != `"SHA-1"` {
		t.Fatalf("resolved_value = %q, want the constant's literal", param.ResolvedValue)
	}
}
