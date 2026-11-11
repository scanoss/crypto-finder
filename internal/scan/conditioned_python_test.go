// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const pythonHasherModule = `import hashlib

def digest(data, alg):
    return hashlib.new(alg, data)
`

const pythonDigestRules = `rules:
  - id: py.hash.sha256
    message: sha256
    severity: INFO
    pattern: hashlib.new("sha256", ...)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: SHA-256
        operation: digest
        parameterCondition: param[0]==sha256
        api: hashlib.new
  - id: py.hash.md5
    message: md5
    severity: INFO
    pattern: hashlib.new("md5", ...)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: MD5
        operation: digest
        parameterCondition: param[0]==md5
        api: hashlib.new
`

// A Python helper whose algorithm is a parameter specializes from the values
// its callers in another module pass, parsed from real source.
func TestMaterializeConditionedFindings_PythonParameterAcrossModules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		main       string
		wantRules  []string
		wantAnchor bool
	}{
		{
			name:      "positional literal",
			main:      "from app.hasher import digest\n\ndigest(b\"x\", \"sha256\")\n",
			wantRules: []string{"py.hash.sha256"},
		},
		{
			name:      "keyword arguments in another order",
			main:      "from app.hasher import digest\n\ndef run():\n    return digest(alg=\"md5\", data=b\"x\")\n",
			wantRules: []string{"py.hash.md5"},
		},
		{
			name:      "string constant forwarded through a local",
			main:      "from app.hasher import digest\n\nALG = \"md5\"\n\ndef run():\n    a = \"sha256\"\n    digest(b\"x\", a)\n    digest(b\"y\", ALG)\n",
			wantRules: []string{"py.hash.md5", "py.hash.sha256"},
		},
		{
			name:       "dynamic caller keeps the generic anchor",
			main:       "from app.hasher import digest\n\ndigest(b\"x\", \"sha256\")\ndigest(b\"y\", input())\n",
			wantRules:  []string{"py.hash.sha256"},
			wantAnchor: true,
		},
		{
			name:       "caller leaves the parameter to a starred argument",
			main:       "from app.hasher import digest\n\ndigest(b\"x\", \"sha256\")\nparts = [b\"y\", \"sha256\"]\ndigest(*parts, \"md5\")\n",
			wantRules:  []string{"py.hash.sha256"},
			wantAnchor: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for rel, src := range map[string]string{
				"app/__init__.py": "",
				"app/hasher.py":   pythonHasherModule,
				"app/main.py":     tt.main,
			} {
				path := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
				BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			hasherPath := filepath.Join(dir, "app", "hasher.py")
			report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: hasherPath, Language: "python", CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 4, EndLine: 4, StartCol: 12, EndCol: 34, Match: "hashlib.new(alg, data)",
				Rules:    []entities.RuleInfo{{ID: "py.hash.dynamic"}},
				Metadata: map[string]string{"api": "hashlib.new", "assetType": "algorithm"},
			}}}}}

			MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "python", ProjectRoot: dir}, []string{writeConditionedRules(t, pythonDigestRules)})

			var gotRules []string
			gotAnchor := false
			for _, asset := range report.Findings[0].CryptographicAssets {
				if asset.Rules[0].ID == "py.hash.dynamic" {
					gotAnchor = true
					continue
				}
				gotRules = append(gotRules, asset.Rules[0].ID)
			}
			slices.Sort(gotRules)
			if !slices.Equal(gotRules, tt.wantRules) || gotAnchor != tt.wantAnchor {
				t.Fatalf("specialized rules = %v, generic anchor = %v; want %v, %v", gotRules, gotAnchor, tt.wantRules, tt.wantAnchor)
			}
		})
	}
}
