// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package rules_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

type consumerScanner struct {
	scan func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error)
}

func (consumerScanner) Initialize(context.Context, scanner.Config) error { return nil }
func (consumerScanner) GetInfo() scanner.Info                            { return scanner.Info{Name: "fixture", Version: "1"} }
func (s consumerScanner) Scan(ctx context.Context, target string, paths []string, info entities.ToolInfo) (*entities.InterimReport, error) {
	return s.scan(ctx, target, paths, info)
}

type consumerResolver struct{ dependencies []dependency.Dependency }

func (r consumerResolver) Resolve(context.Context, string) (*dependency.ResolveResult, error) {
	return &dependency.ResolveResult{RootModule: "app", Dependencies: r.dependencies}, nil
}
func (consumerResolver) Ecosystem() string { return "go" }

func TestDependencyConsumerRetainsValidFindingsAndRejectsMalformedRules(t *testing.T) {
	for _, scenario := range []string{"unchanged", "malformed-prepared"} {
		t.Run(scenario, func(t *testing.T) {
			ruleDir := t.TempDir()
			original := "rules:\n- id: fixture\n  languages: [go]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n  metadata:\n    crypto:\n      parameterCondition: 'param[0]==true'\n"
			for _, name := range []string{"first.yaml", "second.yaml"} {
				body := original
				if name == "second.yaml" {
					body = strings.ReplaceAll(body, "id: fixture", "id: other")
				}
				if err := os.WriteFile(filepath.Join(ruleDir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			deps := []dependency.Dependency{{Module: "a", Version: "1", Dir: t.TempDir()}, {Module: "b", Version: "1", Dir: t.TempDir()}}
			registry := scanner.NewRegistry()
			registry.RegisterFactory("fixture", func() scanner.Scanner {
				return consumerScanner{scan: func(_ context.Context, target string, paths []string, info entities.ToolInfo) (*entities.InterimReport, error) {
					selected := filepath.Join(paths[0], "first.yaml")
					data, err := os.ReadFile(selected)
					if err != nil {
						return nil, err
					}
					if scenario == "malformed-prepared" && target == deps[0].Dir {
						if err := os.WriteFile(selected, []byte(strings.ReplaceAll(string(data), "param[0]==true", "param[]==true ")), 0o600); err != nil {
							return nil, err
						}
					}
					return &entities.InterimReport{Tool: info, Findings: []entities.Finding{{FilePath: filepath.Join(target, "dep.go"), CryptographicAssets: []entities.CryptographicAsset{{StartLine: 2, EndLine: 2, Match: "digest()", Metadata: map[string]string{"assetType": "algorithm", "algorithmFamily": "SHA", "primitive": "hash", "observed": string(data)}}}}}}, nil
				}}
			})
			orchestrator := engine.NewOrchestrator(nil, rules.NewManager(rules.NewLocalRuleSource(nil, []string{ruleDir})), registry)
			consumer := engine.NewDependencyScanner(orchestrator, consumerResolver{dependencies: deps}, callgraph.NewBuilder(callgraph.NewGoParser()), nil)
			opts := engine.DepScanOptions{Workers: 1, ScanOptions: engine.ScanOptions{Target: t.TempDir(), ScannerName: "fixture"}}
			expectedFailed := 0
			if scenario == "malformed-prepared" {
				expectedFailed = 1
			}
			var previous []byte
			for range 2 {
				result, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, opts)
				if err != nil {
					t.Fatal(err)
				}
				if result.ProgressDetails()["deps_failed"] != expectedFailed || result.ProgressDetails()["deps_scanned"] != 2-expectedFailed || len(result.Report.Findings) != 2-expectedFailed {
					t.Fatalf("findings lost: %v", result)
				}
				for i, finding := range result.Report.Findings {
					if len(finding.CryptographicAssets) != 1 {
						t.Fatal("asset count changed")
					}
					asset := finding.CryptographicAssets[0]
					if asset.Metadata["observed"] != original || asset.StartLine != 2 || asset.Match != "digest()" || asset.FindingID == "" || asset.Source != "dependency" || asset.DependencyInfo == nil || asset.DependencyInfo.Module != deps[i].Module {
						t.Fatalf("finding changed: %+v", asset)
					}
				}
				data, err := json.Marshal(result.Report)
				if err != nil {
					t.Fatal(err)
				}
				if previous != nil && !bytes.Equal(previous, data) {
					t.Fatal("complete uncached report changed between invocations")
				}
				previous = data
			}
		})
	}
}
