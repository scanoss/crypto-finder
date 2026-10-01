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

package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

// fluentConditionCase plants one conditioned finding on a fluent call chain.
// span is the text the rule matched (the selector link, or the selector
// argument for a taint rule) and condition the rule's parameterCondition.
type fluentConditionCase struct {
	id, file, span, condition string
	wantChains                bool
}

// TestExportCallGraph_FluentChainConditionReadsTheMatchedLink: a rule's
// parameterCondition names an argument of the call the rule matched. On a
// fluent chain that call is not the outermost link, whose argument ('hex', a
// salt, an encoding) would refute the condition and drop every chain of a
// reachable finding. The condition still refutes a chain whose matched link
// contradicts it. Go has no case: the one fluent chain its conditioned rules
// match is jwt.NewWithClaims(...).SignedString(key), and a signing key does
// not resolve to a literal.
func TestExportCallGraph_FluentChainConditionReadsTheMatchedLink(t *testing.T) {
	t.Parallel()
	tests := []struct {
		dir, ecosystem, language string
		parser                   func() callgraph.Parser
		cases                    []fluentConditionCase
	}{
		{
			dir: "node", ecosystem: "npm", language: "typescript",
			parser: func() callgraph.Parser { return callgraph.NewNodeParser() },
			cases: []fluentConditionCase{
				{id: "node-md5", file: "src/avatar.ts", span: "createHash('md5')", condition: "param[0]==md5", wantChains: true},
				{id: "node-other", file: "src/avatar.ts", span: "createHash('sha256')", condition: "param[0]==md5"},
			},
		},
		{
			dir: "java", ecosystem: "maven", language: "java",
			parser: func() callgraph.Parser { return callgraph.NewJavaParser() },
			cases: []fluentConditionCase{
				{id: "java-md5", file: "src/main/java/com/app/Fingerprint.java", span: `"MD5"`, condition: "param[0]==MD5", wantChains: true},
			},
		},
		{
			dir: "python", ecosystem: "pypi", language: "python",
			parser: func() callgraph.Parser { return callgraph.NewPythonParser() },
			cases: []fluentConditionCase{
				{id: "python-sha256", file: "app/digest.py", span: `"sha256"`, condition: "param[0|name]~=sha-?(224|256|384|512)", wantChains: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			t.Parallel()
			graphs := exportEntryRoots(t, fluentConditionFixture(t, filepath.Join("fluent_conditions", tt.dir), tt.ecosystem, tt.language, tt.parser(), tt.cases), 0)
			for _, c := range tt.cases {
				fg, ok := graphs[c.id]
				if !ok {
					t.Errorf("%s: no finding graph", c.id)
					continue
				}
				if got := len(fg.CallChains) > 0; got != c.wantChains {
					t.Errorf("%s: has chains = %v, want %v (reachability %q, crypto call %q, chains %+v)",
						c.id, got, c.wantChains, fg.Reachability, fg.MatchedOperation.Symbol, shortChains(fg))
				}
			}
		})
	}
}

// fluentConditionFixture builds testdata/<dir> and plants
// each case at its span, with columns as a rule match reports them (1-based,
// end exclusive).
func fluentConditionFixture(t *testing.T, dir, ecosystem, language string, parser callgraph.Parser, cases []fluentConditionCase) entryRootsFixture {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(testFile), "testdata", dir)
	graph, err := callgraph.NewBuilderForEcosystem(ecosystem, parser).BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join(root, c.file))
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		line, col := 0, 0
		lines := strings.Split(string(data), "\n")
		for i, text := range lines {
			if at := strings.Index(text, c.span); at >= 0 {
				line, col = i+1, at+1
				break
			}
		}
		if line == 0 {
			t.Fatalf("%s has no line containing %q", c.file, c.span)
		}
		condition, err := paramcondition.Parse(c.condition)
		if err != nil {
			t.Fatalf("parse %q: %v", c.condition, err)
		}
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: c.file,
			Language: language,
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID:           c.id,
				StartLine:           line,
				EndLine:             line,
				StartCol:            col,
				EndCol:              col + len(c.span),
				Match:               strings.TrimSpace(lines[line-1]),
				Rules:               []entities.RuleInfo{{ID: language + ".crypto." + c.id}},
				Metadata:            map[string]string{"assetType": "algorithm", "parameterCondition": c.condition},
				ParameterConditions: []paramcondition.Condition{condition},
			}},
		})
	}
	return entryRootsFixture{root: root, result: &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		Ecosystem:   ecosystem,
		ProjectRoot: root,
	}}
}
