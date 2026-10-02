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

// TestExportCallGraph_NodeModuleImportsRunTopLevelCode: importing a project
// module runs its top level, so crypto there, and in a callback it registers,
// is reached from the importer's chain. A module nothing imports, one reached
// only by a package specifier, and one loaded by a dynamic import inside an
// uncalled function stay unreachable.
func TestExportCallGraph_NodeModuleImportsRunTopLevelCode(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	files := map[string]string{
		"package.json": `{"name":"app","main":"index.js"}`,
		"index.js": `import './handlers/a.js';
import { util } from './util';
import 'left-pad';
import loaded from 'loaded';

function lazy() { return import('./dynamic.js'); }
util();
`,
		"handlers/a.js": `import crypto from 'crypto';
import './b';
crypto.createHash('md5');
api.handle('ch', async () => crypto.createHash('sha1'));
`,
		"handlers/b.js": `import crypto from 'crypto';
crypto.createHash('sha224');
`,
		"util.js":    "export function util() {}\n",
		"lib/lib.js": "import crypto from 'crypto';\ncrypto.createHash('sha256');\n",
		"dynamic.js": "import crypto from 'crypto';\ncrypto.createHash('sha384');\n",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemNode, callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	cases := []struct {
		id, file, needle string
		reachable        bool
		frames           []string
	}{
		{"direct", "handlers/a.js", "createHash('md5')", true, []string{"index.<module>", "handlers/a.<module>"}},
		{"callback", "handlers/a.js", "createHash('sha1')", true, []string{"index.<module>", "handlers/a.<module>", "handlers/a.<anonymous>@4:18"}},
		{"transitive", "handlers/b.js", "createHash('sha224')", true, []string{"index.<module>", "handlers/a.<module>", "handlers/b.<module>"}},
		{"unimported", "lib/lib.js", "createHash('sha256')", false, nil},
		{"dynamic", "dynamic.js", "createHash('sha384')", false, nil},
	}
	report := &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}}
	for _, c := range cases {
		line := lineContaining(t, filepath.Join(root, c.file), c.needle)
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: c.file,
			Language: "javascript",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: c.id, StartLine: line, EndLine: line, Match: c.needle,
				Rules:    []entities.RuleInfo{{ID: "js.crypto." + c.id}},
				Metadata: map[string]string{"assetType": "algorithm"},
			}},
		})
	}
	graphs := exportEntryRoots(t, entryRootsFixture{root: root, result: &engine.DepScanResult{
		Report: report, CallGraph: graph, Ecosystem: ecosystemNode, ProjectRoot: root,
	}}, 0)
	for _, c := range cases {
		fg := graphs[c.id]
		if !c.reachable {
			if fg.Reachability != graphfrag.ReachabilityUnreachable {
				t.Errorf("%s reachability = %q, want unreachable", c.id, fg.Reachability)
			}
			continue
		}
		if fg.Reachability != graphfrag.ReachabilityReachable {
			t.Errorf("%s reachability = %q, want reachable", c.id, fg.Reachability)
			continue
		}
		if chains := shortChains(fg); !hasChain(chains, string(callgraph.RootKindMain), c.frames...) {
			t.Errorf("%s chains = %+v, want one %v rooted as main", c.id, chains, c.frames)
		}
	}
}

// Two modules that import each other: the export terminates. With nothing
// outside calling either, no root reaches the crypto and it stays unreachable
// (a cycle is not an entry point); once the package entry imports one of them,
// the crypto is reachable through the cycle.
func TestExportCallGraph_NodeModuleImportCycleTerminates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		extra map[string]string
		want  string
	}{
		{"no entry", nil, graphfrag.ReachabilityUnreachable},
		{"entry imports the cycle", map[string]string{"package.json": `{"main":"main.js"}`, "main.js": "import './a';\n"}, graphfrag.ReachabilityReachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			files := map[string]string{
				"a.js": "import './b';\n",
				"b.js": "import './a';\nimport crypto from 'crypto';\ncrypto.createHash('md5');\n",
			}
			for name, content := range tc.extra {
				files[name] = content
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			graph, err := callgraph.NewBuilderForEcosystem(ecosystemNode, callgraph.NewNodeParser()).
				BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			line := lineContaining(t, filepath.Join(root, "b.js"), "createHash('md5')")
			report := &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}, Findings: []entities.Finding{{
				FilePath: "b.js", Language: "javascript",
				CryptographicAssets: []entities.CryptographicAsset{{
					FindingID: "cycle", StartLine: line, EndLine: line, Match: "createHash('md5')",
					Rules:    []entities.RuleInfo{{ID: "js.crypto.cycle"}},
					Metadata: map[string]string{"assetType": "algorithm"},
				}},
			}}}
			graphs := exportEntryRoots(t, entryRootsFixture{root: root, result: &engine.DepScanResult{
				Report: report, CallGraph: graph, Ecosystem: ecosystemNode, ProjectRoot: root,
			}}, 0)
			if got := graphs["cycle"].Reachability; got != tc.want {
				t.Errorf("reachability = %q, want %q", got, tc.want)
			}
		})
	}
}
