// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const javaKeyPairRules = `rules:
  - id: java.kpg.ec
    message: ec
    severity: INFO
    pattern: KeyPairGenerator.getInstance("EC")
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: EC
        operation: keygen
        parameterCondition: param[0]==EC
        api: java.security.KeyPairGenerator.getInstance
`

// namedValueAnchor is the generic finding at the one line of rel that holds
// match, the shape a rule matching any algorithm argument reports.
func namedValueAnchor(t *testing.T, dir, rel, match, ruleID, language, api string) *entities.InterimReport {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(src), "\n") {
		col := strings.Index(line, match)
		if col < 0 {
			continue
		}
		return &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: filepath.Join(dir, filepath.FromSlash(rel)), Language: language,
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: i + 1, EndLine: i + 1, StartCol: col + 1, EndCol: col + 1 + len(match), Match: match,
				Rules:    []entities.RuleInfo{{ID: ruleID}},
				Metadata: map[string]string{"api": api, "assetType": "algorithm"},
			}},
		}}}
	}
	t.Fatalf("%s holds no %q", rel, match)
	return nil
}

func writeSourceTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func specializedRules(report *entities.InterimReport, anchorID string) (rules []string, anchor bool) {
	for i := range report.Findings[0].CryptographicAssets {
		id := report.Findings[0].CryptographicAssets[i].Rules[0].ID
		if id == anchorID {
			anchor = true
			continue
		}
		rules = append(rules, id)
	}
	slices.Sort(rules)
	return rules, anchor
}

// An enum constant's name() or a String constant declared in another file
// specializes a dynamic key-pair finding, at the call and through a parameter.
func TestMaterializeConditionedFindings_JavaNamedValueInAnotherFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, file, match string
		wantRules         []string
	}{
		{"enum name at the call", "app/Direct.java", "KeyPairGenerator.getInstance(AlgoName.EC.name())", []string{"java.kpg.ec"}},
		{"enum name through a parameter", "app/Keys.java", "KeyPairGenerator.getInstance(alg)", []string{"java.kpg.ec"}},
		{"constant at the call", "app/Constant.java", "KeyPairGenerator.getInstance(Names.CURVE)", []string{"java.kpg.ec"}},
		{"overridden toString stays generic", "app/Override.java", "KeyPairGenerator.getInstance(Labeled.EC.toString())", nil},
	}
	dir := writeSourceTree(t, map[string]string{
		"lib/algo/AlgoName.java": "package lib.algo;\npublic enum AlgoName { EC, RSA }\n",
		"lib/algo/Labeled.java":  "package lib.algo;\npublic enum Labeled {\n    EC;\n    @Override public String toString() { return \"ecdsa\"; }\n}\n",
		"lib/algo/Names.java":    "package lib.algo;\npublic final class Names {\n    public static final String CURVE = \"EC\";\n}\n",
		"app/Direct.java": `package app;
import java.security.KeyPairGenerator;
import lib.algo.AlgoName;
public class Direct {
    void gen() throws Exception {
        KeyPairGenerator.getInstance(AlgoName.EC.name());
    }
}
`,
		"app/Keys.java": `package app;
import java.security.KeyPairGenerator;
public class Keys {
    static void gen(String alg) throws Exception {
        KeyPairGenerator.getInstance(alg);
    }
}
`,
		"app/Main.java": `package app;
import lib.algo.AlgoName;
public class Main {
    void run() throws Exception {
        Keys.gen(AlgoName.EC.name());
    }
}
`,
		"app/Constant.java": `package app;
import java.security.KeyPairGenerator;
import lib.algo.Names;
public class Constant {
    void gen() throws Exception {
        KeyPairGenerator.getInstance(Names.CURVE);
    }
}
`,
		"app/Override.java": `package app;
import java.security.KeyPairGenerator;
import lib.algo.Labeled;
public class Override {
    void gen() throws Exception {
        KeyPairGenerator.getInstance(Labeled.EC.toString());
    }
}
`,
	})
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, javaKeyPairRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := namedValueAnchor(t, dir, tt.file, tt.match, "java.kpg.dynamic", "java", "java.security.KeyPairGenerator.getInstance")
			MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java", ProjectRoot: dir, RootModule: "com.app:app"}, []string{rules})
			got, anchor := specializedRules(report, "java.kpg.dynamic")
			if !slices.Equal(got, tt.wantRules) || anchor != (len(tt.wantRules) == 0) {
				t.Fatalf("specialized rules = %v, generic anchor = %v; want %v", got, anchor, tt.wantRules)
			}
		})
	}
}

// A module constant or Enum member declared in another Python module
// specializes a dynamic digest finding, at the call and through a parameter.
func TestMaterializeConditionedFindings_PythonNamedValueInAnotherModule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, file, match string
		wantRules         []string
	}{
		{"enum value at the call", "app/direct.py", "hashlib.new(Alg.SHA.value, data)", []string{"py.hash.sha256"}},
		{"module attribute at the call", "app/attr.py", "hashlib.new(settings.WEAK, data)", []string{"py.hash.md5"}},
		{"imported constant through a parameter", "app/hasher.py", "hashlib.new(alg, data)", []string{"py.hash.md5", "py.hash.sha256"}},
	}
	dir := writeSourceTree(t, map[string]string{
		"app/__init__.py":     "",
		"app/cfg/__init__.py": "",
		"app/cfg/settings.py": "from enum import Enum\n\nWEAK = \"md5\"\n\nclass Alg(Enum):\n    SHA = \"sha256\"\n",
		"app/direct.py":       "import hashlib\nfrom app.cfg.settings import Alg\n\ndef run(data):\n    return hashlib.new(Alg.SHA.value, data)\n",
		"app/attr.py":         "import hashlib\nfrom app.cfg import settings\n\ndef run(data):\n    return hashlib.new(settings.WEAK, data)\n",
		"app/hasher.py":       pythonHasherModule,
		"app/main.py":         "from app.hasher import digest\nfrom app.cfg.settings import WEAK, Alg\n\ndigest(b\"x\", WEAK)\ndigest(b\"y\", Alg.SHA.value)\n",
	})
	graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, pythonDigestRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := namedValueAnchor(t, dir, tt.file, tt.match, "py.hash.dynamic", "python", "hashlib.new")
			MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "python", ProjectRoot: dir}, []string{rules})
			got, anchor := specializedRules(report, "py.hash.dynamic")
			if !slices.Equal(got, tt.wantRules) || anchor {
				t.Fatalf("specialized rules = %v, generic anchor = %v; want %v and no anchor", got, anchor, tt.wantRules)
			}
		})
	}
}
