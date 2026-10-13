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

package opengrep

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func execCommand(ctx context.Context, dir, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	return cmd
}

// TestConfigPrefixMatchesCLI pins the rule id prefixes `opengrep scan -d`
// printed for a rule file at /tmp/og1/rules/go/crypto/rules.yaml.
func TestConfigPrefixMatchesCLI(t *testing.T) {
	cases := []struct {
		configID, cwd, want string
	}{
		{"rules/go/crypto/rules.yaml", "/tmp/og1", "rules.go.crypto."},
		{"/tmp/og1/rules/go/crypto/rules.yaml", "/tmp", "og1.rules.go.crypto."},
		{"/tmp/og1/rules/go/crypto/rules.yaml", "/tmp/og1/tgt", "tmp.og1.rules.go.crypto."},
		{"/tmp/og1/rules/go/crypto/rules.yaml", "/", "tmp.og1.rules.go.crypto."},
		{"/tmp/run-1/go/merged-rules.yaml", "/home/u", "tmp.run-1.go."},
		{"/tmp/run-1/merged-rules.yaml", "/tmp/run-1", ""},
		{"../rules/x.yaml", "/home/u", "rules."},
		{"/c/.crypto-finder-filtered/v1/run+1/go/x.yaml", "/home", "c..crypto-finder-filtered.v1.run1.go."},
	}
	for _, c := range cases {
		if got := configPrefix(c.configID, c.cwd); got != c.want {
			t.Errorf("configPrefix(%q, %q) = %q, want %q", c.configID, c.cwd, got, c.want)
		}
	}
}

func TestIsConfigSuffix(t *testing.T) {
	cases := map[string]bool{
		"rules.yaml": true, "rules.yml": true, "rules.YAML": false, "rules.json": false,
		"rules.test.yaml": false, "rules.fixed.yaml": false, "rules.fixed.test.yaml": false,
		".hidden.yaml": true, "a.b.yaml": true, "yaml": false,
	}
	for name, want := range cases {
		if got := isConfigSuffix(name); got != want {
			t.Errorf("isConfigSuffix(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLoadCoreRulesetPrefixesAndDedupes(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"go/a.yaml": "rules:\n  - id: one\n    message: m\n    severity: INFO\n    languages: [go]\n    pattern: foo()\n    metadata: {x: 1}\n" +
			"  - id: two\n    message: m\n    severity: INFO\n    languages: [golang]\n    pattern: bar()\n",
		"go/b.yaml":      `{"rules":[{"id":"one","message":"m","severity":"INFO","languages":["go"],"pattern":"foo()","metadata":{"x":2}}]}`,
		"go/c.test.yaml": "rules: []\n",
		"go/sub/d.yml":   "rules:\n  - id: three\n    message: m\n    severity: WARNING\n    languages: [javascript, typescript]\n    pattern: baz()\n",
	})
	cwd := filepath.Dir(root)
	ruleset, err := loadCoreRuleset([]string{filepath.Join(root, "go")}, cwd)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(root) + ".go."
	ids := make([]string, 0, len(ruleset.rules))
	for _, rule := range ruleset.rules {
		ids = append(ids, rule.id)
	}
	// a.yaml and b.yaml hold the same rule "one" under the same prefix but
	// for metadata: the CLI keeps a.yaml's at b.yaml's position.
	want := []string{base + "two", base + "one", base + "sub.three"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("rule ids = %v, want %v", ids, want)
	}
	if string(ruleset.rules[1].metadata) != `{"x":1}` {
		t.Errorf("deduplicated rule kept metadata %s, want the first occurrence's", ruleset.rules[1].metadata)
	}
	if got := ruleset.rules[2].analyzers(); !reflect.DeepEqual(got, []string{"js", "ts"}) {
		t.Errorf("analyzers = %v", got)
	}
	if ruleset.coreReason != "" {
		t.Errorf("coreReason = %q", ruleset.coreReason)
	}
}

func TestLoadCoreRulesetFlagsWhatCoreModeCannotReproduce(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"r.yaml": "rules:\n  - id: g\n    message: m\n    severity: INFO\n    languages: [generic]\n    pattern: foo\n",
	})
	ruleset, err := loadCoreRuleset([]string{root}, "/")
	if err != nil {
		t.Fatal(err)
	}
	if ruleset.coreReason == "" || ruleset.rules[0].analyzers() != nil {
		t.Errorf("a generic rule must disable core mode, got reason %q", ruleset.coreReason)
	}
	writeTree(t, root, map[string]string{"r.yaml": "rules:\n  - id: p\n    message: m\n    severity: INFO\n    languages: [go]\n    pattern: foo()\n    paths: {include: [a]}\n"})
	if ruleset, err = loadCoreRuleset([]string{root}, "/"); err != nil || ruleset.coreReason == "" {
		t.Errorf("rule paths must disable core mode, got %v %q", err, ruleset.coreReason)
	}
	writeTree(t, root, map[string]string{"r.yaml": "rules:\n  - id: a\n    message: &m m\n    severity: INFO\n    languages: [go]\n    pattern: *m\n"})
	if _, err = loadCoreRuleset([]string{root}, "/"); err == nil {
		t.Error("a YAML alias has no JSON form and must make loading fail")
	}
}

func TestCachedRulesFileReuse(t *testing.T) {
	dir := t.TempDir()
	doc := []byte(`{"rules":[]}`)
	first, cleanup, err := cachedRulesFile(dir, "1.30.2", doc)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	second, _, err := cachedRulesFile(dir, "1.30.2", doc)
	if err != nil || first != second {
		t.Fatalf("cache path %q then %q (%v)", first, second, err)
	}
	if _, err := os.Stat(first); err != nil {
		t.Errorf("cached rules file must survive cleanup: %v", err)
	}
	other, _, err := cachedRulesFile(dir, "1.31.0", doc)
	if err != nil || other == first {
		t.Errorf("another OpenGrep version must get its own file, got %q", other)
	}
	temp, cleanup, err := cachedRulesFile("", "1.30.2", doc)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Errorf("an uncached rules file must be removed by cleanup")
	}
}
