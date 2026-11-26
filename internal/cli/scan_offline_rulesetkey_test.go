// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
)

// runDirSource is a remote ruleset as a leased one loads: the directory it
// was decrypted into for this run.
type runDirSource struct{ dir string }

func (s runDirSource) Load() ([]string, error) { return []string{s.dir}, nil }
func (s runDirSource) Name() string            { return "remote:dca@latest" }
func (s runDirSource) Info() entities.RulesInfo {
	return entities.RulesInfo{Source: "remote", Name: "dca", Version: "latest"}
}

func writeRunDir(t *testing.T, root, run, rule string) string {
	t.Helper()
	dir := filepath.Join(root, ".crypto-finder-filtered", "latest", run)
	if err := os.MkdirAll(filepath.Join(dir, "java"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "java", "rules.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A leased remote ruleset (--ruleset dca --offline) is keyed by the content
// of the per-run directory it was decrypted into, not by that directory's
// name, which changes every run.
func TestOfflineRulesetKeyOfALeasedRuleset(t *testing.T) {
	origDirs, origIndex, origCards := scanRuleDirs, scanCardsIndex, scanCardsDir
	t.Cleanup(func() { scanRuleDirs, scanCardsIndex, scanCardsDir = origDirs, origIndex, origCards })
	scanRuleDirs, scanCardsIndex, scanCardsDir = nil, "", ""

	root := t.TempDir()
	key := func(dir string) string {
		t.Helper()
		k, _, err := offlineRulesetKey(&lockedRules{manager: rules.NewManager(runDirSource{dir: dir})})
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	first := key(writeRunDir(t, root, "run-1", "rules: []\n"))
	if again := key(writeRunDir(t, root, "run-2", "rules: []\n")); again != first {
		t.Errorf("the same ruleset in another run directory keys %s, want %s", again, first)
	}
	if changed := key(writeRunDir(t, root, "run-3", "rules: [{id: x}]\n")); changed == first {
		t.Error("a changed rule file does not change the key")
	}
}
