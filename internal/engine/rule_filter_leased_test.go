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

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/config"
)

// The rule files of a leased ruleset decrypted for a run are found, and a
// filtered copy lands in the same runs directory.
func TestLeasedRunDir_RuleFilesAndFilteredCopy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rulesetsDir, err := config.GetRulesetsDir()
	if err != nil {
		t.Fatal(err)
	}
	runsDir := cache.RunsDir(rulesetsDir, "dca", "latest")
	runDir, err := cache.NewRunDir(runsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"rules/java", "rules/python"} {
		if err := os.MkdirAll(filepath.Join(runDir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	javaRule := writeRuleFile(t, filepath.Join(runDir, "rules", "java"), "aes.yaml", "rules:\n  - id: aes\n    languages: [java]\n")
	pyRule := writeRuleFile(t, filepath.Join(runDir, "rules", "python"), "aes.yaml", "rules:\n  - id: aes\n    languages: [python]\n")

	files := expandRulePaths([]string{runDir})
	if len(files) != 2 || files[0] != javaRule || files[1] != pyRule {
		t.Fatalf("rule files = %v", files)
	}

	if got := filteredRunsParent(javaRule); got != runsDir {
		t.Fatalf("filteredRunsParent = %s, want %s", got, runsDir)
	}
	filtered, cleanup, err := prepareRulePathsForScanner([]string{runDir}, []string{"java"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(filtered) != 1 || !strings.HasPrefix(filtered[0], runsDir+string(os.PathSeparator)) {
		t.Fatalf("filtered rules at %v, want under %s", filtered, runsDir)
	}
}
