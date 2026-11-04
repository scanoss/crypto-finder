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

package semgrep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/config"
)

// The rules of a leased ruleset are read from a per-run directory under
// <name>/.crypto-finder-filtered/<version>/, and the cached ruleset beside
// it holds .cache-meta.json instead of manifest.json.
func TestDetectRuleVersion_LeasedRunDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rulesetsDir, err := config.GetRulesetsDir()
	if err != nil {
		t.Fatal(err)
	}
	cached := filepath.Join(rulesetsDir, "dca", "latest")
	runDir := filepath.Join(rulesetsDir, "dca", config.FilteredRulesDirName, "latest", "run-1")
	for _, dir := range []string{cached, filepath.Join(runDir, "rules")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cached, ".cache-meta.json"), []byte(`{"ruleset_name":"dca","version":"v1.40.0","leased":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(runDir, "rules", "aes.yaml")
	if got := detectRuleVersion([]string{rule}); got != "v1.40.0" {
		t.Fatalf("detectRuleVersion(run dir) = %q, want v1.40.0", got)
	}
	if got := detectRuleVersion([]string{filepath.Join(rulesetsDir, "dca", config.FilteredRulesDirName)}); got != "" {
		t.Fatalf("detectRuleVersion(runs root) = %q, want empty", got)
	}
}
