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

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

func TestRulesImportThenStatus(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SCANOSS_API_KEY", "test-key")
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", map[string]string{"rules/java/aes.yaml": rulesettest.RuleYAML}, time.Now().Add(400*24*time.Hour))
	bundlePath := filepath.Join(t.TempDir(), "dca-v1.40.0.tar.gz")
	if err := os.WriteFile(bundlePath, issued.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath+".lease.json", issued.LeaseJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runRulesImport(cmd, []string{bundlePath}); err != nil {
		t.Fatal(err)
	}
	expires := issued.Lease.ExpiresAt.UTC().Format(time.RFC3339)
	if !strings.Contains(out.String(), "dca@v1.40.0") || !strings.Contains(out.String(), expires) {
		t.Fatalf("import output: %q", out.String())
	}

	out.Reset()
	if err := runRulesStatus(cmd, nil); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || strings.Join(strings.Fields(lines[1]), " ") != "dca v1.40.0 leased "+expires+" test-key-1 java" {
		t.Fatalf("status output:\n%s", out.String())
	}

	if err := runRulesImport(cmd, []string{filepath.Join(home, "missing.tar.gz")}); err == nil {
		t.Fatal("importing a missing file succeeded")
	}
}
