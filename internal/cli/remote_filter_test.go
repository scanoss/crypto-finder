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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/rules/prefilter"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/skip"
)

func TestRemoteFilterProfile(t *testing.T) {
	target := t.TempDir()
	for name, content := range map[string]string{
		"App.java":            "import javax.crypto.Cipher;\n",
		"vendor/lib/Lib.java": "import org.bouncycastle.jce.X;\n",
	} {
		path := filepath.Join(target, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	enabled := remoteFilterOptions{scanner: opengrep.ScannerName, prefilter: scanner.RulePrefilterImports}
	for name, opts := range map[string]remoteFilterOptions{
		"prefilter off":    {scanner: opengrep.ScannerName, prefilter: scanner.RulePrefilterOff},
		"semgrep":          {scanner: "semgrep", prefilter: scanner.RulePrefilterImports},
		"dependencies":     {scanner: opengrep.ScannerName, prefilter: scanner.RulePrefilterImports, scanDependencies: true},
		"no-remote-filter": {scanner: opengrep.ScannerName, prefilter: scanner.RulePrefilterImports, noRemoteFilter: true},
	} {
		if remoteFilterProfile(target, skip.NewDefaultMatcher(), opts) != nil {
			t.Errorf("%s: the whole ruleset must be downloaded", name)
		}
	}
	builder := remoteFilterProfile(target, skip.NewDefaultMatcher(), enabled)
	if builder == nil {
		t.Fatal("expected a profile builder")
	}
	index := &prefilter.Index{
		Languages: []string{"go", "java"},
		Modules:   map[prefilter.Family][]string{prefilter.FamilyJava: {"javax.crypto", "org.bouncycastle"}, prefilter.FamilyGo: {"crypto/aes"}}, //nolint:exhaustive // A partial profile.
	}
	profile, err := builder(context.Background(), index)
	if err != nil {
		t.Fatalf("builder: %v", err)
	}
	if len(profile.Languages) != 1 || profile.Languages[0] != "java" {
		t.Errorf("languages = %v, want [java]", profile.Languages)
	}
	if modules := profile.Modules[prefilter.FamilyJava]; len(modules) != 1 || modules[0] != "javax.crypto" {
		t.Errorf("java modules = %v, want [javax.crypto] (vendor is skipped)", modules)
	}
	if _, ok := profile.Modules[prefilter.FamilyGo]; ok {
		t.Error("a family without files must be absent")
	}
}
