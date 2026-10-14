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
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// fakeEngine writes executable scripts standing in for the opengrep CLI
// and opengrep-core. The CLI script appends its arguments to calls.log and
// prints one finding for check_id cliID; the core script prints coreJSON,
// or fails when coreJSON is empty.
type fakeEngine struct {
	dir, cli, core, log string
}

func newFakeEngine(t *testing.T, cliID, coreJSON string) *fakeEngine {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts stand in for opengrep")
	}
	dir := t.TempDir()
	f := &fakeEngine{dir: dir, cli: filepath.Join(dir, "opengrep"), core: filepath.Join(dir, "opengrep-core"), log: filepath.Join(dir, "calls.log")}
	cliScript := "#!/bin/sh\necho \"cli $*\" >> " + f.log + "\n" +
		`printf '{"results":[{"check_id":"` + cliID + `","path":"%s","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":2,"offset":1},"extra":{"message":"m","metadata":{},"metavars":{},"severity":"INFO","lines":"x"}}],"errors":[]}' "$FAKE_TARGET"` + "\nexit 1\n"
	coreScript := "#!/bin/sh\nif [ \"$1\" = -version ]; then echo 'opengrep-core version: 1.30.2'; exit 0; fi\necho \"core $*\" >> " + f.log + "\n"
	if coreJSON == "" {
		coreScript += "echo boom >&2\nexit 2\n"
	} else {
		coreScript += "cat <<'EOF'\n.\n" + coreJSON + "\nEOF\n"
	}
	for path, script := range map[string]string{f.cli: cliScript, f.core: coreScript} {
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // Executable test fixtures.
			t.Fatal(err)
		}
	}
	return f
}

func (f *fakeEngine) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func fakeScanner(t *testing.T, f *fakeEngine, version string, mode scanner.OpengrepMode, pf scanner.RulePrefilter) *Scanner {
	t.Helper()
	original := commandOutput
	t.Cleanup(func() { commandOutput = original })
	commandOutput = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("--x-ignore-semgrepignore-files --force-exclude"), nil
	}
	t.Setenv(CoreBinaryEnv, f.core)
	coreBinaries.Range(func(key, _ any) bool { coreBinaries.Delete(key); return true })
	return &Scanner{executablePath: f.cli, version: version, timeout: time.Minute, mode: mode, prefilter: pf, includeGitIgnored: true}
}

func fixtureProject(t *testing.T) (target, rules string) {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"src/a.go": "package a\n\nimport \"crypto/sha256\"\n\nfunc f() { sha256.New() }\n",
		"rules/go/merged-rules.yaml": `{"rules":[
{"id":"std.sha","message":"m","severity":"INFO","languages":["go"],"patterns":[{"pattern-inside":"import \"crypto/sha256\"\n...\n"},{"pattern":"sha256.New()"}]},
{"id":"x.hkdf","message":"m","severity":"INFO","languages":["go"],"patterns":[{"pattern-inside":"import \"golang.org/x/crypto/hkdf\"\n...\n"},{"pattern":"hkdf.New(...)"}]}
]}`,
	})
	target = filepath.Join(root, "src")
	t.Setenv("FAKE_TARGET", filepath.Join(target, "a.go"))
	return target, filepath.Join(root, "rules", "go")
}

func scanIDs(t *testing.T, s *Scanner, target, rules string) []string {
	t.Helper()
	report, err := s.Scan(context.Background(), target, []string{rules}, entities.ToolInfo{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var ids []string
	for _, finding := range report.Findings {
		for i := range finding.CryptographicAssets {
			for _, rule := range finding.CryptographicAssets[i].Rules {
				ids = append(ids, rule.ID)
			}
		}
	}
	return ids
}

func TestCoreModeFallsBackOnUnverifiedVersion(t *testing.T) {
	f := newFakeEngine(t, "x.std.sha", `{"results":[],"errors":[]}`)
	target, rules := fixtureProject(t)
	s := fakeScanner(t, f, "1.29.0", scanner.OpengrepModeCore, scanner.RulePrefilterOff)
	if ids := scanIDs(t, s, target, rules); len(ids) != 1 {
		t.Fatalf("findings = %v, want the CLI's one", ids)
	}
	if calls := f.calls(t); strings.Contains(calls, "core ") || !strings.Contains(calls, "cli ") {
		t.Errorf("an unverified version must run the CLI only, calls:\n%s", calls)
	}
}

func TestCoreModeFallsBackWhenCoreFails(t *testing.T) {
	f := newFakeEngine(t, "x.std.sha", "")
	target, rules := fixtureProject(t)
	s := fakeScanner(t, f, "1.30.2", scanner.OpengrepModeCore, scanner.RulePrefilterOff)
	if ids := scanIDs(t, s, target, rules); len(ids) != 1 {
		t.Fatalf("findings = %v, want the CLI's one", ids)
	}
	calls := f.calls(t)
	if !strings.Contains(calls, "core ") || !strings.Contains(calls, "cli ") {
		t.Errorf("a failing core must be retried with the CLI, calls:\n%s", calls)
	}
}

func TestCoreModeRunsCore(t *testing.T) {
	target, rules := fixtureProject(t)
	// The rules file holds distinct ids, so opengrep-core gets them as the
	// file spells them and the adapter adds the CLI's prefix back.
	id := "std.sha"
	coreJSON := `{"results":[{"check_id":"` + id + `","path":"` + filepath.Join(target, "a.go") +
		`","start":{"line":5,"col":12,"offset":45},"end":{"line":5,"col":24,"offset":57},"extra":{"message":"m","metadata":{},"metavars":{},"is_ignored":false}}],"errors":[]}`
	f := newFakeEngine(t, "unused", coreJSON)
	s := fakeScanner(t, f, "1.30.2", scanner.OpengrepModeCore, scanner.RulePrefilterOff)
	ids := scanIDs(t, s, target, rules)
	if len(ids) != 1 || ids[0] != "std.sha" {
		t.Fatalf("findings = %v, want the core finding cleaned to std.sha", ids)
	}
	calls := f.calls(t)
	if strings.Contains(calls, "cli ") || !strings.Contains(calls, "-taint_intrafile") {
		t.Errorf("core mode must not run the CLI, calls:\n%s", calls)
	}
}

func TestPrefilterRunsCLIWithKeptRulesAndRestoresIDs(t *testing.T) {
	target, rules := fixtureProject(t)
	cwd, err := physicalDir("")
	if err != nil {
		t.Fatal(err)
	}
	// The CLI reports the prefiltered file's prefix, the marker, then the id
	// the rule has in its original file.
	original := configPrefix(filepath.Join(rules, "merged-rules.yaml"), cwd) + "std.sha"
	f := newFakeEngine(t, "tmp.crypto-finder-prefilter-1."+prefilteredIDMarker+original, "")
	s := fakeScanner(t, f, "1.30.2", scanner.OpengrepModeCLI, scanner.RulePrefilterImports)
	ids := scanIDs(t, s, target, rules)
	if len(ids) != 1 || ids[0] != "std.sha" {
		t.Fatalf("findings = %v, want std.sha", ids)
	}
	calls := f.calls(t)
	if strings.Contains(calls, rules) || !strings.Contains(calls, "crypto-finder-prefilter-") {
		t.Errorf("the CLI must get the prefiltered rules file, calls:\n%s", calls)
	}
}

func TestOutcomeScansIgnoreModes(t *testing.T) {
	f := newFakeEngine(t, "x.std.sha", `{"results":[],"errors":[]}`)
	target, rules := fixtureProject(t)
	s := fakeScanner(t, f, "1.30.2", scanner.OpengrepModeCore, scanner.RulePrefilterImports)
	if _, err := s.ScanWithOutcome(context.Background(), target, []string{rules}, entities.ToolInfo{}); err != nil {
		t.Fatal(err)
	}
	calls := f.calls(t)
	if strings.Contains(calls, "core ") || !strings.Contains(calls, "--config "+rules) {
		t.Errorf("certification scans must run the CLI with the rules as given, calls:\n%s", calls)
	}
}

// TestCoreModeFallsBackWhenCoreRejectsARule pins that a rule opengrep-core
// could not load (reported at exit 0, the other rules' findings included)
// sends the scan to the CLI, which fails the run for such a rule, so a
// broken rules file fails a scan the same way in both modes.
func TestCoreModeFallsBackWhenCoreRejectsARule(t *testing.T) {
	target, rules := fixtureProject(t)
	coreJSON := `{"results":[{"check_id":"std.sha","path":"` + filepath.Join(target, "a.go") +
		`","start":{"line":5,"col":12,"offset":45},"end":{"line":5,"col":24,"offset":57},"extra":{"message":"m","metadata":{},"metavars":{},"is_ignored":false}}],` +
		`"errors":[{"error_type":"Rule parse error","severity":"error","message":"Expected one of pattern...","rule_id":"x.hkdf","location":{"path":"rules.json","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0}}}]}`
	f := newFakeEngine(t, "x.std.sha", coreJSON)
	s := fakeScanner(t, f, "1.30.2", scanner.OpengrepModeCore, scanner.RulePrefilterOff)
	if ids := scanIDs(t, s, target, rules); len(ids) != 1 || ids[0] != "x.std.sha" {
		t.Fatalf("findings = %v, want the CLI's x.std.sha", ids)
	}
	calls := f.calls(t)
	if !strings.Contains(calls, "core ") || !strings.Contains(calls, "cli ") {
		t.Errorf("a rule core rejects must send the scan to the CLI, calls:\n%s", calls)
	}
}
