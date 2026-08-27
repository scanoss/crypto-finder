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
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// TestOpengrep_PythonEndColConventionPinning (T0.7/row 6,
// python-parser-parity-2) mirrors TestOpengrep_EndColConventionPinning for
// Python: run the real opengrep binary over a Python fixture with one
// crypto call, and compare its match columns to the PythonParser's own
// StartCol/EndCol for that SAME call — both must agree on the identical
// 1-based, start-inclusive/end-exclusive convention. Absent binary or an
// unusable environment produces an explicit t.Skipf reason, never a silent
// pass.
func TestOpengrep_PythonEndColConventionPinning(t *testing.T) {
	t.Parallel()

	bin, err := exec.LookPath("opengrep")
	if err != nil {
		if bin, err = exec.LookPath("semgrep"); err != nil {
			t.Skip("neither opengrep nor semgrep in PATH; skipping Python column-convention pin")
		}
	}

	// `hashlib.sha256(data)` is exactly 21 characters; the pattern matches
	// that span exactly.
	const matched = "hashlib.sha256(data)"
	dir := t.TempDir()
	target := filepath.Join(dir, "crypto_utils.py")
	src := "import hashlib\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n"
	if err := os.WriteFile(target, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, matched) {
		t.Fatalf("fixture source does not contain the expected matched text %q", matched)
	}

	// Independently derive the SAME call's columns from the real parser —
	// the value this test pins opengrep's convention against.
	p := callgraph.NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "pkg")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	var parserStartCol, parserEndCol, parserLine int
	found := false
	for _, a := range analyses {
		for _, fn := range a.Functions {
			for _, c := range fn.Calls {
				if c.Callee.Package == "hashlib" && c.Callee.Name == "sha256" {
					parserStartCol, parserEndCol, parserLine = c.StartCol, c.EndCol, c.Line
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("PythonParser did not resolve the hashlib.sha256(data) call in the fixture")
	}

	ruleFile := filepath.Join(dir, "rule.yaml")
	rule := "rules:\n- id: col-pin-python\n  languages: [python]\n  message: pin\n  severity: INFO\n  pattern: hashlib.sha256(...)\n"
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}

	// opengrep uses a `scan` subcommand and rejects --metrics; semgrep
	// accepts the flat form with --metrics off. Branch on the binary.
	var args []string
	if strings.Contains(filepath.Base(bin), "opengrep") {
		args = []string{"scan", "--json", "--config", ruleFile, dir}
	} else {
		args = []string{"--json", "--metrics", "off", "--config", ruleFile, dir}
	}
	out, runErr := exec.CommandContext(context.Background(), bin, args...).Output()
	if runErr != nil {
		t.Skipf("%s present but unusable in this environment: %v", bin, runErr)
	}

	var parsed entities.SemgrepOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Skipf("could not parse %s JSON output (env issue?): %v", bin, err)
	}
	if len(parsed.Results) == 0 {
		t.Skipf("%s produced no results (env issue?)", bin)
	}

	r := parsed.Results[0]
	if r.Start.Col < 1 {
		t.Errorf("Start.Col = %d, want >= 1 (columns must be 1-based)", r.Start.Col)
	}
	if span := r.End.Col - r.Start.Col; span != len(matched) {
		t.Errorf("End.Col(%d) - Start.Col(%d) = %d, want %d (len %q): End.Col must be EXCLUSIVE",
			r.End.Col, r.Start.Col, span, len(matched), matched)
	}
	if r.Start.Line != parserLine {
		t.Errorf("opengrep match line = %d, want parser line %d", r.Start.Line, parserLine)
	}
	if r.Start.Col != parserStartCol {
		t.Errorf("opengrep Start.Col = %d, want parser StartCol = %d (both MUST agree on the same 1-based convention)", r.Start.Col, parserStartCol)
	}
	if r.End.Col != parserEndCol {
		t.Errorf("opengrep End.Col = %d, want parser EndCol = %d (both MUST agree on the same exclusive-end convention)", r.End.Col, parserEndCol)
	}
}
