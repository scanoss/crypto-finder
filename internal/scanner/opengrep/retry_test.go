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
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// timeoutEngine is a fake opengrep CLI whose first scan reports a Timeout
// for rule id on the target, as the CLI does under load, and whose retry
// (the run with the retry's 30 s limit) reports the match.
func timeoutEngine(t *testing.T, id string) *fakeEngine {
	t.Helper()
	return limitEngine(t, id, `{"code":2,"level":"warn","type":"Timeout","rule_id":"`+id+
		`","message":"Timeout when running `+id+` on %s:\\n ","path":"%s"}`)
}

// interruptedParseEngine is timeoutEngine for a first scan whose time limit
// interrupted the parse of the target, which the CLI reports as a syntax
// error naming no rule.
func interruptedParseEngine(t *testing.T, id string) *fakeEngine {
	t.Helper()
	return limitEngine(t, id, `{"code":2,"level":"warn","type":"Other syntax error",`+
		`"message":"Other syntax error at line %s:1:\\n Memprof_limits.Limit_reached: token set","path":"%s"}`)
}

// limitEngine is a fake opengrep CLI whose first scan reports firstError (a
// format taking the target twice) and whose retry reports the match of id.
func limitEngine(t *testing.T, id, firstError string) *fakeEngine {
	t.Helper()
	f := newFakeEngine(t, "unused", "")
	timeoutJSON := `{"results":[],"errors":[` + firstError + `]}`
	matchJSON := `{"results":[{"check_id":"tmp.crypto-finder-prefilter-9.` + prefilteredIDMarker + id +
		`","path":"%s","start":{"line":5,"col":12,"offset":45},"end":{"line":5,"col":24,"offset":57},"extra":{"message":"m","metadata":{},"metavars":{},"severity":"INFO","lines":"x"}}],"errors":[]}`
	script := "#!/bin/sh\necho \"cli $*\" >> " + f.log + "\n" +
		"case \"$*\" in *--timeout\\ 30*) printf '" + matchJSON + "' \"$FAKE_TARGET\";;\n" +
		"*) printf '" + timeoutJSON + "' \"$FAKE_TARGET\" \"$FAKE_TARGET\";; esac\nexit 0\n"
	if err := os.WriteFile(f.cli, []byte(script), 0o700); err != nil { // Executable test fixture.
		t.Fatal(err)
	}
	return f
}

func TestRuleTimeoutIsRetriedWithLongerLimit(t *testing.T) {
	target, rules := fixtureProject(t)
	cwd, err := physicalDir("")
	if err != nil {
		t.Fatal(err)
	}
	id := configPrefix(filepath.Join(rules, "merged-rules.yaml"), cwd) + "std.sha"
	for _, mode := range []struct {
		name string
		pf   scanner.RulePrefilter
	}{{"cli", scanner.RulePrefilterOff}, {"prefilter", scanner.RulePrefilterImports}} {
		t.Run(mode.name, func(t *testing.T) {
			f := timeoutEngine(t, id)
			if mode.pf == scanner.RulePrefilterImports {
				// The prefiltered first run reports ids behind the marker too.
				data, err := os.ReadFile(f.cli)
				if err != nil {
					t.Fatal(err)
				}
				script := strings.Replace(string(data), `"rule_id":"`+id, `"rule_id":"tmp.crypto-finder-prefilter-1.`+prefilteredIDMarker+id, 1)
				if err := os.WriteFile(f.cli, []byte(script), 0o700); err != nil { // Executable test fixture.
					t.Fatal(err)
				}
			}
			s := fakeScanner(t, f, "1.30.2", scanner.OpengrepModeCLI, mode.pf)
			report, err := s.Scan(context.Background(), target, []string{rules}, entities.ToolInfo{})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != 1 || report.Findings[0].CryptographicAssets[0].Rules[0].ID != "std.sha" {
				t.Fatalf("findings = %+v, want std.sha recovered by the retry", report.Findings)
			}
			if len(report.IncompleteFiles) != 0 {
				t.Errorf("a recovered timeout must not leave the file incomplete: %v", report.IncompleteFiles)
			}
			calls := strings.Split(strings.TrimSpace(f.calls(t)), "\n")
			if len(calls) != 2 {
				t.Fatalf("want the scan and one retry, calls:\n%s", strings.Join(calls, "\n"))
			}
			retry := calls[1]
			if !strings.Contains(retry, "--timeout 30") || !strings.Contains(retry, "crypto-finder-prefilter-") ||
				!strings.HasSuffix(retry, filepath.Join(target, "a.go")) {
				t.Errorf("retry must run the timed-out rule on the file with a 30 s limit, got %s", retry)
			}
		})
	}
}

// TestInterruptedParseIsRetried pins a file whose parse the time limit cut
// short: no rule ran on it and the error names none, yet the retry must run
// every rule on it, or a busy host silently loses all of its findings.
func TestInterruptedParseIsRetried(t *testing.T) {
	target, rules := fixtureProject(t)
	cwd, err := physicalDir("")
	if err != nil {
		t.Fatal(err)
	}
	id := configPrefix(filepath.Join(rules, "merged-rules.yaml"), cwd) + "std.sha"
	for _, mode := range []struct {
		name string
		pf   scanner.RulePrefilter
	}{{"cli", scanner.RulePrefilterOff}, {"prefilter", scanner.RulePrefilterImports}} {
		t.Run(mode.name, func(t *testing.T) {
			f := interruptedParseEngine(t, id)
			s := fakeScanner(t, f, "1.30.2", scanner.OpengrepModeCLI, mode.pf)
			report, err := s.Scan(context.Background(), target, []string{rules}, entities.ToolInfo{})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != 1 || report.Findings[0].CryptographicAssets[0].Rules[0].ID != "std.sha" {
				t.Fatalf("findings = %+v, want std.sha recovered by the retry", report.Findings)
			}
			if len(report.IncompleteFiles) != 0 {
				t.Errorf("a recovered parse must not leave the file incomplete: %v", report.IncompleteFiles)
			}
			calls := strings.Split(strings.TrimSpace(f.calls(t)), "\n")
			if len(calls) != 2 || !strings.Contains(calls[1], "--timeout 30") || !strings.HasSuffix(calls[1], filepath.Join(target, "a.go")) {
				t.Fatalf("want the scan and one retry of the file with a 30 s limit, calls:\n%s", strings.Join(calls, "\n"))
			}
		})
	}
}

func TestTimeoutsListInterruptedParses(t *testing.T) {
	interrupted := entities.SemgrepError{Type: "Other syntax error", Path: "/a.c", Message: "Other syntax error at line /a.c:1:\n Memprof_limits.Limit_reached: token set"}
	syntax := entities.SemgrepError{Type: "Syntax error", Path: "/b.c", Message: "Syntax error at line /b.c:3"}
	got := timeouts([]entities.SemgrepError{
		{Type: "Timeout", RuleID: "p.a", Path: "/a.c"},
		interrupted,
		{Type: "Timeout", RuleID: "p.b", Path: "/a.c"},
		syntax,
		{Type: "Timeout", RuleID: "p.a", Path: "/c.c"},
	})
	want := timedOut{"/a.c": {}, "/c.c": {"p.a": true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("timeouts = %v, want %v: an interrupted parse reruns the whole file, other syntax errors nothing", got, want)
	}
	a := &coreRule{ruleBase: &ruleBase{baseID: "a"}, id: "p.a"}
	b := &coreRule{ruleBase: &ruleBase{baseID: "b"}, id: "p.b"}
	plan := planRetry(got, []*coreRule{a, b})
	if !plan.whole["/a.c"] || plan.whole["/c.c"] || len(plan.rules) != 2 {
		t.Fatalf("plan = %+v, want /a.c whole and every rule", plan)
	}
	output := &entities.SemgrepOutput{Errors: []entities.SemgrepError{interrupted, syntax}}
	merged, _, still := mergeRetry(output, &entities.SemgrepOutput{}, plan)
	if still != 0 || len(merged.Errors) != 1 || merged.Errors[0].Path != "/b.c" {
		t.Errorf("errors = %+v still %d: the retry's errors replace the interrupted parse, other errors stay", merged.Errors, still)
	}
	merged, _, still = mergeRetry(output, &entities.SemgrepOutput{Errors: []entities.SemgrepError{interrupted}}, plan)
	if still != 1 || len(merged.Errors) != 2 {
		t.Errorf("errors = %+v still %d: a parse interrupted again stays reported", merged.Errors, still)
	}
}

func TestPlanRetry(t *testing.T) {
	a := &coreRule{ruleBase: &ruleBase{baseID: "a"}, id: "p.a"}
	b := &coreRule{ruleBase: &ruleBase{baseID: "b"}, id: "p.b"}
	c := &coreRule{ruleBase: &ruleBase{baseID: "c"}, id: "p.c"}
	d := &coreRule{ruleBase: &ruleBase{baseID: "d"}, id: "p.d"}
	ran := []*coreRule{a, b, c, d}
	plan := planRetry(timedOut{
		"/x/One.java":   {"p.b": true, "p.gone": true},
		"/x/Three.java": {"p.a": true, "p.b": true, "p.c": true},
		"/x/Gone.java":  {"p.unknown": true},
	}, ran)
	if !reflect.DeepEqual(plan.files, []string{"/x/One.java", "/x/Three.java"}) {
		t.Errorf("files = %v; a file whose only timed-out rule is unknown has nothing to retry", plan.files)
	}
	// Three timeouts reach the CLI's threshold, after which it skipped the
	// file's other rules: the whole file runs again.
	if !plan.whole["/x/Three.java"] || plan.whole["/x/One.java"] {
		t.Errorf("whole = %v", plan.whole)
	}
	ids := make([]string, 0, len(plan.rules))
	for _, rule := range plan.rules {
		ids = append(ids, rule.id)
	}
	if !reflect.DeepEqual(ids, []string{"p.a", "p.b", "p.c", "p.d"}) {
		t.Errorf("rules = %v, want every rule in scan order", ids)
	}
	if !plan.covers("/x/One.java", "p.b") || plan.covers("/x/One.java", "p.a") || !plan.covers("/x/Three.java", "p.d") {
		t.Error("covers must hold the timed-out pairs and every rule of whole files")
	}
}

func TestMergeRetry(t *testing.T) {
	result := func(id, path string, offset int) entities.SemgrepResult {
		return entities.SemgrepResult{CheckID: id, Path: path, Start: entities.SemgrepLocation{Line: offset, Offset: offset}, End: entities.SemgrepLocation{Line: offset, Offset: offset + 1}}
	}
	timeout := func(id, path string) entities.SemgrepError {
		return entities.SemgrepError{Type: "Timeout", Level: "warn", RuleID: id, Path: path}
	}
	var partial any
	if err := json.Unmarshal([]byte(`["PartialParsing",[]]`), &partial); err != nil {
		t.Fatal(err)
	}
	output := &entities.SemgrepOutput{
		Results: []entities.SemgrepResult{result("p.a", "/b.java", 3), result("p.b", "/a.java", 9)},
		Errors:  []entities.SemgrepError{timeout("p.a", "/a.java"), timeout("p.c", "/a.java"), timeout("p.a", "/z.java"), {Type: partial, Path: "/a.java"}},
	}
	plan := &retryPlan{files: []string{"/a.java"}, whole: map[string]bool{}, pairs: timedOut{"/a.java": {"p.a": true, "p.c": true}}}
	retried := &entities.SemgrepOutput{
		Results: []entities.SemgrepResult{
			result("p.a", "/a.java", 1), // recovered
			result("p.b", "/a.java", 9), // already found, not a planned pair
			result("p.b", "/a.java", 2), // a rule that never timed out on the file
		},
		Errors: []entities.SemgrepError{timeout("p.c", "/a.java"), {Type: partial, Path: "/a.java"}},
	}
	merged, recovered, still := mergeRetry(output, retried, plan)
	if recovered != 1 || still != 1 {
		t.Errorf("recovered %d still %d, want 1 1", recovered, still)
	}
	got := make([]string, 0, len(merged.Results))
	for _, r := range merged.Results {
		got = append(got, r.CheckID+"@"+r.Path)
	}
	if want := []string{"p.a@/a.java", "p.b@/a.java", "p.a@/b.java"}; !reflect.DeepEqual(got, want) {
		t.Errorf("results = %v, want %v in the CLI's order", got, want)
	}
	errs := make([]string, 0, len(merged.Errors))
	for _, e := range merged.Errors {
		errs = append(errs, errorTypeName(e.Type)+":"+e.RuleID+"@"+e.Path)
	}
	// p.a on /a.java is recovered; p.c timed out again; /z.java was not
	// retried; the retry's other errors repeat the first run's.
	if want := []string{"Timeout:p.a@/z.java", "PartialParsing:@/a.java", "Timeout:p.c@/a.java"}; !reflect.DeepEqual(errs, want) {
		t.Errorf("errors = %v, want %v", errs, want)
	}
	if len(output.Results) != 2 {
		t.Error("the first run's output must not change")
	}
}

func TestRetryRuleTimeout(t *testing.T) {
	for configured, want := range map[uint8]int{0: 30, 5: 30, 30: 120, 100: 255} {
		if got := (&Scanner{ruleTimeout: configured}).retryRuleTimeout(); got != want {
			t.Errorf("retry limit for %d = %d, want %d", configured, got, want)
		}
	}
}
