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
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
)

func testRule(t *testing.T, raw string) *coreRule {
	t.Helper()
	base, err := newRuleBase([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return &coreRule{ruleBase: base, prefix: "p.", id: "p." + base.baseID}
}

// coreStdout is opengrep-core 1.30.2 output for two rules over one file,
// with its progress dots, trimmed to what the adapter reads plus fields it
// must ignore.
const coreStdout = ".\n.\n" + `{"version":"1.30.2","results":[
 {"check_id":"p.b","path":"PATH","start":{"line":3,"col":2,"offset":20},"end":{"line":4,"col":5,"offset":40},
  "extra":{"metavars":{"$X":{"start":{"line":3,"col":6,"offset":24},"end":{"line":3,"col":7,"offset":25},"abstract_content":"k"}},
   "engine_kind":"OSS","is_ignored":false,"message":"uses k","metadata":{"crypto":{"api":"x"}},"validation_state":"NO_VALIDATOR"}},
 {"check_id":"p.a","path":"PATH","start":{"line":3,"col":2,"offset":20},"end":{"line":3,"col":9,"offset":27},
  "extra":{"metavars":{},"is_ignored":false,"message":"","metadata":{}}},
 {"check_id":"p.a","path":"PATH","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":4,"offset":3},
  "extra":{"metavars":{},"is_ignored":true,"message":"silenced","metadata":{}}},
 {"check_id":"p.a","path":"PATH","start":{"line":2,"col":1,"offset":10},"end":{"line":2,"col":4,"offset":13},
  "extra":{"metavars":{},"is_ignored":false,"message":"first","metadata":{}}}
],"errors":[
 {"error_type":"Timeout","severity":"error","message":"timed out","rule_id":"p.a","location":{"path":"PATH","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0}}},
 {"error_type":["PartialParsing",[{"path":"PATH","start":{"line":5,"col":1,"offset":50},"end":{"line":5,"col":3,"offset":52}}]],"severity":"warn","message":"partial","location":{"path":"PATH","start":{"line":5,"col":1,"offset":50},"end":{"line":5,"col":3,"offset":52}}}
],"paths":{"scanned":["PATH"]},"skipped_rules":[]}`

func TestConvertCoreOutputLikeCLI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.go")
	writeTree(t, dir, map[string]string{"a.go": "x1\r\nx2\n\tk := f(k)\n  g()\nbad\xffline\n"})
	rules := []*coreRule{
		testRule(t, `{"id":"a","message":"rule a","severity":"WARNING","languages":["go"],"pattern":"f()","metadata":{"purl":"pkg:golang/x","crypto":{"api":"a"}}}`),
		testRule(t, `{"id":"b","message":"rule b","severity":"INFO","languages":["go"],"pattern":"g()","metadata":{"category":"security"}}`),
	}
	parsed, err := parseCoreOutput([]byte(strings.ReplaceAll(coreStdout, "PATH", path)))
	if err != nil {
		t.Fatal(err)
	}
	out, err := convertCoreOutput(parsed, rules, false, "")
	if err != nil {
		t.Fatal(err)
	}
	// Core run with the rules' own ids reports them; results still carry the
	// CLI's prefixed ids.
	unprefixed := strings.NewReplacer(`"check_id":"p.`, `"check_id":"`, `"rule_id":"p.`, `"rule_id":"`).Replace(strings.ReplaceAll(coreStdout, "PATH", path))
	parsedBase, err := parseCoreOutput([]byte(unprefixed))
	if err != nil {
		t.Fatal(err)
	}
	outBase, err := convertCoreOutput(parsedBase, rules, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(outBase, out) {
		t.Errorf("base-id core output converts to\n%+v\nwant\n%+v", outBase, out)
	}
	got := make([]string, 0, len(out.Results))
	for _, r := range out.Results {
		got = append(got, r.CheckID+"@"+r.Extra.Message+"|"+r.Extra.Severity+"|"+r.Extra.Lines)
	}
	// Ordered by location, then rule id; the nosemgrep-silenced match is gone;
	// an empty message falls back to the rule's.
	want := []string{"p.a@first|WARNING|x2", "p.a@rule a|WARNING|\tk := f(k)", "p.b@uses k|INFO|\tk := f(k)\n  g()"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results =\n%q\nwant\n%q", got, want)
	}
	if out.Results[0].Extra.Metadata.PURL != "pkg:golang/x" || out.Results[0].Extra.Metadata.Crypto["api"] != "a" {
		t.Errorf("rule metadata not carried: %+v", out.Results[0].Extra.Metadata)
	}
	if out.Results[2].Extra.Metadata.Category != "security" || out.Results[2].Extra.Metadata.Crypto["api"] != "x" {
		t.Errorf("core metadata must update rule metadata: %+v", out.Results[2].Extra.Metadata)
	}
	if out.Results[2].Extra.Metavars["$X"].AbstractContent != "k" {
		t.Errorf("metavars lost: %+v", out.Results[2].Extra.Metavars)
	}

	if len(out.Errors) != 2 {
		t.Fatalf("errors = %+v", out.Errors)
	}
	timeout := out.Errors[0]
	if timeout.Type != "Timeout" || timeout.Level != "error" || timeout.Path != path || timeout.Code != 2 ||
		timeout.Message != "Timeout when running p.a on "+path+":\n timed out" {
		t.Errorf("timeout error = %+v", timeout)
	}
	partial := out.Errors[1]
	if partial.Code != 3 || len(partial.Spans) != 1 || partial.Spans[0].Start.Line != 5 || partial.Path != path || partial.Message != "Syntax error at line "+path+":5:\n partial" {
		t.Errorf("partial parsing error = %+v", partial)
	}
	// The transformer reads the same incomplete-file signal from both modes.
	report := semgrep.TransformSemgrepCompatibleOutputToInterimFormat(out, entities.ToolInfo{}, dir, []string{dir}, false)
	if !reflect.DeepEqual(report.IncompleteFiles, []string{path}) {
		t.Errorf("incomplete files = %v", report.IncompleteFiles)
	}
}

// TestConvertCoreOutputOrdersByLocationNotRuleOrder pins the CLI's order:
// every result by path, start, end and then rule id, whatever the order of
// the rules. Two rules matching one span (DES.java's ISO9797Alg3Mac, matched
// by a broad and a DES-specific rule) must come out by id, so the
// deduplicated asset lists the same rule first in both modes.
func TestConvertCoreOutputOrdersByLocationNotRuleOrder(t *testing.T) {
	rules := []*coreRule{
		testRule(t, `{"id":"mac-des","message":"m","severity":"INFO","languages":["java"],"pattern":"f()"}`),
		testRule(t, `{"id":"mac-broad","message":"m","severity":"INFO","languages":["java"],"pattern":"f()"}`),
	}
	match := func(id, path string, line, col, endCol int) string {
		return fmt.Sprintf(`{"check_id":%q,"path":%q,"start":{"line":%d,"col":%d,"offset":%d},"end":{"line":%d,"col":%d,"offset":%d},"extra":{"metavars":{},"message":"m","metadata":{}}}`,
			id, path, line, col, line*100+col, line, endCol, line*100+endCol)
	}
	// opengrep-core reports by rule, then file; -j makes even that order a
	// matter of scheduling.
	stdout := `{"version":"1.30.2","results":[` + strings.Join([]string{
		match("mac-des", "b/DES.java", 145, 19, 54),
		match("mac-des", "a/AES.java", 9, 1, 5),
		match("mac-broad", "b/DES.java", 145, 38, 53),
		match("mac-broad", "b/DES.java", 145, 19, 54),
		match("mac-broad", "a/AES.java", 3, 1, 5),
	}, ",") + `],"errors":[]}`
	parsed, err := parseCoreOutput([]byte(stdout))
	if err != nil {
		t.Fatal(err)
	}
	out, err := convertCoreOutput(parsed, rules, true, "")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(out.Results))
	for _, r := range out.Results {
		got = append(got, fmt.Sprintf("%s:%d:%d %s", r.Path, r.Start.Line, r.Start.Col, r.CheckID))
	}
	want := []string{
		"a/AES.java:3:1 p.mac-broad",
		"a/AES.java:9:1 p.mac-des",
		"b/DES.java:145:19 p.mac-broad",
		"b/DES.java:145:19 p.mac-des",
		"b/DES.java:145:38 p.mac-broad",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results =\n%q\nwant\n%q", got, want)
	}
}

func TestConvertCoreOutputRejectsUnknownRule(t *testing.T) {
	parsed := &coreOutput{Results: []coreMatch{{CheckID: "nope"}}}
	if _, err := convertCoreOutput(parsed, nil, true, ""); err == nil {
		t.Error("a result for a rule the adapter did not pass must fail the conversion")
	}
}

func TestParseCoreOutputNeedsJSON(t *testing.T) {
	if _, err := parseCoreOutput([]byte(".\n.\n")); err == nil {
		t.Error("progress dots alone are no output")
	}
}

func TestCoreArgsMatchCLIDump(t *testing.T) {
	s := &Scanner{jobs: 3, ruleTimeout: 30}
	got := strings.Join(s.coreArgs("R", "T"), " ")
	// opengrep scan -d --jobs 3 --timeout 30 --taint-intrafile prints this
	// command line after the binary.
	want := "-json -rules R -j 3 -targets T -timeout 30 -timeout_threshold 3 -max_memory 0 -dynamic_timeout_unit_kb 30 -dynamic_timeout_max_multiplier 20 -max_match_per_file 10000 -taint_intrafile -fast"
	if got != want {
		t.Errorf("core args =\n%s\nwant\n%s", got, want)
	}
	if args := (&Scanner{}).coreArgs("R", "T"); args[8] != "5" {
		t.Errorf("default rule timeout = %s, want the CLI's 5", args[8])
	}
}

func TestRestorePrefilteredID(t *testing.T) {
	cases := map[string]string{
		"tmp.crypto-finder-prefilter-1." + prefilteredIDMarker + "tmp.run-2.go.crypto.sha": "tmp.run-2.go.crypto.sha",
		prefilteredIDMarker + "a.b": "a.b",
		"untouched.id":              "untouched.id",
	}
	for in, want := range cases {
		if got := restorePrefilteredID(in); got != want {
			t.Errorf("restorePrefilteredID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRulesDocumentIDs(t *testing.T) {
	a := &coreRule{ruleBase: &ruleBase{baseID: "a", raw: []byte(`{"id":"a"}`)}, prefix: "tmp.run-1.", id: "tmp.run-1.a"}
	b := &coreRule{ruleBase: &ruleBase{baseID: "b", raw: []byte(`{"id":"b"}`)}, prefix: "tmp.run-1.", id: "tmp.run-1.b"}
	otherA := &coreRule{ruleBase: &ruleBase{baseID: "a", raw: []byte(`{"id":"a"}`)}, prefix: "tmp.run-1.sub.", id: "tmp.run-1.sub.a"}
	for _, c := range []struct {
		rules []*coreRule
		base  bool
		ids   []string
	}{
		{[]*coreRule{a, b}, true, []string{"a", "b"}},
		{[]*coreRule{a, otherA}, false, []string{"tmp.run-1.a", "tmp.run-1.sub.a"}},
	} {
		useBase := coreRuleIDs(c.rules)
		doc, err := rulesDocument(c.rules, useBase)
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Rules []map[string]string `json:"rules"`
		}
		if err := json.Unmarshal(doc, &parsed); err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(parsed.Rules))
		for _, rule := range parsed.Rules {
			ids = append(ids, rule["id"])
		}
		if useBase != c.base || !reflect.DeepEqual(ids, c.ids) {
			t.Errorf("useBase %v ids %v, want %v %v", useBase, ids, c.base, c.ids)
		}
	}
}

// TestConvertCoreOutputFailsOnARuleCoreCouldNotLoad pins that a rule
// opengrep-core rejected makes the conversion fail, so the scan runs the
// CLI: the CLI validates its rules first and fails the run (exit 7 for a
// misspelled key, 8 for an unknown language, 2 for an unparsable pattern),
// where core scans with the other rules at exit 0. Rules core skips without
// failing, incompatible with its version or missing a plugin, are skipped by
// the CLI as well.
func TestConvertCoreOutputFailsOnARuleCoreCouldNotLoad(t *testing.T) {
	rules := []*coreRule{testRule(t, `{"id":"a","message":"m","severity":"INFO","languages":["go"],"pattern":"f()"}`)}
	// opengrep-core 1.30.2 output for a rule with `patern:` instead of `pattern:`.
	ruleParse := `{"error_type":"Rule parse error","severity":"error","message":"Expected one of ` + "`pattern`" + `, ...","rule_id":"a","location":{"path":"rules.json","start":{"line":7,"col":5,"offset":107},"end":{"line":7,"col":5,"offset":107}}}`
	patternParse := `{"error_type":["PatternParseError",["pattern"]],"severity":"error","message":"Invalid pattern for Go","rule_id":"a","location":{"path":"rules.json","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0}}}`
	invalidYAML := `{"error_type":"Invalid YAML","severity":"error","message":"duplicate key","rule_id":"a","location":{"path":"rules.json","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0}}}`
	for name, entry := range map[string]string{"rule parse": ruleParse, "pattern parse": patternParse, "invalid yaml": invalidYAML} {
		parsed, err := parseCoreOutput([]byte(`{"results":[],"errors":[` + entry + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = convertCoreOutput(parsed, rules, true, "")
		if !errors.Is(err, errCoreUnavailable) || !strings.Contains(err.Error(), "rule p.a") {
			t.Errorf("%s: err = %v, want core unavailable naming the CLI's rule id p.a", name, err)
		}
	}
	incompatible := `{"error_type":["IncompatibleRule",{"rule_id":"a","this_version":"1.30.2","min_version":"2.0.0"}],"severity":"info","message":"incompatible","rule_id":"a"}`
	missingPlugin := `{"error_type":"Missing plugin","severity":"warn","message":"no plugin","rule_id":"a"}`
	for name, entry := range map[string]string{"incompatible": incompatible, "missing plugin": missingPlugin} {
		parsed, err := parseCoreOutput([]byte(`{"results":[],"errors":[` + entry + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		out, err := convertCoreOutput(parsed, rules, true, "")
		if err != nil || len(out.Errors) != 1 {
			t.Errorf("%s: a rule core skips like the CLI must convert, got %v %+v", name, err, out)
		}
	}
}

// TestConvertCoreOutputHidesInventoryAndExperiment pins that matches of
// INVENTORY and EXPERIMENT severity are left out as the CLI leaves them out
// of its output (DEFAULT_SHOWN_SEVERITIES), judged by the match's own
// severity when core reports one and by its rule's otherwise.
func TestConvertCoreOutputHidesInventoryAndExperiment(t *testing.T) {
	rules := []*coreRule{
		testRule(t, `{"id":"shown","message":"m","severity":"INFO","languages":["go"],"pattern":"f()"}`),
		testRule(t, `{"id":"inv","message":"m","severity":"INVENTORY","languages":["go"],"pattern":"f()"}`),
		testRule(t, `{"id":"exp","message":"m","severity":"EXPERIMENT","languages":["go"],"pattern":"f()"}`),
	}
	match := func(id, severity string) string {
		return fmt.Sprintf(`{"check_id":%q,"path":"a.go","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":2,"offset":1},"extra":{"metavars":{},"message":"m","metadata":{},"severity":%q}}`, id, severity)
	}
	parsed, err := parseCoreOutput([]byte(`{"results":[` + strings.Join([]string{match("shown", ""), match("inv", ""), match("exp", ""), match("shown", "INVENTORY"), match("shown", "WARNING")}, ",") + `],"errors":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := convertCoreOutput(parsed, rules, true, "")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(out.Results))
	for _, r := range out.Results {
		got = append(got, r.CheckID+"|"+r.Extra.Severity)
	}
	want := []string{"p.shown|INFO", "p.shown|WARNING"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("results = %q, want %q", got, want)
	}
}

// TestDecodeLikePython pins the CLI's reading of invalid UTF-8
// (open(errors="replace")): every expectation was computed with CPython's
// bytes.decode("utf-8", "replace"). Each maximal invalid prefix is one
// U+FFFD: a stray byte, an overlong or out-of-range lead, or a multi-byte
// sequence cut short.
func TestDecodeLikePython(t *testing.T) {
	const r = "�"
	cases := []struct{ in, want string }{
		{"bad\xffline", "bad" + r + "line"},
		{"\xff\xff", r + r},
		{"\xe2\x82A", r + "A"},
		{"\xe2\x82", r},
		{"\xe0\x80", r + r},
		{"\xed\xa0\x80", r + r + r},
		{"\xf0\x90\x80", r},
		{"\xf4\x90\x80\x80", r + r + r + r},
		{"\xc0\xaf", r + r},
		{"\xf8\x88\x80\x80\x80", r + r + r + r + r},
		{"\xc3", r},
		{"ok\xc3\xa9", "oké"},
		{"\xe2\x82\xac", "€"},
		{"\xf0\x9f\x98\x80", "😀"},
		{"", ""},
	}
	for _, c := range cases {
		if got := decodeLikePython([]byte(c.in)); got != c.want {
			t.Errorf("decodeLikePython(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.go": "x\xff\xffy\r\nz\n"})
	if got := newLineReader(dir).span("a.go", 1, 2); got != "x"+r+r+"y\nz" {
		t.Errorf("lines = %q, want each invalid byte replaced", got)
	}
}
