// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rules below are invented: "acme-crypto" is not a real library and none
// of them comes from a ruleset.

const nodeTaintSinks = `  pattern-sinks:
  - patterns:
    - pattern-inside: |
        $NS = require("acme-crypto")
        ...
    - pattern: $NS.encrypt($X)
`

const nodeTaintHead = `rules:
- id: acme-taint
  message: acme taint
  severity: INFO
  languages: [javascript]
  mode: taint
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: weak
`

const nodeTaintSources = `  pattern-sources:
  - patterns:
    - pattern: $X
    - metavariable-regex:
        metavariable: $X
        regex: '^"weak-.*"$'
`

func nodeTaintRules(t *testing.T) *Assets {
	t.Helper()
	dir := t.TempDir()
	src := nodeTaintHead + nodeTaintSources + nodeTaintSinks
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Load("", "", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A taint rule compiles to sink entries that carry the sources' regexes.
func TestCompileNodeTaint(t *testing.T) {
	sites, records := compileNode(t, nodeTaintHead+nodeTaintSources+nodeTaintSinks)
	if !strings.Contains(records["acme-taint"], `"taint": true`) || !strings.Contains(records["acme-taint"], `"status": "compiled"`) {
		t.Errorf("record = %s", records["acme-taint"])
	}
	if len(sites["acme-taint"]) == 0 {
		t.Fatal("no entries")
	}
	for _, e := range sites["acme-taint"] {
		if !strings.Contains(e, `"taint": true`) || !strings.Contains(e, `"taint_sources": ["^\"weak-.*\"$"]`) {
			t.Errorf("entry = %s", e)
		}
	}
}

// Sanitizers and propagators are not modeled: the rule is skipped, as in the
// other languages.
func TestCompileNodeTaintSkipsSanitizersAndPropagators(t *testing.T) {
	for _, extra := range []string{
		"  pattern-sanitizers:\n  - pattern: clean($X)\n",
		"  pattern-propagators:\n  - pattern: $A.push($B)\n    from: $B\n    to: $A\n",
	} {
		_, records := compileNode(t, nodeTaintHead+nodeTaintSources+extra+nodeTaintSinks)
		if want := `{"taint": true, "status": "skipped", "reason": "taint sanitizers/propagators"}`; records["acme-taint"] != want {
			t.Errorf("record = %s, want %s", records["acme-taint"], want)
		}
	}
}

func nodeTaintCall(line int, arg string) call {
	return call{line: line, col: 1, key: "acme-crypto.encrypt", method: "encrypt", raw: "c.encrypt", args: []string{arg}}
}

// The sink holds when a source's value is passed to it directly, and not
// when another value is.
func TestNodeTaintDirect(t *testing.T) {
	a := nodeTaintRules(t)
	checkNode(t, a, nodeFragment(
		nodeTaintCall(4, `"weak-md5"`),
		nodeTaintCall(5, `"strong"`),
	), `acme-taint@4 {"assetType": "algorithm", "algorithmName": "weak"}`)
}

// A value reaches the sink through a parameter of a helper in the same file:
// the call of the helper passes it.
func TestNodeTaintThroughHelperParameter(t *testing.T) {
	a := nodeTaintRules(t)
	zero := 0
	build := func(passed string) *FragmentJSON {
		sink := nodeTaintCall(7, "key")
		sink.caller = "src/app.run"
		f := nodeFragment(sink)
		f.ExternalCalls[0].EntryCall.Parameters[0].SourceNodes = []SourceNode{{Type: "PARAMETER", Name: "key", ParameterIndex: &zero}}
		f.InternalEdgeStrings = []string{""}
		var edge CompactEdge
		edge.N[0], edge.N[1], edge.N[2], edge.N[6], edge.N[10], edge.N[11] = 0, 1, 12, 1, 1, 20
		edge.Entry = &CallSiteJSON{Parameters: []Param{{ParameterIndex: 0, ArgumentExpression: passed}}}
		f.InternalEdges = []CompactEdge{edge}
		return f
	}
	checkNode(t, a, build(`"weak-sha1"`), `acme-taint@7 {"assetType": "algorithm", "algorithmName": "weak"}`)
	checkNode(t, a, build(`"strong"`))
}
