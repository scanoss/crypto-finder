// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"reflect"
	"slices"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

func TestGoParseKey(t *testing.T) {
	t.Parallel()
	for key, want := range map[string][2]string{
		"example.com/lib.Open":          {"example.com/lib", "Open"},
		"example.com/lib.(*Key).Sign":   {"example.com/lib.Key", "Sign"},
		"example.com/lib/v2.(Hash).New": {"example.com/lib/v2.Hash", "New"},
		"crypto/sha256.Sum256":          {"crypto/sha256", "Sum256"},
		"example.com/app.<varinit:app>": {"example.com/app", "<varinit:app>"},
	} {
		cls, method, ok := goParseKey(key)
		if !ok || cls != want[0] || method != want[1] {
			t.Errorf("goParseKey(%q) = %q, %q, %v; want %q, %q", key, cls, method, ok, want[0], want[1])
		}
	}
	if _, _, ok := goParseKey("Open"); ok {
		t.Error("a bare name has no class")
	}
}

func TestGoShortClass(t *testing.T) {
	t.Parallel()
	for cls, want := range map[string]string{
		"example.com/lib":         "lib",
		"example.com/lib.Key":     "lib.Key",
		"example.com/lib/v3":      "lib",
		"example.com/lib/v3.Hash": "lib.Hash",
		"gopkg.in/example/lib.v2": "lib",
	} {
		if got := goShortClass(cls); got != want {
			t.Errorf("goShortClass(%q) = %q, want %q", cls, got, want)
		}
	}
}

func TestGoImportBindings(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]map[string]string{
		"import \"example.com/lib\"":                               {"lib": "example.com/lib"},
		"import \"example.com/lib\"\n...":                          {"lib": "example.com/lib"},
		"import (\n  ...\n  \"example.com/lib/v2\"\n  ...\n)\n...": {"lib": "example.com/lib/v2"},
		"import alias \"example.com/lib\"\n...":                    {"alias": "example.com/lib"},
		"import $PKG \"example.com/lib\"\n...":                     {"$PKG": "example.com/lib"},
	} {
		got, ok := goImportBindings(text)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("goImportBindings(%q) = %v, %v; want %v", text, got, ok, want)
		}
	}
	if _, ok := goImportBindings("$X := lib.Open()\n..."); ok {
		t.Error("an assignment is not an import clause")
	}
}

// compileGoRule compiles one made-up Go rule.
func compileGoRule(t *testing.T, yamlText string) ([]*OMap, error) {
	t.Helper()
	doc, err := parseYAML([]byte(yamlText))
	if err != nil {
		t.Fatal(err)
	}
	rules := as[[]any](as[*OMap](doc).GetOr("rules"))
	return compileRule(as[*OMap](rules[0]), false)
}

// A pattern-not written as a sub-rule compiles to one not_calls entry per
// plain pattern, as OpenGrep subtracts each; any other sub-rule skips the
// rule instead of aborting the compile (go-port audit S13).
// A sink no import clause typed keeps its package name, which the cards match
// against any package of that name: an alias-scoped pattern-not is not implied
// there, and the rule is skipped.
func TestCompileGoAliasScopedNotNeedsAnImportPath(t *testing.T) {
	t.Parallel()
	const not = "      - pattern-not:\n          patterns:\n            - pattern-inside: |\n                import $OTHER \"example.com/other/lib\"\n                ...\n            - pattern: $OTHER.$M(...)\n"
	heads := map[string]string{
		"no import clause":               "",
		"an import not about the callee": "      - pattern-inside: |\n          import (\n            \"example.com/a\"\n            \"example.com/b\"\n          )\n          ...\n",
	}
	for name, guard := range heads {
		rule := "rules:\n  - id: r\n    message: m\n    severity: INFO\n    languages: [go]\n    patterns:\n" + guard + "      - pattern: lib.Open($A)\n" + not
		if _, err := compileGoRule(t, rule); err == nil {
			t.Errorf("%s: compiled, want skip", name)
		} else if s, ok := asSkip(err); !ok || s.reason != "pattern-not of an unsupported sub-rule" {
			t.Errorf("%s: err %v, want skip", name, err)
		}
	}
}

func TestCompileGoPatternNotSubRule(t *testing.T) {
	t.Parallel()
	const head = "rules:\n  - id: r\n    message: m\n    severity: INFO\n    languages: [go]\n    patterns:\n      - pattern-inside: |\n          import \"example.com/lib\"\n          ...\n      - pattern: lib.Open($A)\n"
	cases := []struct {
		name, body string
		wantNots   int
		wantSkip   string
	}{
		{"plain", "      - pattern-not: lib.Open(1)\n", 1, ""},
		{"a pattern sub-rule", "      - pattern-not:\n          pattern: lib.Open(1)\n", 1, ""},
		{"a pattern-either sub-rule", "      - pattern-not:\n          pattern-either:\n            - pattern: lib.Open(1)\n            - pattern: lib.Open(2)\n", 2, ""},
		{"a patterns sub-rule", "      - pattern-not:\n          patterns:\n            - pattern: lib.Open($B)\n            - metavariable-regex:\n                metavariable: $B\n                regex: ^3$\n", 0, "pattern-not of an unsupported sub-rule"},
		{"a pattern-either with a constraint", "      - pattern-not:\n          pattern-either:\n            - patterns:\n                - pattern: lib.Open($B)\n", 0, "pattern-not of a pattern-either that is not plain patterns"},
		{"a sub-rule scoped by another import's alias", "      - pattern-not:\n          patterns:\n            - pattern-either:\n                - pattern-inside: |\n                    import (\n                      ...\n                      $OTHER \"example.com/other/lib\"\n                      ...\n                    )\n                    ...\n                - pattern-inside: |\n                    import $OTHER \"example.com/other/lib\"\n                    ...\n            - pattern-either:\n                - pattern: $OTHER.$M(...)\n                - pattern: $OTHER.$M\n", 0, ""},
		{"a sub-rule scoped by the rule's own alias", "      - pattern-not:\n          patterns:\n            - pattern-inside: |\n                import $OWN \"example.com/lib\"\n                ...\n            - pattern: $X.$M(...)\n            - pattern-not: $OWN.$M(...)\n", 0, ""},
		{"a sub-rule removing given calls through the rule's own alias", "      - pattern-not:\n          patterns:\n            - pattern-inside: |\n                import $L \"example.com/lib\"\n                ...\n            - pattern: $L.Open(1)\n", 0, "pattern-not of an unsupported sub-rule"},
		{"a dispatch through the rule's own alias", "      - pattern-not:\n          patterns:\n            - pattern-inside: |\n                import $L \"example.com/lib\"\n                ...\n            - pattern: $L.$M(...)\n", 0, "pattern-not of an unsupported sub-rule"},
		{"what another import's alias does not reach", "      - pattern-not:\n          patterns:\n            - pattern-inside: |\n                import $OTHER \"example.com/other/lib\"\n                ...\n            - pattern: $X.$M(...)\n            - pattern-not: $OTHER.$M(...)\n", 0, "pattern-not of an unsupported sub-rule"},
		{"an import scope binding no alias", "      - pattern-not:\n          patterns:\n            - pattern-inside: |\n                import \"example.com/other/lib\"\n                ...\n            - pattern: lib.Open(1)\n", 0, "pattern-not of an unsupported sub-rule"},
		{"an alias the sub-rule does not use", "      - pattern-not:\n          patterns:\n            - pattern-inside: |\n                import $OTHER \"example.com/other/lib\"\n                ...\n            - pattern: lib.Open(1)\n", 0, "pattern-not of an unsupported sub-rule"},
	}
	for _, c := range cases {
		sinks, err := compileGoRule(t, head+c.body)
		if c.wantSkip != "" {
			if s, ok := asSkip(err); !ok || s.reason != c.wantSkip {
				t.Errorf("%s: err %v, want skip %q", c.name, err, c.wantSkip)
			}
			continue
		}
		if err != nil || len(sinks) != 1 {
			t.Fatalf("%s: %d sinks, err %v", c.name, len(sinks), err)
		}
		if got := len(as[[]any](sinks[0].GetOr("not_calls"))); got != c.wantNots {
			t.Errorf("%s: %d not_calls, want %d", c.name, got, c.wantNots)
		}
		// A sub-rule scoped by an import alias subtracts only calls reached through an
		// alias, which the cards resolve by import path: dropped, and recorded.
		dropped := listOf(sinks[0].GetOr("dropped_clauses"))
		if wantDrop := c.wantNots == 0; wantDrop != slices.Contains(dropped, any(goAliasScopedNotDropped)) {
			t.Errorf("%s: dropped_clauses %v", c.name, dropped)
		}
	}
}

func TestCompileGoRules(t *testing.T) {
	t.Parallel()
	const head = "rules:\n  - id: r\n    message: m\n    severity: INFO\n    languages: [go]\n    patterns:\n"
	imports := "      - pattern-either:\n          - pattern-inside: |\n              import (\n                ...\n                \"example.com/lib/v2\"\n                ...\n              )\n              ...\n          - pattern-inside: import \"example.com/lib/v2\"\n"
	cases := []struct {
		name, body, wantType, wantMethod, wantSkip string
	}{
		{"import qualifies a package call", imports + "      - pattern: lib.Open(...)\n", "example.com/lib/v2", "Open", ""},
		{"a typed receiver names a type of the package", imports + "      - pattern: '($K : *lib.Key).Sign(...)'\n", "example.com/lib/v2.Key", "Sign", ""},
		{"a package named apart from its path", imports + "      - pattern: other.Open(...)\n", "example.com/lib/v2", "Open", ""},
		{"an import binds a metavariable receiver", "      - pattern-inside: |\n          import $P \"example.com/lib\"\n          ...\n      - pattern: $P.New(...)\n", "example.com/lib", "New", ""},
		{"an import without a following ... covers no call", "      - pattern-inside: import $P \"example.com/lib\"\n      - pattern: $P.New(...)\n", "", "", "pattern-inside import without a following ..., which covers no call"},
		{"no import: the rule's own spelling", "      - pattern: lib.Open(...)\n", "lib", "Open", ""},
		{"an untyped receiver in an importing file", imports + "      - pattern: $X.Sign(...)\n", "", "", "pattern-inside import on a call with an untyped receiver"},
	}
	for _, c := range cases {
		sinks, err := compileGoRule(t, head+c.body)
		if c.wantSkip != "" {
			if s, ok := asSkip(err); !ok || s.reason != c.wantSkip {
				t.Errorf("%s: err %v, want skip %q", c.name, err, c.wantSkip)
			}
			continue
		}
		if err != nil || len(sinks) != 1 {
			t.Errorf("%s: %d sinks, err %v", c.name, len(sinks), err)
			continue
		}
		if got := getString(sinks[0], strType); got != c.wantType || getString(sinks[0], "method") != c.wantMethod {
			t.Errorf("%s: type %q method %q, want %q %q", c.name, got, getString(sinks[0], "method"), c.wantType, c.wantMethod)
		}
		if sinks[0].Has(goReceiverMetavarKey) {
			t.Errorf("%s: working key left on the sink", c.name)
		}
	}
}

// `import $P "p" ...` binds only an aliased import of p, as OpenGrep does
// (go-port audit S1): the sink carries the path, and a 1.32 fragment's import
// specs decide whether a call's qualifier is such an alias.
func TestGoAliasedImport(t *testing.T) {
	t.Parallel()
	const rule = "rules:\n  - id: r\n    message: m\n    severity: INFO\n    languages: [go]\n    patterns:\n      - pattern-inside: |\n          import $P \"example.com/acme/lib\"\n          ...\n      - pattern: $P.New(...)\n"
	sinks, err := compileGoRule(t, rule)
	if err != nil || len(sinks) != 1 {
		t.Fatalf("%d sinks, err %v", len(sinks), err)
	}
	if got := getString(sinks[0], keyGoAliasOf); got != "example.com/acme/lib" {
		t.Fatalf("go_alias_of %q", got)
	}
	frag := &FragmentJSON{SchemaVersion: "graph-fragment-1.32", Imports: map[string][]graphfrag.GraphFragmentImport{
		"a.go": {{Module: "example.com/acme/lib"}},
		"b.go": {{Module: "example.com/acme/lib", Alias: "x"}},
	}}
	frag.ScanMetadata.Ecosystem = ecosystemGo
	known, aliases := goImportAliases(frag)
	fr := &Frag{Go: true, GoImports: known, GoAliases: aliases}
	e := &Entry{GoAliasOf: "example.com/acme/lib"}
	cases := []struct {
		file, src string
		want      bool
	}{
		{"a.go", "lib.New(1)", false},
		{"b.go", "x.New(1)", true},
		{"b.go", "lib.New(1)", false},
	}
	for _, c := range cases {
		if got := goAliasedCall(e, &Site{File: c.file, Src: c.src}, fr); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.file, c.src, got, c.want)
		}
	}
	// An older fragment lists no import specs: the call is kept.
	frag.SchemaVersion = "graph-fragment-1.30"
	known, aliases = goImportAliases(frag)
	if !goAliasedCall(e, &Site{File: "a.go", Src: "lib.New(1)"}, &Frag{Go: true, GoImports: known, GoAliases: aliases}) {
		t.Error("1.30 fragment: call dropped")
	}
}

// A Go value as written (`lib.L2`) is read with the import path of the
// constant reference the fragment records for it on the same line, and kept
// as written when that is ambiguous or missing.
func TestGoQualifiedRef(t *testing.T) {
	t.Parallel()
	ref := func(raw string, line int) *Site { return &Site{Raw: raw, Line: line, Kind: "constant_ref"} }
	fr := &Frag{RefsByCaller: map[string][]*Site{
		"f": {ref("example.com/lib/v2.L2", 7), ref("example.com/other.L2", 9), ref("example.com/lib/v2.L3", 9)},
	}}
	for _, c := range []struct {
		text string
		line int
		want string
	}{
		{"lib.L2", 7, "example.com/lib/v2.L2"},
		{"lib.L2", 9, "lib.L2"}, // the reference on line 9 is another package's
		{"lib.L3", 9, "example.com/lib/v2.L3"},
		{"lib.L4", 7, "lib.L4"},
	} {
		got := fr.goQualifiedRef(Val{Caller: "f", Line: c.line, LineOK: true}, c.text)
		if got != c.want {
			t.Errorf("goQualifiedRef(%q, line %d) = %q, want %q", c.text, c.line, got, c.want)
		}
	}
}

// A focus-metavariable on a Go receiver compiles to a receiver focus, typed
// or not, and the finding is reported at the receiver's span (go-port audit
// S16; pinned against OpenGrep 1.33.1: `key` of `key.Sign(..)` at 2-5,
// `lib.Load(lib.Opts{})` of `lib.Load(lib.Opts{}).Sign(nil)` at 2-22).
func TestGoFocusReceiver(t *testing.T) {
	t.Parallel()
	const head = "rules:\n  - id: r\n    message: m\n    severity: INFO\n    languages: [go]\n    patterns:\n"
	for _, body := range []string{
		"      - pattern: $K.Sign(...)\n      - focus-metavariable: $K\n",
		"      - pattern: '($K : *lib.Key).Sign(...)'\n      - focus-metavariable: $K\n",
	} {
		sinks, err := compileGoRule(t, head+body)
		if err != nil || len(sinks) != 1 {
			t.Fatalf("%q: %d sinks, err %v", body, len(sinks), err)
		}
		if focus, _ := sinks[0].GetOr(keyFocusReceiver).(bool); !focus || sinks[0].Has(goReceiverMetavarKey) {
			t.Errorf("%q: focus_receiver %v, working key kept %v", body, sinks[0].GetOr(keyFocusReceiver), sinks[0].Has(goReceiverMetavarKey))
		}
	}
	spans := []struct {
		call, method string
		want         int
		ok           bool
	}{
		{`key.Sign([]byte("m"))`, "Sign", 3, true},
		{`lib.Load(lib.Opts{}).Sign(nil)`, "Sign", 20, true},
		{`a.b . Sign (x)`, "Sign", 3, true},
		{`Sign(x)`, "Sign", 0, false},
		{`key.Verify(x)`, "Sign", 0, false},
		{`key.Sign(x`, "Sign", 0, false},
	}
	for _, c := range spans {
		if n, ok := goReceiverSpan(c.call, c.method); n != c.want || ok != c.ok {
			t.Errorf("goReceiverSpan(%q) = %d %v, want %d %v", c.call, n, ok, c.want, c.ok)
		}
	}
	site := &Site{Col: 2, ColOK: true, EndCol: 32, Line: 8, Method: "Sign", Src: "lib.Load(lib.Opts{}).Sign(nil) // tail"}
	f := &Finding{Col: 2, EndCol: 32}
	goFocusReceiver(f, site)
	if f.EndCol != 22 || f.FocusText != "lib.Load(lib.Opts{})" {
		t.Errorf("receiver focus: end %d text %q, want 22 %q", f.EndCol, f.FocusText, "lib.Load(lib.Opts{})")
	}
	// The call's span stays the terminal's, so a chain's inner link
	// (lib.Load, which spans exactly the receiver) is not taken for the call.
	if f.TerminalCol != 2 || f.TerminalEndCol != 32 {
		t.Errorf("terminal %d-%d, want 2-32", f.TerminalCol, f.TerminalEndCol)
	}
}
