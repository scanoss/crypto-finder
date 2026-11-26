// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rustRule is one invented Rust rule: id and formula (YAML under the rule).
func rustRuleYAML(rules map[string]string) string {
	var b strings.Builder
	b.WriteString("rules:\n")
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		fmt.Fprintf(&b, "- id: %s\n  languages: [rust]\n  metadata: {crypto: {assetType: algorithm}}\n", id)
		for _, line := range strings.Split(strings.TrimSpace(rules[id]), "\n") {
			b.WriteString("  " + line + "\n")
		}
	}
	return b.String()
}

func exportRust(t *testing.T, rules map[string]string) map[string]ExportedRule {
	t.Helper()
	out, err := ExportRules(writeRules(t, rustRuleYAML(rules)))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]ExportedRule{}
	for _, r := range out {
		byID[r.ID] = r
	}
	return byID
}

func siteTexts(r ExportedRule) []string {
	out := make([]string, len(r.Sites))
	for i, s := range r.Sites {
		out[i] = string(s)
	}
	return out
}

// Each shape of the closed set compiles to its site entries: the method
// bucket and arity on the shared fields, the rest in "rust".
func TestCompileRustShapes(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		want       []string
	}{
		{
			name: "use-gated path call with a regex on the import and a turbofish metavariable",
			rule: `
patterns:
- pattern-inside: |
    use $IMPORT;
    ...
- metavariable-regex: {metavariable: $IMPORT, regex: '^acme_kdf(::|$)'}
- pattern: Kdf::<$H>::new($SALT, ...)
- metavariable-regex: {metavariable: $H, regex: '^Sha256$'}`,
			want: []string{`{"method": "new", "min_arity": 1, "max_arity": null, "rust": {"call": {"callee": {"segs": [{"name": "Kdf", "generics": [{"var": "$H"}]}, {"name": "new"}]}, "args": [{"kind": "metavar", "var": "$SALT"}, {"kind": "ellipsis"}]}, "inside": [{"place": "before", "use": {"path": {"segs": [{"var": "$IMPORT"}]}}}], "where": [{"metavar": "$IMPORT", "regex": "^acme_kdf(::|$)"}, {"metavar": "$H", "regex": "^Sha256$"}], "needs": {"imports": true}}, "taint": false}`},
		},
		{
			name: "method call on any receiver, guarded by an extern crate alias",
			rule: `
patterns:
- pattern-inside: |
    extern crate acme_kdf as $A;
    ...
- pattern: $X.derive($OUT)`,
			want: []string{`{"method": "derive", "min_arity": 1, "max_arity": 1, "rust": {"call": {"receiver": {"kind": "metavar", "var": "$X"}, "method": "derive", "args": [{"kind": "metavar", "var": "$OUT"}]}, "inside": [{"place": "before", "extern_crate": {"name": "acme_kdf", "alias": "$A"}}], "needs": {"imports": true}}, "taint": false}`},
		},
		{
			name: "pattern-either alternatives: one entry each, outer filters on every one",
			rule: `
patterns:
- pattern-either:
  - pattern: acme_sig::verify(&acme_sig::ALG_A, $K)
  - pattern: <$T as acme_hash::Digest>::digest(...)
- pattern-not-inside: |
    mod acme_sig { ... }
    ...
- pattern-not-inside: |
    const $T: $TY = $V;
    ...`,
			want: []string{
				`{"method": "verify", "min_arity": 2, "max_arity": 2, "rust": {"call": {"callee": {"segs": [{"name": "acme_sig"}, {"name": "verify"}]}, "args": [{"kind": "ref", "sub": {"kind": "path", "path": {"segs": [{"name": "acme_sig"}, {"name": "ALG_A"}]}}}, {"kind": "metavar", "var": "$K"}]}, "not_inside": [{"place": "before", "item": {"kind": "mod", "name": "acme_sig"}}, {"place": "before", "item": {"kind": "const", "name": "$T", "type": {"var": "$TY"}, "value": {"kind": "metavar", "var": "$V"}}}], "needs": {"items": true}}, "taint": false}`,
				`{"method": "digest", "min_arity": 0, "max_arity": null, "rust": {"call": {"callee": {"qself": {"self": {"var": "$T"}, "trait": {"segs": [{"name": "acme_hash"}, {"name": "Digest"}]}}, "segs": [{"name": "digest"}]}, "args": [{"kind": "ellipsis"}]}, "not_inside": [{"place": "before", "item": {"kind": "mod", "name": "acme_sig"}}, {"place": "before", "item": {"kind": "const", "name": "$T", "type": {"var": "$TY"}, "value": {"kind": "metavar", "var": "$V"}}}], "needs": {"items": true}}, "taint": false}`,
			},
		},
		{
			name: "a pattern-either of insides multiplies the alternatives; a metavariable path segment buckets nothing",
			rule: `
patterns:
- pattern: acme_kdf::Kdf::$M(...)
- metavariable-regex: {metavariable: $M, regex: '^(new|extract)$'}
- pattern-either:
  - pattern-inside: |
      let $K = acme_kdf::Key::new(...);
      ...
  - patterns:
    - pattern-inside: |
        let ($K, $IV) = acme_kdf::pair();
        ...
    - pattern-inside: |
        use $IMPORT;
        ...
    - metavariable-regex: {metavariable: $IMPORT, regex: '^acme_kdf'}`,
			want: []string{
				`{"method": null, "min_arity": 0, "max_arity": null, "rust": {"call": {"callee": {"segs": [{"name": "acme_kdf"}, {"name": "Kdf"}, {"var": "$M"}]}, "args": [{"kind": "ellipsis"}]}, "inside": [{"place": "before", "let": {"name": "$K", "init": {"kind": "call", "call": {"callee": {"segs": [{"name": "acme_kdf"}, {"name": "Key"}, {"name": "new"}]}, "args": [{"kind": "ellipsis"}]}}}}], "where": [{"metavar": "$M", "regex": "^(new|extract)$"}], "needs": {"declarations": true}}, "taint": false}`,
				`{"method": null, "min_arity": 0, "max_arity": null, "rust": {"call": {"callee": {"segs": [{"name": "acme_kdf"}, {"name": "Kdf"}, {"var": "$M"}]}, "args": [{"kind": "ellipsis"}]}, "inside": [{"place": "before", "let": {"tuple": ["$K", "$IV"], "init": {"kind": "call", "call": {"callee": {"segs": [{"name": "acme_kdf"}, {"name": "pair"}]}, "args": []}}}}, {"place": "before", "use": {"path": {"segs": [{"var": "$IMPORT"}]}}}], "where": [{"metavar": "$IMPORT", "regex": "^acme_kdf"}, {"metavar": "$M", "regex": "^(new|extract)$"}], "needs": {"imports": true, "declarations": true}}, "taint": false}`,
			},
		},
		{
			name: "local definition guards around, before and after the site; an enclosing call",
			rule: `
patterns:
- pattern: acme_rng::fill(&mut $BUF)
- pattern-not-inside: |
    mod acme_rng { ... }
- pattern-not-inside: |
    ...
    fn fill(...) {...}
- pattern-not-inside: |
    ...
    struct Buf ...
    ...
- pattern-not-inside: $B.seal($K, ...)`,
			want: []string{`{"method": "fill", "min_arity": 1, "max_arity": 1, "rust": {"call": {"callee": {"segs": [{"name": "acme_rng"}, {"name": "fill"}]}, "args": [{"kind": "ref", "sub": {"kind": "metavar", "var": "$BUF"}, "mut": true}]}, "not_inside": [{"place": "around", "item": {"kind": "mod", "name": "acme_rng"}}, {"place": "after", "item": {"kind": "fn", "name": "fill", "params": [{"ellipsis": true}]}}, {"place": "anywhere", "item": {"kind": "struct", "name": "Buf"}}, {"place": "around", "call": {"receiver": {"kind": "metavar", "var": "$B"}, "method": "seal", "args": [{"kind": "metavar", "var": "$K"}, {"kind": "ellipsis"}]}}], "needs": {"items": true}}, "taint": false}`},
		},
		{
			name: "pattern-not: a call, and a conjunction of an inside with its own regex (a not-inside)",
			rule: `
patterns:
- pattern: acme::Cipher::new($K)
- pattern-not: acme::Cipher::new(acme::ZERO)
- pattern-not:
    patterns:
    - pattern-inside: |
        use $P::acme;
        ...
    - metavariable-regex: {metavariable: $P, regex: '^(?!crate$)'}
- pattern-not:
    patterns:
    - pattern: acme::Cipher::new($K)
    - pattern-inside: |
        let $K = acme::weak();
        ...`,
			want: []string{`{"method": "new", "min_arity": 1, "max_arity": 1, "rust": {"call": {"callee": {"segs": [{"name": "acme"}, {"name": "Cipher"}, {"name": "new"}]}, "args": [{"kind": "metavar", "var": "$K"}]}, "not_inside": [{"place": "before", "use": {"path": {"segs": [{"var": "$P"}, {"name": "acme"}]}}, "where": [{"metavar": "$P", "regex": "^(?!crate$)"}]}], "not": [{"call": {"callee": {"segs": [{"name": "acme"}, {"name": "Cipher"}, {"name": "new"}]}, "args": [{"kind": "path", "path": {"segs": [{"name": "acme"}, {"name": "ZERO"}]}}]}, "needs": {}}, {"call": {"callee": {"segs": [{"name": "acme"}, {"name": "Cipher"}, {"name": "new"}]}, "args": [{"kind": "metavar", "var": "$K"}]}, "inside": [{"place": "before", "let": {"name": "$K", "init": {"kind": "call", "call": {"callee": {"segs": [{"name": "acme"}, {"name": "weak"}]}, "args": []}}}}], "needs": {"declarations": true}}], "needs": {"imports": true, "declarations": true}}, "taint": false}`},
		},
		{
			name: "a sequence context, a bare path and focus-metavariable",
			rule: `
pattern-either:
- patterns:
  - pattern-inside: |
      let $N = $INIT;
      ...
      acme::Stream::new($K, &$N)
  - pattern: acme::Stream::new($K, &$N)
  - focus-metavariable: $N
- pattern: acme_sig::ALG_A`,
			want: []string{
				`{"method": "new", "min_arity": 2, "max_arity": 2, "rust": {"call": {"callee": {"segs": [{"name": "acme"}, {"name": "Stream"}, {"name": "new"}]}, "args": [{"kind": "metavar", "var": "$K"}, {"kind": "ref", "sub": {"kind": "metavar", "var": "$N"}}]}, "inside": [{"place": "before", "let": {"name": "$N", "init": {"kind": "metavar", "var": "$INIT"}}, "until": {"kind": "call", "call": {"callee": {"segs": [{"name": "acme"}, {"name": "Stream"}, {"name": "new"}]}, "args": [{"kind": "metavar", "var": "$K"}, {"kind": "ref", "sub": {"kind": "metavar", "var": "$N"}}]}}}], "focus": "$N", "needs": {"declarations": true}}, "taint": false}`,
				`{"method": null, "min_arity": 0, "max_arity": null, "rust": {"ref": {"segs": [{"name": "acme_sig"}, {"name": "ALG_A"}]}, "needs": {"refs": true}}, "taint": false}`,
			},
		},
		{
			name: "a second positive that specializes the first, mixed with a context",
			rule: `
patterns:
- pattern: acme::Kdf::new($X)
- pattern-either:
  - pattern: acme::Kdf::new(1)
  - pattern-inside: |
      use acme::Strong;
      ...
- metavariable-regex: {metavariable: $X, regex: '^1'}`,
			want: []string{
				`{"method": "new", "min_arity": 1, "max_arity": 1, "rust": {"call": {"callee": {"segs": [{"name": "acme"}, {"name": "Kdf"}, {"name": "new"}]}, "args": [{"kind": "metavar", "var": "$X"}]}, "within": [{"call": {"callee": {"segs": [{"name": "acme"}, {"name": "Kdf"}, {"name": "new"}]}, "args": [{"kind": "literal", "lit": "1"}]}, "needs": {}}], "where": [{"metavar": "$X", "regex": "^1"}], "needs": {}}, "taint": false}`,
				`{"method": "new", "min_arity": 1, "max_arity": 1, "rust": {"call": {"callee": {"segs": [{"name": "acme"}, {"name": "Kdf"}, {"name": "new"}]}, "args": [{"kind": "metavar", "var": "$X"}]}, "inside": [{"place": "before", "use": {"path": {"segs": [{"name": "acme"}, {"name": "Strong"}]}}}], "where": [{"metavar": "$X", "regex": "^1"}], "needs": {"imports": true}}, "taint": false}`,
			},
		},
		{
			name: "a metavariable-regex on a metavariable one branch does not bind drops that branch",
			rule: `
patterns:
- pattern-either:
  - pattern: acme::f(...)
  - pattern: acme::g($H)
- metavariable-regex: {metavariable: $H, regex: '^Sha'}`,
			want: []string{`{"method": "g", "min_arity": 1, "max_arity": 1, "rust": {"call": {"callee": {"segs": [{"name": "acme"}, {"name": "g"}]}, "args": [{"kind": "metavar", "var": "$H"}]}, "where": [{"metavar": "$H", "regex": "^Sha"}], "needs": {}}, "taint": false}`},
		},
		{
			name: "an item written as the pattern",
			rule: `
pattern: type $NAME = acme_aead::Aead<$CIPHER, U12>;`,
			want: []string{`{"method": null, "min_arity": 0, "max_arity": null, "rust": {"item": {"kind": "type", "name": "$NAME", "type": {"path": {"segs": [{"name": "acme_aead"}, {"name": "Aead", "generics": [{"var": "$CIPHER"}, {"path": {"segs": [{"name": "U12"}]}}]}]}}}, "needs": {"items": true}}, "taint": false}`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := exportRust(t, map[string]string{"acme.rule": tc.rule})["acme.rule"]
			if r.Status != "compiled" {
				t.Fatalf("status %s (%s)", r.Status, r.Reason)
			}
			got := siteTexts(r)
			if !slices.Equal(got, tc.want) {
				t.Errorf("sites:\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(tc.want, "\n     "))
			}
		})
	}
}

// A clause outside the closed set, in any branch, skips the whole rule with
// one reason of the closed set.
func TestCompileRustSkips(t *testing.T) {
	rules := map[string]string{
		"taint sanitizer":          "mode: taint\npattern-sources: [{pattern: acme::source()}]\npattern-sanitizers: [{pattern: acme::clean(...)}]\npattern-sinks: [{pattern: acme::sink(...)}]",
		"focused taint source":     "mode: taint\npattern-sources: [{patterns: [{pattern: acme::source($X)}, {focus-metavariable: $X}]}]\npattern-sinks: [{pattern: acme::sink(...)}]",
		"taint path sink":          "mode: taint\npattern-sources: [{pattern: acme::source()}]\npattern-sinks: [{pattern: acme::SINK}]",
		"pattern-regex":            "pattern-regex: 'acme_[a-z]+'",
		"regex in a conj":          "patterns:\n- pattern: acme::f(...)\n- pattern-regex: x",
		"one bad branch":           "pattern-either:\n- pattern: acme::f(...)\n- pattern: acme::m!($X)",
		"two positives":            "patterns:\n- pattern: acme::f(...)\n- pattern: acme::g(...)",
		"unbound regex":            "patterns:\n- pattern: acme::f(...)\n- metavariable-regex: {metavariable: $X, regex: x}",
		"regex only in a negative": "patterns:\n- pattern: acme::f(...)\n- pattern-not-inside: |\n    use $X::acme;\n    ...\n- metavariable-regex: {metavariable: $X, regex: x}",
		"bad regex":                "patterns:\n- pattern: acme::f($X)\n- metavariable-regex: {metavariable: $X, regex: '(?<'}",
		"mod with a body":          "patterns:\n- pattern: acme::f(...)\n- pattern-not-inside: |\n    mod acme { pub fn $F(...) {...} }\n    ...",
		"grouped use":              "patterns:\n- pattern-inside: |\n    use acme::{a, b};\n    ...\n- pattern: a(...)",
		"shift positive":           "pattern: $A << $B",
		"two statements":           "patterns:\n- pattern-inside: |\n    use a;\n    use b;\n    ...\n- pattern: acme::f(...)",
		"metavariable-pattern":     "patterns:\n- pattern: acme::f($X)\n- metavariable-pattern: {metavariable: $X, pattern: acme::K}",
		"unbound focus":            "patterns:\n- pattern: acme::f(...)\n- focus-metavariable: $Y",
		"inside only":              "patterns:\n- pattern-inside: |\n    use acme;\n    ...",
		"empty either":             "pattern-either: []",
		"either map":               "pattern-either: {pattern: acme::f(...)}",
		"empty either in a conj":   "patterns:\n- pattern: acme::f(...)\n- pattern-either: []",
		// A second positive that specializes no positive of the first: OpenGrep
		// also reports its ranges inside the first's sites, which are no sites.
		"second positive not specialized": "patterns:\n- pattern: acme::Kdf::new($X)\n- pattern-either:\n  - pattern: acme::Mac::new(1)\n  - pattern-inside: |\n      use acme::S;\n      ...",
		"second positive around":          "patterns:\n- pattern: acme::Kdf::new(...)\n- pattern-either:\n  - pattern: wrap(...)\n  - pattern-inside: |\n      use acme::S;\n      ...",
		"shared metavariable rebound":     "patterns:\n- pattern: acme::f($X)\n- pattern-either:\n  - pattern: acme::f(acme::g($X))\n  - pattern-inside: |\n      use acme::S;\n      ...",
		"first positive with a negative":  "patterns:\n- patterns:\n  - pattern: acme::f($X)\n  - pattern-not: acme::f(0)\n- pattern-either:\n  - pattern: acme::f(1)\n  - pattern-inside: |\n      use acme::S;\n      ...",
		"focused second positive":         "patterns:\n- pattern: acme::f($X)\n- pattern-either:\n  - patterns:\n    - pattern: acme::f($X)\n    - focus-metavariable: $X\n  - pattern-inside: |\n      use acme::S;\n      ...",
		"within on a dropped branch":      "patterns:\n- pattern: acme::f(...)\n- pattern-either:\n  - pattern: acme::f(1)\n  - pattern-inside: |\n      use acme::$H;\n      ...\n- metavariable-regex: {metavariable: $H, regex: x}",
		"taint sink of two positives":     "mode: taint\npattern-sources: [{pattern: acme::source()}]\npattern-sinks:\n- patterns:\n  - pattern: acme::sink($X)\n  - pattern: acme::sink(1)",
		// A context branch's negative holds over the branch's context range,
		// not over the site.
		"negated context branch": "patterns:\n- pattern: acme::f($X)\n- pattern-either:\n  - pattern-inside: |\n      use acme::W;\n      ...\n  - patterns:\n    - pattern-inside: |\n        use acme::S;\n        ...\n    - pattern-not-inside: |\n        let c = ...;",
		"no branch binds":        "patterns:\n- pattern-either:\n  - pattern: acme::f(...)\n  - pattern: acme::g(...)\n- metavariable-regex: {metavariable: $H, regex: x}",
	}
	want := map[string]rustSkip{
		"taint sanitizer": skipRustSanitizers, "focused taint source": skipRustSource, "taint path sink": skipRustPositive,
		"pattern-regex": skipRustPatternRegex, "regex in a conj": skipRustPatternRegex,
		"one bad branch": skipRustMacro, "two positives": skipRustPositives, "unbound regex": skipRustUnbound,
		"regex only in a negative": skipRustUnbound, "bad regex": skipRustRegex, "mod with a body": skipRustItem,
		"grouped use": skipRustContext, "shift positive": skipRustExpr, "two statements": skipRustSequence,
		"metavariable-pattern": skipRustClause, "unbound focus": skipRustFocus, "inside only": skipRustNoPositive,
		"empty either": skipRustFormula, "either map": skipRustFormula, "empty either in a conj": skipRustFormula,
		"second positive not specialized": skipRustPositives, "second positive around": skipRustPositives,
		"shared metavariable rebound": skipRustPositives, "first positive with a negative": skipRustPositives,
		"focused second positive": skipRustFocus, "within on a dropped branch": skipRustPositives,
		"taint sink of two positives": skipRustPositives, "negated context branch": skipRustContext,
		"no branch binds": skipRustUnbound,
	}
	byID := map[string]string{}
	for name, rule := range rules {
		byID[strings.ReplaceAll(name, " ", "-")] = rule
	}
	got := exportRust(t, byID)
	for name, reason := range want {
		r := got[strings.ReplaceAll(name, " ", "-")]
		if r.Status != "skipped" || r.Reason != string(reason) || len(r.Sites) != 0 {
			t.Errorf("%s: %s %q with %d sites, want skipped %q", name, r.Status, r.Reason, len(r.Sites), reason)
		}
	}
}

// cards-export keeps one record per rule, compiled + skipped = rules, every
// skip reason is in the closed set, and no Rust entry is lossy.
func TestExportRustCountsAndStrictness(t *testing.T) {
	rules := map[string]string{
		"a": "pattern: acme::f(...)",
		"b": "pattern-either:\n- pattern: acme::f(...)\n- pattern: acme::g($X)",
		"c": "pattern-regex: x",
		"d": "patterns:\n- pattern: acme::f(...)\n- pattern: acme::g(...)",
		"e": "patterns:\n- pattern: $X.seal(...)\n- pattern-not: $X.seal(acme::ZERO)",
	}
	out, err := ExportRules(writeRules(t, rustRuleYAML(rules)))
	if err != nil {
		t.Fatal(err)
	}
	var compiled, skipped, sites int
	seen := map[string]bool{}
	for _, r := range out {
		if seen[r.ID] {
			t.Errorf("rule %s has two records", r.ID)
		}
		seen[r.ID] = true
		switch r.Status {
		case "compiled":
			compiled++
			sites += len(r.Sites)
		case "skipped":
			skipped++
			if !slices.Contains(rustSkipReasons, rustSkip(r.Reason)) {
				t.Errorf("rule %s: reason %q is not in the closed set", r.ID, r.Reason)
			}
		}
		if len(r.DroppedClauses) != 0 {
			t.Errorf("rule %s dropped %v", r.ID, r.DroppedClauses)
		}
		for _, s := range r.Sites {
			if strings.Contains(string(s), `"lossy"`) || !strings.Contains(string(s), `"rust": {`) {
				t.Errorf("rule %s site %s", r.ID, s)
			}
		}
	}
	if len(out) != 5 || compiled != 3 || skipped != 2 || compiled+skipped != len(out) || sites != 4 {
		t.Errorf("%d rules: %d compiled (%d sites) + %d skipped, want 5: 3 (4) + 2", len(out), compiled, sites, skipped)
	}
}

// A compiled Rust entry, written as a v3 site card, loads back into the
// same pattern: site cards carry the Rust form unchanged.
func TestRustSiteCardRoundTrip(t *testing.T) {
	rule := "patterns:\n- pattern-inside: |\n    use $IMPORT;\n    ...\n- pattern: Kdf::<$H>::new(...)\n- metavariable-regex: {metavariable: $IMPORT, regex: '^acme'}"
	r := exportRust(t, map[string]string{"acme.kdf": rule})["acme.kdf"]
	if len(r.Sites) != 1 {
		t.Fatalf("sites = %d", len(r.Sites))
	}
	cards := "format: scanoss-cards/3\nrules:\n  acme.kdf: {severity: INFO, message: m, crypto: {assetType: algorithm}}\ncards:\n- rule: acme.kdf\n  site: " + string(r.Sites[0]) + "\n"
	dir := writeCards(t, map[string]string{"acme/rules.cards": cards})
	a, err := Load("", dir, filepath.Join(dir, "no-rules"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileIndex(writeRules(t, rustRuleYAML(map[string]string{"acme.kdf": rule})))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.index.Entries) != 1 || a.index.Entries[0].Rust == nil {
		t.Fatalf("site card entries = %+v", a.index.Entries)
	}
	got, want := mustJSON(t, a.index.Entries[0].Rust), mustJSON(t, compiled.Entries[0].Rust)
	if got != want || !strings.Contains(got, `"generics":[{"var":"$H"}]`) {
		t.Errorf("site card pattern\n got %s\nwant %s", got, want)
	}
}
