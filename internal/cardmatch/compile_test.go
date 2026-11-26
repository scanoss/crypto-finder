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

package cardmatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// compileYAML compiles one rule file holding src and returns its entries and rule records as JSON.
func compileYAML(t *testing.T, src string) (entries, rules []string) {
	t.Helper()
	return compileYAMLMode(t, src, false)
}

// compileYAMLMode is compileYAML with or without the Python extensions (poc).
func compileYAMLMode(t *testing.T, src string, poc bool) (entries, rules []string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := compileRulesDirMode(dir, poc)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range c.Entries {
		entries = append(entries, jsonValue(e))
	}
	for _, r := range c.Rules {
		rules = append(rules, jsonValue(r))
	}
	return entries, rules
}

func TestCompileShapes(t *testing.T) {
	cases := []struct {
		name, src string
		entries   []string
		rules     []string
	}{
		{
			name: "plain call",
			src: `rules:
- id: md5
  pattern: MessageDigest.getInstance("MD5")
  metadata: {crypto: {algorithmName: MD5, size: 128}}
`,
			entries: []string{`{"receiver": "type", "type": "MessageDigest", "method": "getInstance", "min_arity": 1, "max_arity": 1, ` +
				`"args": [{"kind": "literal", "value": "\"MD5\"", "index": 0}], "method_regex": null, "constraints": [], "not_calls": [], ` +
				`"focus_arg": null, "dropped_clauses": [], "pattern": "MessageDigest.getInstance(\"MD5\")", "rule_id": "md5", "taint": false, ` +
				`"metadata": {"algorithmName": "MD5", "size": 128}}`},
			rules: []string{`{"rule_id": "md5", "file": "rules.yaml", "taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`},
		},
		{
			name: "pattern-either alternatives, two dropped",
			src: `rules:
- id: keygen
  pattern-either:
  - pattern: new $K.Builder(...)
  - pattern: $G.init(foo($X))
  - pattern: KeyGenerator.getInstance(...)
`,
			entries: []string{`{"receiver": "type", "type": "KeyGenerator", "method": "getInstance", "min_arity": 0, "max_arity": null, ` +
				`"args": [{"kind": "ellipsis", "index": 0}], "method_regex": null, "constraints": [], "not_calls": [], "focus_arg": null, ` +
				`"dropped_clauses": ["pattern-either alternative: unrecognised pattern shape", ` + //nolint:misspell // verbatim compile-report text; respelling changes the report output
				`"pattern-either alternative: argument is a sub-pattern with a metavariable"], ` +
				`"pattern": "KeyGenerator.getInstance(...)", "rule_id": "keygen", "taint": false, "metadata": {}}`},
			rules: []string{`{"rule_id": "keygen", "file": "rules.yaml", "taint": false, "status": "compiled", ` +
				`"dropped_clauses": ["pattern-either alternative: argument is a sub-pattern with a metavariable", ` +
				`"pattern-either alternative: unrecognised pattern shape"], "sinks": 1}`}, //nolint:misspell // verbatim compile-report text; respelling changes the report output
		},
		{
			name: "metavariable-regex on an argument",
			src: `rules:
- id: rsa
  patterns:
  - pattern: KeyPairGenerator.getInstance($ALG)
  - metavariable-regex:
      metavariable: $ALG
      regex: ^"(?<alg>RSA|DSA)"$
- id: digest-method
  patterns:
  - pattern: DigestUtils.$M(...)
  - metavariable-regex: {metavariable: $M, regex: '(?<alg>md5|sha1)Hex'}
`,
			entries: []string{
				`{"receiver": "type", "type": "KeyPairGenerator", "method": "getInstance", "min_arity": 1, "max_arity": 1, ` +
					`"args": [{"kind": "metavar", "name": "$ALG", "index": 0}], "method_regex": null, ` +
					`"constraints": [{"metavar": "$ALG", "arg_index": 0, "regex": "^\"(?P\u003calg\u003eRSA|DSA)\"$", "polarity": "positive", "clause": "metavariable-regex"}], ` +
					`"not_calls": [], "focus_arg": null, "dropped_clauses": [], "pattern": "KeyPairGenerator.getInstance($ALG)", "rule_id": "rsa", "taint": false, "metadata": {}}`,
				`{"receiver": "type", "type": "DigestUtils", "method": null, "min_arity": 0, "max_arity": null, "args": [{"kind": "ellipsis", "index": 0}], ` +
					`"method_regex": "(?P\u003calg\u003emd5|sha1)Hex", "method_metavar": "$M", "constraints": [], "not_calls": [], "focus_arg": null, ` +
					`"dropped_clauses": [], "pattern": "DigestUtils.$M(...)", "rule_id": "digest-method", "taint": false, "metadata": {}}`,
			},
		},
		{
			name: "taint rule: sources regex, focus-metavariable",
			src: `rules:
- id: cipher-taint
  mode: taint
  pattern-sources:
  - patterns:
    - pattern: $S
    - metavariable-regex: {metavariable: $S, regex: '"AES.*"'}
  pattern-sinks:
  - patterns:
    - pattern: Cipher.getInstance($T, ...)
    - focus-metavariable: $T
`,
			entries: []string{`{"receiver": "type", "type": "Cipher", "method": "getInstance", "min_arity": 1, "max_arity": null, ` +
				`"args": [{"kind": "metavar", "name": "$T", "index": 0}, {"kind": "ellipsis", "index": 1}], "method_regex": null, "constraints": [], "not_calls": [], ` +
				`"focus_arg": 0, "dropped_clauses": [], "pattern": "Cipher.getInstance($T, ...)", "taint_sources": ["\"AES.*\""], ` +
				`"rule_id": "cipher-taint", "taint": true, "metadata": {}}`},
		},
		{
			name: "pattern-not and pattern-not-inside as constraints",
			src: `rules:
- id: dyn
  patterns:
  - pattern: Signature.getInstance($A)
  - pattern-not: Signature.getInstance("SHA256withRSA")
  - pattern-not-inside: |
      $A = "...";
      ...
      Signature.getInstance($A);
`,
			entries: []string{`{"receiver": "type", "type": "Signature", "method": "getInstance", "min_arity": 1, "max_arity": 1, ` +
				`"args": [{"kind": "metavar", "name": "$A", "index": 0}], "method_regex": null, ` +
				`"constraints": [{"metavar": "$A", "arg_index": 0, "kind": "not_assigned_string_literal", "polarity": "negative", "clause": "pattern-not-inside"}], ` +
				`"not_calls": [{"receiver": "type", "type": "Signature", "method": "getInstance", "min_arity": 1, "max_arity": 1, ` +
				`"args": [{"kind": "literal", "value": "\"SHA256withRSA\"", "index": 0}], "method_regex": null}], ` +
				`"focus_arg": null, "dropped_clauses": [], "pattern": "Signature.getInstance($A)", "rule_id": "dyn", "taint": false, "metadata": {}}`},
		},
		{
			name: "skipped rule with its reason",
			src: `rules:
- id: field
  pattern: Algorithm.HS256
- id: regex
  pattern-regex: AES
`,
			rules: []string{
				`{"rule_id": "field", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "not a call (field, constant, type or literal reference)"}`,
				`{"rule_id": "regex", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "pattern-regex"}`,
			},
		},
		{
			name: "import clause kept on the callee or dropped",
			src: `rules:
- id: imp
  patterns:
  - pattern-either:
    - pattern-inside: |
        import javax.crypto.Cipher;
        ...
    - pattern-inside: |
        import org.example.Other;
        ...
  - pattern-either:
    - pattern: Cipher.getInstance(...)
    - pattern: Mac.getInstance(...)
`,
			rules: []string{`{"rule_id": "imp", "file": "rules.yaml", "taint": false, "status": "compiled", ` +
				`"dropped_clauses": ["pattern-inside import not about the callee type"], "sinks": 2}`},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, rules := compileYAML(t, c.src)
			if c.entries != nil && !reflect.DeepEqual(entries, c.entries) {
				t.Errorf("entries\n got %s\nwant %s", strings.Join(entries, "\n     "), strings.Join(c.entries, "\n     "))
			}
			if c.rules != nil && !reflect.DeepEqual(rules, c.rules) {
				t.Errorf("rules\n got %s\nwant %s", strings.Join(rules, "\n     "), strings.Join(c.rules, "\n     "))
			}
		})
	}
}

// The import clause becomes callee_packages on the entry whose type it names; the other entry
// records the clause as dropped.
func TestCompileImportClause(t *testing.T) {
	dir := t.TempDir()
	src := `rules:
- id: imp
  patterns:
  - pattern-inside: |
      import javax.crypto.Cipher;
      ...
  - pattern-either:
    - pattern: Cipher.getInstance(...)
    - pattern: Mac.getInstance(...)
`
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ix, err := CompileIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ix.Entries) != 2 {
		t.Fatalf("%d entries", len(ix.Entries))
	}
	if got := ix.Entries[0].CalleePackages; !reflect.DeepEqual(got, []string{"javax.crypto"}) {
		t.Errorf("Cipher callee packages %v", got)
	}
	if got := ix.Entries[1]; got.CalleePackages != nil || !reflect.DeepEqual(got.DroppedClauses, []string{"pattern-inside import not about the callee type"}) {
		t.Errorf("Mac: callee packages %v, dropped %v", got.CalleePackages, got.DroppedClauses)
	}
}

// Parity with compile_rules.py (Java rules) or compile_rules_py.py (Python rules) on a real
// ruleset. Set CARDMATCH_PARITY_RULES to the rules directory and CARDMATCH_PARITY_INDEX to the
// PoC's index.json of it; entries and rule records must be equal, key order included. CARDMATCH_PARITY_OUT, if set, receives the Go output.
func TestCompileParity(t *testing.T) {
	rulesDir, ref := os.Getenv("CARDMATCH_PARITY_RULES"), os.Getenv("CARDMATCH_PARITY_INDEX")
	if rulesDir == "" || ref == "" {
		t.Skip("CARDMATCH_PARITY_RULES / CARDMATCH_PARITY_INDEX not set")
	}
	c, err := compileRulesDirMode(rulesDir, true)
	if err != nil {
		t.Fatal(err)
	}
	got := `{"entries": ` + jsonValue(omapList(c.Entries)) + `, "rules": ` + jsonValue(omapList(c.Rules)) + `}`
	if out := os.Getenv("CARDMATCH_PARITY_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	want := orderedJSON(t, data)
	have := orderedJSON(t, []byte(got))
	ix, err := c.index()
	if err != nil {
		t.Fatal(err)
	}
	refIx, err := loadIndex(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ix, refIx) {
		t.Error("CompileIndex differs from loadIndex of the reference")
	}
	for _, key := range []string{"entries", "rules"} {
		w, _ := want.Get(key)
		h, _ := have.Get(key)
		wl, hl := w.([]any), h.([]any)
		if len(wl) != len(hl) {
			t.Errorf("%s: %d, want %d", key, len(hl), len(wl))
		}
		diffs := 0
		for i := 0; i < len(wl) && i < len(hl); i++ {
			if a, b := jsonValue(hl[i]), jsonValue(wl[i]); a != b {
				diffs++
				if diffs <= 5 {
					t.Errorf("%s[%d]\n got %s\nwant %s", key, i, a, b)
				}
			}
		}
		t.Logf("%s: %d python, %d go, %d differ", key, len(wl), len(hl), diffs)
	}
}

func omapList(l []*OMap) []any {
	out := make([]any, len(l))
	for i, m := range l {
		out[i] = m
	}
	return out
}

func orderedJSON(t *testing.T, data []byte) *OMap {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeOrdered(dec)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*OMap)
}

// End to end: the matcher gives the same findings with the compiled index as with index.json.
// Set CARDMATCH_E2E_RULES, CARDMATCH_E2E_INDEX, CARDMATCH_E2E_CARDS and CARDMATCH_E2E_FRAGMENTS
// (a glob of graph fragment files).
func TestCompiledIndexFindings(t *testing.T) {
	rulesDir, index := os.Getenv("CARDMATCH_E2E_RULES"), os.Getenv("CARDMATCH_E2E_INDEX")
	cardsDir, glob := os.Getenv("CARDMATCH_E2E_CARDS"), os.Getenv("CARDMATCH_E2E_FRAGMENTS")
	if rulesDir == "" || index == "" || cardsDir == "" || glob == "" {
		t.Skip("CARDMATCH_E2E_RULES / _INDEX / _CARDS / _FRAGMENTS not set")
	}
	fromFile, err := Load(index, cardsDir, rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Load("", cardsDir, rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(glob)
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fragments for %s (%v)", glob, err)
	}
	total, sites := 0, 0
	for _, path := range paths {
		frag, err := readFragment(path)
		if err != nil {
			t.Fatal(err)
		}
		want, n := fromFile.mustMatch(t, frag)
		got, _ := compiled.mustMatch(t, frag)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %d findings with the compiled index, %d with index.json", path, len(got), len(want))
		}
		total += len(want)
		sites += n
	}
	t.Logf("%d fragments, %d call sites, %d findings", len(paths), sites, total)
}

// The compiler's output (entries and rule records, extensions on) for a real
// ruleset, for coverage reports: CARDMATCH_COMPILE_RULES (the rules
// directory) and CARDMATCH_COMPILE_OUT (the JSON written). It also checks
// that the index builds.
func TestCompileDump(t *testing.T) {
	rulesDir, out := os.Getenv("CARDMATCH_COMPILE_RULES"), os.Getenv("CARDMATCH_COMPILE_OUT")
	if rulesDir == "" || out == "" {
		t.Skip("CARDMATCH_COMPILE_RULES / CARDMATCH_COMPILE_OUT not set")
	}
	c, err := compileRulesDir(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	got := `{"entries": ` + jsonValue(omapList(c.Entries)) + `, "rules": ` + jsonValue(omapList(c.Rules)) + `}`
	if err := os.WriteFile(out, []byte(got), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.index(); err != nil {
		t.Fatal(err)
	}
}

func readFragment(path string) (*FragmentJSON, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var frag FragmentJSON
	if err := json.NewDecoder(f).Decode(&frag); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &frag, nil
}
