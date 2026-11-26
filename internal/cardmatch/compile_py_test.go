// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// The Python shapes of compile_rules_py.py: entries and rule records as it
// writes them (its index.json), keyword indices still symbolic; the
// compiler's extensions are off.
func TestCompilePythonShapes(t *testing.T) {
	const tail = `"constraints": [], "not_calls": [], "focus_arg": null, "dropped_clauses": []`
	cases := []struct {
		name, src string
		entries   []string
		rules     []string
	}{
		{
			name: "dotted callee, positional and keyword arguments, single quotes",
			src: `rules:
- id: kdf
  languages: [python]
  pattern: hashlib.pbkdf2_hmac('sha1', $PW, ..., dklen=$LEN)
`,
			entries: []string{`{"receiver": "type", "type": "hashlib", "method": "pbkdf2_hmac", "min_arity": 3, "max_arity": null, "args": [` +
				`{"kind": "literal", "value": "\"sha1\"", "index": 0}, {"kind": "metavar", "name": "$PW", "index": 1}, {"kind": "ellipsis", "index": 2}, ` +
				`{"kind": "metavar", "name": "$LEN", "kw": "dklen", "index": "kw:dklen"}], "method_regex": null, ` + tail +
				`, "pattern": "hashlib.pbkdf2_hmac('sha1', $PW, ..., dklen=$LEN)", "rule_id": "kdf", "taint": false, "metadata": {}}`},
		},
		{
			name: "any receiver, bare name, kw=... and keyword literal",
			src: `rules:
- id: two
  languages: [python]
  pattern-either:
  - pattern: $CTX.load_cert_chain(certfile=..., password="x")
  - pattern: new_key(1.5, None, '...')
`,
			entries: []string{
				`{"receiver": "any", "type": null, "method": "load_cert_chain", "min_arity": 2, "max_arity": 2, "args": [` +
					`{"kind": "metavar", "name": null, "kw": "certfile", "index": "kw:certfile"}, {"kind": "literal", "value": "\"x\"", "kw": "password", "index": "kw:password"}], ` +
					`"method_regex": null, ` + tail + `, "pattern": "$CTX.load_cert_chain(certfile=..., password=\"x\")", "rule_id": "two", "taint": false, "metadata": {}}`,
				`{"receiver": "none", "type": null, "method": "new_key", "min_arity": 3, "max_arity": 3, "args": [` +
					`{"kind": "literal", "value": "1.5", "index": 0}, {"kind": "literal", "value": "None", "index": 1}, {"kind": "any_string", "index": 2}], ` +
					`"method_regex": null, ` + tail + `, "pattern": "new_key(1.5, None, '...')", "rule_id": "two", "taint": false, "metadata": {}}`,
			},
		},
		{
			name: "metavariable-regex and focus on a keyword argument",
			src: `rules:
- id: focus
  languages: [python]
  patterns:
  - pattern: hashes.Hash(algorithm=$A)
  - metavariable-regex: {metavariable: $A, regex: '^(?<alg>MD5)$'}
  - focus-metavariable: $A
`,
			entries: []string{`{"receiver": "type", "type": "hashes", "method": "Hash", "min_arity": 1, "max_arity": 1, "args": [` +
				`{"kind": "metavar", "name": "$A", "kw": "algorithm", "index": "kw:algorithm"}], "method_regex": null, ` +
				`"constraints": [{"metavar": "$A", "arg_index": "kw:algorithm", "regex": "^(?P\u003calg\u003eMD5)$", "polarity": "positive", "clause": "metavariable-regex"}], ` +
				`"not_calls": [], "focus_arg": "kw:algorithm", "dropped_clauses": [], "pattern": "hashes.Hash(algorithm=$A)", "rule_id": "focus", "taint": false, "metadata": {}}`},
		},
		{
			name: "Python spelling of the not-assigned-literal inside",
			src: `rules:
- id: dyn
  languages: [python]
  patterns:
  - pattern: hashlib.new($N, ...)
  - pattern-not-inside: |
      $N = '$VALUE'
      ...
`,
			entries: []string{`{"receiver": "type", "type": "hashlib", "method": "new", "min_arity": 1, "max_arity": null, "args": [` +
				`{"kind": "metavar", "name": "$N", "index": 0}, {"kind": "ellipsis", "index": 1}], "method_regex": null, ` +
				`"constraints": [{"metavar": "$N", "arg_index": 0, "kind": "not_assigned_string_literal", "polarity": "negative", "clause": "pattern-not-inside"}], ` +
				`"not_calls": [], "focus_arg": null, "dropped_clauses": [], "pattern": "hashlib.new($N, ...)", "rule_id": "dyn", "taint": false, "metadata": {}}`},
		},
		{
			name: "skips",
			src: `rules:
- {id: assign, languages: [python], pattern: '$K = rsa.generate_private_key(...)'}
- {id: with, languages: [python], pattern: 'with open(...) as $F'}
- {id: chain, languages: [python], pattern: 'x509.CertificateBuilder().sign(...)'}
- {id: ref, languages: [python], pattern: 'ssl.PROTOCOL_TLSv1'}
- {id: str, languages: [python], pattern: '"md5"'}
- {id: sub, languages: [python], pattern: 'k.sign(d, padding.PSS(...))'}
- {id: kwell, languages: [python], pattern: 'f(a=$...X)'}
- {id: after, languages: [python], pattern: 'f(..., $X)'}
- id: notmap
  languages: [python]
  patterns:
  - pattern: f($X)
  - pattern-not: {pattern: g()}
`,
			rules: []string{
				`{"rule_id": "assign", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "unrecognised pattern shape"}`, //nolint:misspell // verbatim compile-report text; respelling changes the report output
				`{"rule_id": "with", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "statement, block or declaration pattern"}`,
				`{"rule_id": "chain", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "chained call pattern"}`,
				`{"rule_id": "ref", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "not a call (attribute, constant, name or literal reference)"}`,
				`{"rule_id": "str", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "not a call (attribute, constant, name or literal reference)"}`,
				`{"rule_id": "sub", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "argument is a sub-pattern with a metavariable"}`,
				`{"rule_id": "kwell", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "keyword argument bound to an ellipsis metavariable"}`,
				`{"rule_id": "after", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "argument after an ellipsis (index not fixed)"}`,
				`{"rule_id": "notmap", "file": "rules.yaml", "taint": false, "status": "skipped", "reason": "pattern-not that is not a plain call (pattern given as a mapping)"}`,
			},
		},
		{
			name: "the shapes follow the rule's language",
			src: `rules:
- {id: java, languages: [java], pattern: "f('a')"}
- {id: py, languages: [python], pattern: "f('a')"}
`,
			entries: []string{
				`{"receiver": "none", "type": null, "method": "f", "min_arity": 1, "max_arity": 1, "args": [{"kind": "text", "value": "'a'", "index": 0}], ` +
					`"method_regex": null, ` + tail + `, "pattern": "f('a')", "rule_id": "java", "taint": false, "metadata": {}}`,
				`{"receiver": "none", "type": null, "method": "f", "min_arity": 1, "max_arity": 1, "args": [{"kind": "literal", "value": "\"a\"", "index": 0}], ` +
					`"method_regex": null, ` + tail + `, "pattern": "f('a')", "rule_id": "py", "taint": false, "metadata": {}}`,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries, rules := compileYAMLMode(t, c.src, true)
			if c.entries != nil && !reflect.DeepEqual(entries, c.entries) {
				t.Errorf("entries\n got %s\nwant %s", strings.Join(entries, "\n     "), strings.Join(c.entries, "\n     "))
			}
			if c.rules != nil && !reflect.DeepEqual(rules, c.rules) {
				t.Errorf("rules\n got %s\nwant %s", strings.Join(rules, "\n     "), strings.Join(c.rules, "\n     "))
			}
		})
	}
}

// A compiled Python rule matches a Python fragment end to end: keyword
// arguments by name, a metavariable-regex on a keyword argument filling the
// metadata, a positional literal.
func TestCompiledPythonIndexMatches(t *testing.T) {
	dir := t.TempDir()
	src := `rules:
- id: hash
  languages: [python]
  patterns:
  - pattern: cryptography.hazmat.primitives.hashes.Hash(algorithm=$A, ...)
  - metavariable-regex: {metavariable: $A, regex: '^hashes\.(?<alg>MD5|SHA1)\(\)$'}
  metadata: {crypto: {algorithmName: $alg}}
- id: kdf
  languages: [python]
  pattern: hashlib.pbkdf2_hmac('sha1', ...)
  metadata: {crypto: {algorithmName: PBKDF2}}
- id: carded
  languages: [python]
  pattern: hashlib.md5(...)
  metadata: {crypto: {algorithmName: MD5}}
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cards := t.TempDir()
	if err := os.WriteFile(filepath.Join(cards, "rules.cards"), []byte("cards:\n- rule: carded\n  match: {call: hashlib.sha1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assets, err := Load("", cards, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "hashlib"}, {Line: 2, Module: "cryptography.hazmat.primitives", Name: "hashes"}},
		pyCall("cryptography.hazmat.primitives.hashes.Hash", "hashes.Hash", 5, kw(0, "algorithm", "hashes.MD5()")),
		pyCall("cryptography.hazmat.primitives.hashes.Hash", "hashes.Hash", 6, pos(0, "hashes.MD5()")),
		pyCall("cryptography.hazmat.primitives.hashes.Hash", "hashes.Hash", 7, kw(0, "algorithm", "hashes.SHA256()")),
		pyCall("hashlib.pbkdf2_hmac", "hashlib.pbkdf2_hmac", 8, pos(0, "'sha1'"), pos(1, "pw"), kw(2, "dklen", "32")),
		pyCall("hashlib.pbkdf2_hmac", "hashlib.pbkdf2_hmac", 9, kw(0, "hash_name", "'sha1'")),
		pyCall("hashlib.md5", "hashlib.md5", 10),
		pyCall("hashlib.sha1", "hashlib.sha1", 11),
	)
	found, _ := assets.mustMatch(t, frag)
	got := ruleLines(found)
	want := []string{
		`carded@11 {"algorithmName": "MD5"}`,
		`hash@5 {"algorithmName": "MD5"}`,
		`kdf@8 {"algorithmName": "PBKDF2"}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// keywordIndices turns every symbolic keyword index into the matcher's
// keyword id, in arguments, not_calls, constraints and the focus.
func TestKeywordIndices(t *testing.T) {
	e := omap("args", []any{omap("index", "kw:a"), omap("index", int64(0))},
		"not_calls", []any{omap("args", []any{omap("index", "kw:b")})},
		"constraints", []any{omap("arg_index", "kw:a")}, "focus_arg", "kw:c")
	keywordIndices([]*OMap{e})
	want := `{"args": [{"index": ` + itoa(kwKey("a")) + `}, {"index": 0}], "not_calls": [{"args": [{"index": ` + itoa(kwKey("b")) +
		`}]}], "constraints": [{"arg_index": ` + itoa(kwKey("a")) + `}], "focus_arg": ` + itoa(kwKey("c")) + `}`
	if got := jsonValue(e); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}
