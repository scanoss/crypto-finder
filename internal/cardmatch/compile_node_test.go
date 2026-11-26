// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The rules below are invented: "acme-crypto" is not a real library and none
// of them comes from a ruleset.

// compileNode compiles rule YAML and returns each rule's entries in site form
// and its record, after checking the entries load (validateNode).
func compileNode(t *testing.T, src string) (sites map[string][]string, records map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := compileRulesDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	sites, records = map[string][]string{}, map[string]string{}
	for _, e := range c.Entries {
		id := pyStr(e.GetOr("rule_id"))
		sites[id] = append(sites[id], jsonValue(SiteEntry(e)))
	}
	for _, r := range c.Rules {
		rec := &OMap{}
		for i, k := range r.Keys {
			if k != "file" && k != "rule_id" {
				rec.Set(k, r.Vals[i])
			}
		}
		records[pyStr(r.GetOr("rule_id"))] = jsonValue(rec)
	}
	if _, err := c.index(); err != nil {
		t.Fatalf("compiled node entries do not load: %v", err)
	}
	return sites, records
}

type nodeWant struct {
	record string
	sites  []string
}

// TestCompileNodeShapes pins the entries of each rule shape: every spelling of
// an import and of a call collapses to the callee key reach gives the call.
func TestCompileNodeShapes(t *testing.T) {
	cases := []struct {
		name, src string
		want      map[string]nodeWant
	}{
		{
			name: "guards of every form, module metavariables",
			src: `rules:
- id: guards
  languages: [javascript, typescript]
  pattern-either:
  - patterns:
    - pattern-either:
      - pattern-inside: |
          $NS = <... require("acme-crypto") ...>
          ...
      - pattern-inside: |
          import $NS from "acme-crypto"
          ...
      - pattern-inside: |
          import * as $NS from "acme-crypto"
          ...
      - pattern-inside: |
          $NS = <... import("acme-crypto") ...>
          ...
      - pattern-inside: |
          $NS = $E("acme-crypto")
          ...
      - pattern-inside: |
          try {
            $NS = require("acme-crypto");
          } catch ($ERR) {
          }
          ...
      - pattern-inside: |
          $RAW = require("acme-crypto")
          ...
          $NS = $INTEROP($RAW)
          ...
    - pattern-either:
      - pattern: $NS.cipher.encrypt(...)
      - pattern: $NS.default.cipher.encrypt(...)
      - pattern: (0, $NS.cipher.encrypt)(...)
  - patterns:
    - pattern-either:
      - pattern-inside: |
          var {..., cipher, ...} = require("acme-crypto")
          ...
      - pattern-inside: |
          import {..., cipher, ...} from "acme-crypto"
          ...
    - pattern: cipher.encrypt(...)
  - patterns:
    - pattern-either:
      - pattern-inside: |
          var {cipher: $L} = require("acme-crypto")
          ...
      - pattern-inside: |
          import {cipher as $L} from "acme-crypto"
          ...
    - pattern: $L.encrypt(...)
  - pattern: require("acme-crypto").cipher.encrypt(...)
- id: modvar
  languages: [javascript]
  patterns:
  - pattern-either:
    - patterns:
      - pattern-inside: |
          $C = require($M)
          ...
      - pattern: $C.digest($ALG, ...)
    - patterns:
      - pattern-inside: |
          import {..., digest, ...} from $M
          ...
      - pattern: digest($ALG, ...)
    - pattern: acme.digest($ALG, ...)
  - metavariable-regex:
      metavariable: $M
      regex: ^["']?(?:node:)?acme-crypto["']?$
  - metavariable-regex:
      metavariable: $ALG
      regex: (?i)^["'](?<alg>sha1)["']$
- id: modvar-open
  languages: [javascript]
  pattern-either:
  - patterns:
    - pattern-inside: |
        $C = require($M)
        ...
    - pattern: $C.digest(...)
    - metavariable-regex: {metavariable: $M, regex: '^.*crypto$'}
  - patterns:
    - pattern-inside: |
        $C = require("acme-crypto")
        ...
    - pattern: $C.digest(...)
`,
			want: map[string]nodeWant{
				"guards": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 5}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "cipher.encrypt", "member": true}, "method": "encrypt", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "cipher.encrypt", "member": true, "wrapped": true}, "method": "encrypt", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "cipher.encrypt", "local_regex": "^cipher$"}, "method": "encrypt", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "cipher.encrypt"}, "method": "encrypt", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "cipher.encrypt", "inline": true}, "method": "encrypt", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"modvar": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 3}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto", "node:acme-crypto"], "path": "digest", "member": true}, "method": "digest", "min_arity": 1, "max_arity": null, "arg_pattern": "$ALG, ...", "constraints": [{"metavar": "$ALG", "regex": "(?i)^[\"'](?P\u003calg\u003esha1)[\"']$"}], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto", "node:acme-crypto"], "path": "digest", "local_regex": "^digest$"}, "method": "digest", "min_arity": 1, "max_arity": null, "arg_pattern": "$ALG, ...", "constraints": [{"metavar": "$ALG", "regex": "(?i)^[\"'](?P\u003calg\u003esha1)[\"']$"}], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "written", "path": "acme.digest"}, "method": "digest", "min_arity": 1, "max_arity": null, "arg_pattern": "$ALG, ...", "constraints": [{"metavar": "$ALG", "regex": "(?i)^[\"'](?P\u003calg\u003esha1)[\"']$"}], "not_calls": [], "taint": false}`,
					},
				},
				"modvar-open": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": ["pattern-either alternative: module regex not finite"], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "digest", "member": true}, "method": "digest", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false, "lossy": ["pattern-either alternative: module regex not finite"]}`,
					},
				},
			},
		},
		{
			name: "callee forms: new, instances, the module binding, WebCrypto, objects, written",
			src: `rules:
- id: ctor
  languages: [javascript]
  patterns:
  - pattern-inside: |
      import * as $NS from "acme-crypto"
      ...
  - pattern: new $NS.modes.Cipher($KEY, ...)
- id: instance
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
      $C = new $NS.Cipher(...)
      ...
  - pattern: $C.update(...)
- id: instance-args
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern-inside: |
      $C = new $NS.Cipher("x")
      ...
  - pattern: $C.update(...)
- id: module-call
  languages: [javascript]
  pattern-either:
  - patterns:
    - pattern-inside: |
        import $LIB from "acme-crypto"
        ...
    - pattern: $LIB($DATA)
    - metavariable-regex: {metavariable: $LIB, regex: '^(acmeHash)$'}
  - patterns:
    - pattern-inside: |
        $F = require("acme-crypto")
        ...
    - pattern: new $F(...)
- id: webcrypto
  languages: [javascript]
  pattern-either:
  - pattern: crypto.subtle.digest(...)
  - pattern: globalThis.crypto.subtle.digest(...)
  - pattern: $X.webcrypto.subtle.digest(...)
  - pattern: require("crypto").subtle.digest(...)
  - patterns:
    - pattern-inside: |
        const { subtle } = crypto
        ...
    - pattern: subtle.digest(...)
  - patterns:
    - pattern-inside: |
        $S = window.crypto.subtle
        ...
    - pattern: $S.digest(...)
- id: random
  languages: [javascript]
  pattern-either:
  - pattern: crypto.getRandomValues($B)
  - pattern: window.crypto.getRandomValues($B)
  - pattern: require("crypto").getRandomValues($B)
- id: object
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern-either:
    - patterns:
      - pattern-inside: |
          $H = $NS.createHash("sha1")
          ...
      - pattern: $H.update(...)
    - pattern: $NS.createHash("sha1").update(...)
- id: written
  languages: [javascript]
  pattern: acmeHash($X)
`,
			want: map[string]nodeWant{
				"ctor": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "modes.(Cipher).\u003cinit\u003e", "new": true, "member": true}, "method": "\u003cinit\u003e", "min_arity": 1, "max_arity": null, "arg_pattern": "$KEY, ...", "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"instance": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "(Cipher).update"}, "method": "update", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"instance-args": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": ["constructor arguments of the receiver"], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "(Cipher).update"}, "method": "update", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false, "lossy": ["constructor arguments of the receiver"]}`,
					},
				},
				"module-call": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 2}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "default", "local_regex": "^(acmeHash)$"}, "method": "default", "min_arity": 1, "max_arity": 1, "arg_pattern": "$DATA", "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "(default).\u003cinit\u003e", "new": true}, "method": "\u003cinit\u003e", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"object": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "object", "path": "update", "from": [{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "createHash", "member": true}, "method": "createHash", "min_arity": 1, "max_arity": 1, "arg_pattern": "\"sha1\""}], "via": ["chain", "var"]}, "method": "update", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"random": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 3}`,
					sites: []string{
						`{"callee": {"bind": "global", "path": "(Crypto).getRandomValues", "written": "crypto.getRandomValues"}, "method": "getRandomValues", "min_arity": 1, "max_arity": 1, "arg_pattern": "$B", "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "global", "path": "(Crypto).getRandomValues", "written": "window.crypto.getRandomValues"}, "method": "getRandomValues", "min_arity": 1, "max_arity": 1, "arg_pattern": "$B", "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["crypto"], "path": "getRandomValues", "inline": true}, "method": "getRandomValues", "min_arity": 1, "max_arity": 1, "arg_pattern": "$B", "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"webcrypto": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 6}`,
					sites: []string{
						`{"callee": {"bind": "global", "path": "(SubtleCrypto).digest", "written": "crypto.subtle.digest"}, "method": "digest", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "global", "path": "(SubtleCrypto).digest", "written": "globalThis.crypto.subtle.digest"}, "method": "digest", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "global", "path": "(SubtleCrypto).digest", "written": "$X.webcrypto.subtle.digest"}, "method": "digest", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "global", "path": "(SubtleCrypto).digest", "written": "require(\"crypto\").subtle.digest"}, "method": "digest", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "global", "path": "(SubtleCrypto).digest", "written": "subtle.digest"}, "method": "digest", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "global", "path": "(SubtleCrypto).digest", "written": "$S.digest"}, "method": "digest", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"written": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "written", "path": "acmeHash"}, "method": "acmeHash", "min_arity": 1, "max_arity": 1, "arg_pattern": "$X", "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
			},
		},
		{
			name: "member metavariables, arguments, negations, context calls, skips",
			src: `rules:
- id: members
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern-either:
    - pattern: $NS.$FN($KEY)
    - pattern: $NS.$CTX.sign(...)
    - pattern: $NS.$ANY.verify(...)
  - metavariable-regex: {metavariable: $FN, regex: '^(encrypt|decrypt)$'}
  - metavariable-regex: {metavariable: $CTX, regex: '^ctx\d+$'}
- id: args-nots
  languages: [javascript]
  patterns:
  - pattern-either:
    - patterns:
      - pattern-inside: |
          import * as $NS from "acme-crypto"
          ...
      - pattern: '$NS.seal($KEY, {..., mode: $MODE, ...}, ...)'
    - patterns:
      - pattern-inside: |
          import {..., seal, ...} from "acme-crypto"
          ...
      - pattern: 'seal($KEY, {..., mode: $MODE, ...}, ...)'
  - metavariable-regex: {metavariable: $MODE, regex: '^"(?<mode>gcm|ccm)"$'}
  - pattern-not: '$NS.seal($KEY, {..., mode: $MODE, legacy: true, ...}, ...)'
  - pattern-not: $NS.open(...)
  - pattern-not-inside: |
      import $OTHER from "acme-crypto-legacy"
      ...
  - pattern-not-inside: |
      import {seal as $X} from "acme-crypto"
      ...
  - pattern-not-inside: |
      function $F(...) { ... }
  - focus-metavariable: $MODE
- id: fuse
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern-inside: $NS.sign($DATA, ...)
  - pattern: '{..., alg: "none", ...}'
- id: shapes
  languages: [javascript]
  patterns:
  - pattern-inside: |
      import $NS from "acme-crypto"
      ...
  - pattern: $NS.keygen(...)
  - pattern: '$CALL({..., curve: $CURVE, ...})'
  - pattern: '$CALL({..., type: "ec", ...})'
- id: generic
  languages: [javascript]
  patterns:
  - pattern-inside: |
      import {..., p256, ...} from "acme-crypto"
      ...
  - pattern: $OBJ.sign(...)
  - metavariable-pattern: {metavariable: $OBJ, language: generic, pattern: p256}
- id: literal
  languages: [javascript]
  patterns:
  - pattern-inside: |
      import $NS from "acme-crypto"
      ...
  - pattern: '{..., alg: "none", ...}'
- id: read
  languages: [javascript]
  patterns:
  - pattern-inside: |
      import $NS from "acme-crypto"
      ...
  - pattern: $NS.modes.CBC
- id: regex
  languages: [javascript]
  pattern-regex: acme
- id: partly
  languages: [javascript]
  pattern-either:
  - pattern: acmeSeal(...)
  - patterns:
    - pattern: acmeOpen($N)
    - metavariable-comparison: {comparison: $N > 1}
- id: callback
  languages: [javascript]
  patterns:
  - pattern: acmeSeal($CB)
  - metavariable-pattern:
      metavariable: $CB
      patterns:
      - pattern: (...) => $BODY
`,
			want: map[string]nodeWant{
				"args-nots": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": ["pattern-not-inside"], "sinks": 2}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "seal", "member": true}, "method": "seal", "min_arity": 2, "max_arity": null, "arg_pattern": "$KEY, {..., mode:$MODE, ...}, ...", "constraints": [{"metavar": "$MODE", "regex": "^\"(?P\u003cmode\u003egcm|ccm)\"$"}], "not_calls": [{"min_arity": 2, "max_arity": null, "arg_pattern": "$KEY, {..., mode:$MODE, legacy:true, ...}, ..."}], "not_imports": ["acme-crypto-legacy"], "focus_metavar": "$MODE", "taint": false, "lossy": ["pattern-not-inside"]}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "seal", "local_regex": "^seal$"}, "method": "seal", "min_arity": 2, "max_arity": null, "arg_pattern": "$KEY, {..., mode:$MODE, ...}, ...", "constraints": [{"metavar": "$MODE", "regex": "^\"(?P\u003cmode\u003egcm|ccm)\"$"}], "not_calls": [{"min_arity": 2, "max_arity": null, "arg_pattern": "$KEY, {..., mode:$MODE, legacy:true, ...}, ..."}], "not_imports": ["acme-crypto-legacy"], "focus_metavar": "$MODE", "taint": false, "lossy": ["pattern-not-inside"]}`,
					},
				},
				"callback": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": ["metavariable-pattern $CB"], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "written", "path": "acmeSeal"}, "method": "acmeSeal", "min_arity": 1, "max_arity": 1, "arg_pattern": "$CB", "constraints": [], "not_calls": [], "taint": false, "lossy": ["metavariable-pattern $CB"]}`,
					},
				},
				"fuse": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "literal", "modules": ["acme-crypto"]}, "method": null, "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., alg:\"none\", ...}", "constraints": [], "not_calls": [], "within": [{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "sign", "member": true}, "method": "sign", "min_arity": 2, "max_arity": null, "arg_pattern": "$DATA, ..., \u003c...{..., alg:\"none\", ...}...\u003e, ..."}], "taint": false}`,
					},
				},
				"generic": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "p256.sign", "local_regex": "^p256$"}, "method": "sign", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"literal": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "literal", "modules": ["acme-crypto"]}, "method": null, "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., alg:\"none\", ...}", "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"members": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 4}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "decrypt", "member": true}, "method": "decrypt", "min_arity": 1, "max_arity": 1, "arg_pattern": "$KEY", "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "encrypt", "member": true}, "method": "encrypt", "min_arity": 1, "max_arity": 1, "arg_pattern": "$KEY", "constraints": [], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path_regex": "^(?P\u003cCTX\u003e[^.()]+)\\.sign$", "member": true}, "method": "sign", "min_arity": 0, "max_arity": null, "constraints": [{"metavar": "$CTX", "regex": "^ctx\\d+$"}], "not_calls": [], "taint": false}`,
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path_regex": "^(?P\u003cANY\u003e[^.()]+)\\.verify$", "member": true}, "method": "verify", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
				"partly": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": ["pattern-either alternative: metavariable-comparison"], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "written", "path": "acmeSeal"}, "method": "acmeSeal", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false, "lossy": ["pattern-either alternative: metavariable-comparison"]}`,
					},
				},
				"read": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "modes.CBC", "member": true}, "method": "CBC", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "read": true, "taint": false}`,
					},
				},
				"regex": {
					record: `{"taint": false, "status": "skipped", "reason": "pattern-regex"}`,
				},
				"shapes": {
					record: `{"taint": false, "status": "compiled", "dropped_clauses": [], "sinks": 1}`,
					sites: []string{
						`{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "keygen", "member": true}, "method": "keygen", "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., curve:$CURVE, type:\"ec\", ...}", "constraints": [], "not_calls": [], "taint": false}`,
					},
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sites, records := compileNode(t, c.src)
			if len(records) != len(c.want) {
				t.Errorf("%d rules compiled, want %d", len(records), len(c.want))
			}
			for id, w := range c.want {
				if records[id] != w.record {
					t.Errorf("%s: record\n got %s\nwant %s", id, records[id], w.record)
				}
				if !reflect.DeepEqual(sites[id], w.sites) && (len(sites[id]) > 0 || len(w.sites) > 0) {
					t.Errorf("%s: sites\n got %s\nwant %s", id, strings.Join(sites[id], "\n     "), strings.Join(w.sites, "\n     "))
				}
			}
		})
	}
}

// The compiler's output does not depend on map order: the same rules give the
// same entries every time, modules merged in sorted order.
func TestCompileNodeDeterministic(t *testing.T) {
	src := `rules:
- id: merge
  languages: [javascript]
  pattern-either:
  - patterns:
    - pattern-inside: |
        import * as $NS from "zeta-crypto"
        ...
    - pattern: $NS.hash(...)
  - patterns:
    - pattern-inside: |
        $NS = require($M)
        ...
    - pattern: $NS.hash(...)
    - metavariable-regex: {metavariable: $M, regex: '^"(beta|alpha)-crypto"$'}
  - pattern: hashIt(...)
`
	want := []string{
		`{"callee": {"bind": "import", "modules": ["alpha-crypto", "beta-crypto", "zeta-crypto"], "path": "hash", "member": true}, "method": "hash", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
		`{"callee": {"bind": "written", "path": "hashIt"}, "method": "hashIt", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`,
	}
	for i := 0; i < 5; i++ {
		sites, _ := compileNode(t, src)
		if !reflect.DeepEqual(sites["merge"], want) {
			t.Fatalf("run %d:\n got %s\nwant %s", i, strings.Join(sites["merge"], "\n     "), strings.Join(want, "\n     "))
		}
	}
}

// An alternative whose guard is not an import is dropped; a rule none of whose
// alternatives compile is skipped with the reason most of them gave.
func TestCompileNodeSkipReasons(t *testing.T) {
	src := `rules:
- id: class-context
  languages: [typescript]
  pattern-either:
  - patterns:
    - pattern-inside: |
        class $C { ... }
    - pattern: $X.sign(...)
  - patterns:
    - pattern-inside: |
        import $NS from "acme-crypto"
        ...
    - pattern: $NS.sign(...)
- id: unbound
  languages: [javascript]
  pattern: $F($X)
- id: taint
  languages: [javascript]
  mode: taint
  pattern-sources: [{pattern: source()}]
  pattern-sinks: [{pattern: sink($X)}]
`
	_, records := compileNode(t, src)
	for id, want := range map[string]string{
		"class-context": `{"taint": false, "status": "compiled", "dropped_clauses": ["pattern-either alternative: guard: unsupported statement starting with \"class\""], "sinks": 1}`,
		"unbound":       `{"taint": false, "status": "skipped", "reason": "unbound metavariable callee $F"}`,
		"taint":         `{"taint": true, "status": "skipped", "reason": "taint source is not a bare metavariable"}`,
	} {
		if records[id] != want {
			t.Errorf("%s:\n got %s\nwant %s", id, records[id], want)
		}
	}
}

// A loaded node entry is checked once, at load: a malformed one fails the
// index instead of matching wrongly.
func TestValidateNodeEntries(t *testing.T) {
	ok := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "seal"}, "method": "seal", "min_arity": 1, "max_arity": 1, "arg_pattern": "$K"}`
	cases := map[string]string{
		"no modules":            `{"callee": {"bind": "import", "path": "seal"}, "min_arity": 0}`,
		"path and regex":        `{"callee": {"bind": "import", "modules": ["m"], "path": "seal", "path_regex": "^seal$"}, "min_arity": 0}`,
		"bad regex":             `{"callee": {"bind": "import", "modules": ["m"], "path_regex": "^(seal$"}, "min_arity": 0}`,
		"new without init":      `{"callee": {"bind": "import", "modules": ["m"], "path": "Cipher", "new": true}, "min_arity": 0}`,
		"global with modules":   `{"callee": {"bind": "global", "modules": ["m"], "path": "(Crypto).getRandomValues"}, "min_arity": 0}`,
		"global not interface":  `{"callee": {"bind": "global", "path": "getRandomValues"}, "min_arity": 0}`,
		"object without from":   `{"callee": {"bind": "object", "path": "update", "via": ["var"]}, "min_arity": 0}`,
		"object dotted path":    `{"callee": {"bind": "object", "path": "a.update", "via": ["var"], "from": [{"callee": {"bind": "written", "path": "f"}, "min_arity": 0}]}, "min_arity": 0}`,
		"object bad via":        `{"callee": {"bind": "object", "path": "update", "via": ["wire"], "from": [{"callee": {"bind": "written", "path": "f"}, "min_arity": 0}]}, "min_arity": 0}`,
		"unknown bind":          `{"callee": {"bind": "magic", "path": "f"}, "min_arity": 0}`,
		"arity mismatch":        `{"callee": {"bind": "written", "path": "f"}, "min_arity": 0, "arg_pattern": "$K"}`,
		"bad arg pattern":       `{"callee": {"bind": "written", "path": "f"}, "min_arity": 0, "arg_pattern": "$K ="}`,
		"focus not bound":       `{"callee": {"bind": "written", "path": "f"}, "min_arity": 1, "max_arity": 1, "arg_pattern": "$K", "focus_metavar": "$X"}`,
		"constraint on index":   `{"callee": {"bind": "written", "path": "f"}, "min_arity": 0, "constraints": [{"arg_index": 0, "regex": "x"}]}`,
		"not_calls with callee": `{"callee": {"bind": "written", "path": "f"}, "min_arity": 0, "not_calls": [{"callee": {"bind": "written", "path": "f"}, "min_arity": 0}]}`,
		"java with arg_pattern": `{"receiver": "none", "method": "f", "min_arity": 1, "max_arity": 1, "arg_pattern": "$K"}`,
		"java with not_imports": `{"receiver": "none", "method": "f", "min_arity": 0, "not_imports": ["m"]}`,
		"node with java args":   `{"callee": {"bind": "written", "path": "f"}, "min_arity": 0, "args": [{"kind": "metavar", "index": 0}]}`,
	}
	load := func(entry string) error {
		var ix Index
		if err := json.Unmarshal([]byte(`{"entries": [`+entry+`]}`), &ix); err != nil {
			t.Fatalf("%s: %v", entry, err)
		}
		return ix.validateNode()
	}
	if err := load(ok); err != nil {
		t.Errorf("valid entry rejected: %v", err)
	}
	for name, entry := range cases {
		if load(entry) == nil {
			t.Errorf("%s: accepted %s", name, entry)
		}
	}
}

func TestNodeCalleeKeys(t *testing.T) {
	for _, c := range []struct {
		callee NodeCallee
		want   []string
	}{
		{
			NodeCallee{Bind: BindImport, Modules: []string{"acme-crypto", "node:acme-crypto"}, Path: "x.(Y).<init>", New: true},
			[]string{"acme-crypto.x.(Y).<init>", "node:acme-crypto.x.(Y).<init>"},
		},
		{NodeCallee{Bind: BindGlobal, Path: "(SubtleCrypto).digest"}, []string{"(SubtleCrypto).digest"}},
		{NodeCallee{Bind: BindImport, Modules: []string{"m"}, PathRegex: "^a$"}, nil},
		{NodeCallee{Bind: BindWritten, Path: "acmeHash"}, nil},
	} {
		if got := c.callee.keys(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%+v: keys %v, want %v", c.callee, got, c.want)
		}
	}
}

func TestEnumRegex(t *testing.T) {
	for _, c := range []struct {
		rx   string
		want []string
	}{
		{`^["']?(?:node:)?acme["']?$`, []string{`"acme"`, `"acme'`, `"node:acme"`, `"node:acme'`, `acme`, `acme"`, `acme'`, `node:acme`, `node:acme"`, `node:acme'`, `'acme`, `'acme"`, `'acme'`, `'node:acme`, `'node:acme"`, `'node:acme'`, `"acme`, `"node:acme`}},
		{`^(encrypt|decrypt)$`, []string{"decrypt", "encrypt"}},
		{`^(?:sha-?(1|256))$`, []string{"sha-1", "sha-256", "sha1", "sha256"}},
		{`^x\w$`, nil},      // a class longer than the class limit
		{`^acme`, nil},      // a prefix: anything may follow
		{`^.*crypto$`, nil}, // a star
		{`(?i)^md5$`, nil},  // case folding
		{`^(a|b)(c|d)?$`, []string{"a", "ac", "ad", "b", "bc", "bd"}},
		{`^ab{1,2}$`, []string{"ab", "abb"}},
		{`^ab+$`, nil},
		{`(`, nil},
	} {
		got, ok := enumRegex(c.rx, enumMax)
		if c.want == nil {
			if ok {
				t.Errorf("%s: enumerated %v, want not finite", c.rx, got)
			}
			continue
		}
		want := append([]string{}, c.want...)
		sort.Strings(want)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v %v, want %v", c.rx, got, ok, want)
		}
	}
	if _, ok := enumRegex(`^(a|b|c|d)(a|b|c|d)(a|b|c|d)$`, 10); ok {
		t.Error("past the string limit, a regex is not finite")
	}
}

func TestNodeRule(t *testing.T) {
	for langs, want := range map[string]bool{"[javascript]": true, "[typescript]": true, "[javascript, typescript]": true, "[java]": false, "[python]": false} {
		r := omap("languages", jsAnyList(strings.Split(strings.Trim(langs, "[]"), ", ")))
		if got := nodeRule(r); got != want {
			t.Errorf("%s: nodeRule %v, want %v", langs, got, want)
		}
	}
}

// A pattern-not written as a formula: a set of calls less its own
// pattern-nots becomes a not_calls entry with those as its exceptions; a
// pattern-either of patterns is one not_calls entry each. A shape that is
// not a set of calls less a set of calls is still dropped.
func TestCompileNodeNestedNot(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: nested
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern: $NS.generate(...)
  - pattern-not: $CALL()
  - pattern-not:
      patterns:
      - pattern: $CALL($ATTRS, {...}, ...)
      - pattern-not: '$CALL($ATTRS, {..., algorithm: $ALG, ...}, ...)'
      - pattern-not: '$CALL($ATTRS, {..., keyPair: $KP, ...}, ...)'
  - pattern-not:
      pattern-either:
      - pattern: $CALL($A, "weak")
      - pattern: $NS.generate($A, "weaker")
- id: regex
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern: $NS.generate(...)
  - pattern-not:
      patterns:
      - pattern: '$CALL({..., size: $BITS, ...})'
      - metavariable-regex:
          metavariable: $BITS
          regex: ^\d+$
- id: regex-unbound
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern: $NS.generate(...)
  - pattern-not:
      patterns:
      - pattern: $CALL($X)
      - metavariable-regex:
          metavariable: $OTHER
          regex: ^a$
- id: unbounded
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern: $NS.generate(...)
  - pattern-not:
      patterns:
      - pattern: $CALL($ATTRS, {...})
      - pattern-not-inside: |
          function f() { ... }
`)
	want := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "generate", "member": true}, "method": "generate", "min_arity": 0, "max_arity": null, "constraints": [], ` +
		`"not_calls": [{"min_arity": 0, "max_arity": 0, "arg_pattern": ""}, ` +
		`{"min_arity": 2, "max_arity": null, "arg_pattern": "$ATTRS, {...}, ...", "not_calls": [` +
		`{"min_arity": 2, "max_arity": null, "arg_pattern": "$ATTRS, {..., algorithm:$ALG, ...}, ..."}, ` +
		`{"min_arity": 2, "max_arity": null, "arg_pattern": "$ATTRS, {..., keyPair:$KP, ...}, ..."}]}, ` +
		`{"min_arity": 2, "max_arity": 2, "arg_pattern": "$A, \"weak\""}, ` +
		`{"min_arity": 2, "max_arity": 2, "arg_pattern": "$A, \"weaker\""}], "taint": false}`
	if got := sites["nested"]; !reflect.DeepEqual(got, []string{want}) {
		t.Errorf("nested:\n got  %v\n want %v", got, want)
	}
	wantRegex := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "generate", "member": true}, "method": "generate", "min_arity": 0, "max_arity": null, "constraints": [], ` +
		`"not_calls": [{"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., size:$BITS, ...}", "constraints": [{"metavar": "$BITS", "regex": "^\\d+$"}]}], "taint": false}`
	if got := sites["regex"]; !reflect.DeepEqual(got, []string{wantRegex}) {
		t.Errorf("regex:\n got  %v\n want %v", got, wantRegex)
	}
	if !strings.Contains(records["regex-unbound"], "pattern-not: nested formula") {
		t.Errorf("regex-unbound: a regex on a metavariable the negated call does not bind cannot be read; record %s", records["regex-unbound"])
	}
	if !strings.Contains(records["unbounded"], "pattern-not: nested formula") {
		t.Errorf("unbounded: a pattern-not-inside under a pattern-not is not a set of calls; record %s", records["unbounded"])
	}
}

// A destructuring binder with a metavariable name binds whichever export the
// call names: the call must be written with that local name (local_first),
// or a namespace import of the module would match it too.
func TestCompileNodeLocalFirst(t *testing.T) {
	sites, _ := compileNode(t, `rules:
- id: first
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      var {..., $NS, ...} = require("acme-crypto")
      ...
  - pattern: $NS.create(...)
`)
	want := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path_regex": "^(?P\u003cNS\u003e[^.()]+)\\.create$", "local_first": true}, "method": "create", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "taint": false}`
	if got := sites["first"]; !reflect.DeepEqual(got, []string{want}) {
		t.Errorf("first:\n got  %v\n want %v", got, want)
	}
}

// A context that passes the matched call on to a call named by a
// metavariable-regex, with focus on the matched call, compiles to consumers:
// inline for `$SEALER(.., $RND, ..)`, var for `$MAT = $RND ... $SEALER(.., $MAT, ..)`.
func TestCompileNodeConsumers(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: iv
  languages: [javascript, typescript]
  patterns:
  - patterns:
    - pattern-inside: |
        $C = require("acme-crypto")
        ...
    - pattern: $C.random(...)
  - pattern-either:
    - patterns:
      - pattern-inside: |
          $MAT = $RND
          ...
          $SEALER($ALGO, $KEY, $MAT, ...)
      - metavariable-regex:
          metavariable: $SEALER
          regex: ^(?:\w+\.)?seal$
    - patterns:
      - pattern-inside: $SEALER($ALGO, $KEY, $RND, ...)
      - metavariable-regex:
          metavariable: $SEALER
          regex: ^(?:\w+\.)?seal$
  - focus-metavariable: $RND
`)
	base := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "random", "member": true}, "method": "random", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], `
	want := []string{
		base + `"consumers": [{"via": "var", "callee_regex": "^(?:\\w+\\.)?seal$", "arg_pattern": "$ALGO, $KEY, $MAT, ...", "use": "$MAT"}], "taint": false}`,
		base + `"consumers": [{"via": "inline", "callee_regex": "^(?:\\w+\\.)?seal$", "arg_pattern": "$ALGO, $KEY, $RND, ...", "use": "$RND"}], "taint": false}`,
	}
	if got := sites["iv"]; !reflect.DeepEqual(got, want) {
		t.Errorf("iv:\n got  %v\n want %v", got, want)
	}
	if strings.Contains(records["iv"], "focus") || strings.Contains(records["iv"], "enclosing call") {
		t.Errorf("iv: the consumer contexts and their focus are read, not dropped; record %s", records["iv"])
	}
}

// pattern-not-regex compiles to the entry's not_regexes.
func TestCompileNodeNotRegex(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: kdf
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      $C = require("acme-crypto")
      ...
  - pattern: $C.derive(...)
  - pattern-not-regex: \bc\s*:\s*\d
`)
	want := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "derive", "member": true}, "method": "derive", "min_arity": 0, "max_arity": null, "constraints": [], "not_calls": [], "not_regexes": ["\\bc\\s*:\\s*\\d"], "taint": false}`
	if got := sites["kdf"]; !reflect.DeepEqual(got, []string{want}) {
		t.Errorf("kdf:\n got  %v\n want %v", got, want)
	}
	if strings.Contains(records["kdf"], "pattern-not-regex") {
		t.Errorf("kdf: pattern-not-regex is read, not dropped; record %s", records["kdf"])
	}
}

// A pattern-not whose callee is a name no guard binds is written text: when
// the name is one the callee may be written with (its local regex), it is a
// negation of that callee, not a vacuous one.
func TestCompileNodeNotWrittenName(t *testing.T) {
	sites, _ := compileNode(t, `rules:
- id: unnamed
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      $LIB = require("acme-crypto")
      ...
  - pattern: new $LIB($C)
  - metavariable-regex:
      metavariable: $LIB
      regex: ^(Acme|acme)$
  - pattern-not: new Acme("...")
  - pattern-not: new Other("...")
`)
	want := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "(default).\u003cinit\u003e", "new": true, "local_regex": "^(Acme|acme)$"}, "method": "\u003cinit\u003e", "min_arity": 1, "max_arity": 1, "arg_pattern": "$C", "constraints": [], ` +
		`"not_calls": [{"min_arity": 1, "max_arity": 1, "arg_pattern": "\"...\""}], "taint": false}`
	if got := sites["unnamed"]; !reflect.DeepEqual(got, []string{want}) {
		t.Errorf("unnamed:\n got  %v\n want %v", got, want)
	}
}

// A context binding an argument metavariable to a call's result, assigned
// or destructured, compiles to a producer of the call; a bare metavariable
// callee with a metavariable-regex compiles to a text callee.
func TestCompileNodeProducers(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: gen
  languages: [javascript, typescript]
  patterns:
  - pattern-either:
    - pattern-inside: |-
        var {..., $K, ...} = $GEN($TYPE, ...)
        ...
    - pattern-inside: |-
        $K = $GEN($TYPE, ...)
        ...
  - metavariable-regex:
      metavariable: $GEN
      regex: ^(?:\w+\.)?makePair$
  - metavariable-regex:
      metavariable: $TYPE
      regex: ^["'](?:x1)["']$
  - pattern-inside: |-
      $C = require("acme-crypto")
      ...
  - pattern: '$C.agree({..., privateKey: <... $K ...>, ...})'
- id: consumer
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |-
      $K = $GEN($TYPE, ...)
      ...
  - metavariable-regex:
      metavariable: $GEN
      regex: ^(?:\w+\.)?makePair$
  - pattern-inside: |-
      $C = require("acme-crypto")
      ...
  - pattern: $C.createSigner(...)
  - pattern-inside: $SIGNED.sign(<... $K ...>, ...)
- id: no-regex
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |-
      $K = $GEN($TYPE, ...)
      ...
  - pattern-inside: |-
      $C = require("acme-crypto")
      ...
  - pattern: $C.agree(<... $K ...>)
`)
	gen := `{"callee": {"bind": "text", "path_regex": "^(?P\u003cGEN\u003e.+)$"}, "method": null, "min_arity": 1, "max_arity": null, "arg_pattern": "$TYPE, ...", "constraints": [{"metavar": "$GEN", "regex": "^(?:\\w+\\.)?makePair$"}, {"metavar": "$TYPE", "regex": "^[\"'](?:x1)[\"']$"}]}`
	sink := `{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "agree", "member": true}, "method": "agree", "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., privateKey:\u003c...$K...\u003e, ...}", "constraints": [], "not_calls": [], `
	want := []string{
		sink + `"producers": [{"use": "$K", "via": "destructure", "from": [` + gen + `]}], "taint": false}`,
		sink + `"producers": [{"use": "$K", "via": "var", "from": [` + gen + `]}], "taint": false}`,
	}
	if got := sites["gen"]; !reflect.DeepEqual(got, want) {
		t.Errorf("gen:\n got  %v\n want %v", got, want)
	}
	if got := strings.Join(sites["consumer"], "\n"); !strings.Contains(got, `"consumers": [{"via": "receiver", "method_regex": "^sign$", "arg_pattern": "\u003c...$K...\u003e, ...", "producers": [{"use": "$K", "via": "var", "from": [{"callee": {"bind": "text"`) {
		t.Errorf("consumer: the consumer's argument reads the producer: %s (%s)", got, records["consumer"])
	}
	if !strings.Contains(records["no-regex"], "unbound metavariable callee $GEN") {
		t.Errorf("no-regex: a bare metavariable callee with no regex matches any call: %s", records["no-regex"])
	}
}

// A pattern-not written as a sub-rule (its own guards, producers) compiles
// to not_entries; one with a clause the compiler would drop is dropped whole.
func TestCompileNodeNotRule(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: not-rule
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |-
      $C = require("acme-crypto")
      ...
  - pattern: $C.sign($D, <... $K ...>)
  - pattern-not:
      patterns:
      - pattern-inside: |-
          $K = $GEN("x1", ...)
          ...
      - metavariable-regex:
          metavariable: $GEN
          regex: ^(?:\w+\.)?makePair$
      - pattern-inside: |-
          $C = require("acme-crypto")
          ...
      - pattern: $C.sign($D, <... $K ...>)
- id: lossy
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |-
      $C = require("acme-crypto")
      ...
  - pattern: $C.sign($D, $K)
  - pattern-not:
      patterns:
      - pattern-inside: |-
          $C = require("acme-crypto")
          ...
      - pattern: $C.sign($D, $K)
      - pattern-not-inside: f(...)
`)
	got := strings.Join(sites["not-rule"], "\n")
	if !strings.Contains(got, `"not_entries": [{"callee": {"bind": "import", "modules": ["acme-crypto"], "path": "sign", "member": true}`) || !strings.Contains(got, `"producers": [{"use": "$K", "via": "var"`) {
		t.Errorf("not-rule: the negated sub-rule is an entry with its producer: %s (%s)", got, records["not-rule"])
	}
	if strings.Contains(records["not-rule"], "nested formula") {
		t.Errorf("not-rule: nothing dropped: %s", records["not-rule"])
	}
	if strings.Contains(strings.Join(sites["lossy"], "\n"), "not_entries") || !strings.Contains(records["lossy"], "pattern-not: nested formula") {
		t.Errorf("lossy: a sub-rule with a dropped clause is dropped: %v %s", sites["lossy"], records["lossy"])
	}
}

// An object literal with no call around it: a literal entry under the
// guard's module; its object pattern-nots negate the object, a context call
// still encloses it (no consumer), an assignment target is recorded as
// dropped.
func TestCompileNodeLiteral(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: lit
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      import $NS from "acme-crypto"
      ...
  - pattern: '{..., alg: "x1", ...}'
  - pattern-not: '{..., kty: $K, ...}'
  - pattern-not: $NS.f(...)
- id: inside-call
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      import $NS from "acme-crypto"
      ...
  - pattern-inside: $H.header(...)
  - pattern: '{..., alg: "x1", ...}'
- id: assigned
  languages: [javascript, typescript]
  patterns:
  - pattern-inside: |
      import $NS from "acme-crypto"
      ...
  - pattern: '$O = {..., alg: "x1", ...}'
`)
	want := `{"callee": {"bind": "literal", "modules": ["acme-crypto"]}, "method": null, "min_arity": 1, "max_arity": 1, "arg_pattern": "{..., alg:\"x1\", ...}", "constraints": [], "not_calls": [{"min_arity": 1, "max_arity": 1, "arg_pattern": "{..., kty:$K, ...}"}], "taint": false}`
	if got := sites["lit"]; len(got) != 1 || got[0] != want {
		t.Errorf("lit:\n got  %v\n want %v", got, want)
	}
	if got := strings.Join(sites["inside-call"], "\n"); strings.Contains(got, "consumers") || !strings.Contains(got, `"bind": "literal"`) || !strings.Contains(got, `"within": [{"callee": {"bind": "text"`) {
		t.Errorf("inside-call: a literal within its context call: %s (%s)", got, records["inside-call"])
	}
	if got := strings.Join(sites["assigned"], ""); !strings.Contains(got, `"bind": "literal", "modules": ["acme-crypto"], "assigned": true}`) {
		t.Errorf("assigned: an assigned object literal: %s (%s)", got, records["assigned"])
	}
}

// A method on a property of a produced value compiles to an object callee
// with props; a callee headed by an unbound metavariable to a text callee; a
// pattern-not whose pattern-not is itself a nested formula to not_calls with
// exceptions of exceptions.
func TestCompileNodeChainsAndNestedNots(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: props
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $F = require("acme-crypto")
      ...
  - pattern-inside: |
      $KEY = $F.gen(...)
      ...
  - pattern: $KEY.priv.sign($MD)
- id: text
  languages: [javascript]
  patterns:
  - pattern: $R.$H.digest($D)
  - metavariable-regex:
      metavariable: $H
      regex: ^sha256$
- id: bare
  languages: [javascript]
  patterns:
  - pattern: $F($D)
- id: nested
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $F = require("acme-crypto")
      ...
  - pattern: $F.seal($K, $O)
  - pattern-not:
      patterns:
      - pattern: $CALL($K, {...})
      - pattern-not:
          patterns:
          - pattern: '$CALL($K, {..., kdf: $X, ...})'
          - pattern-not: '$CALL($K, {..., kdf: "x1", ...})'
`)
	if got := strings.Join(sites["props"], ""); !strings.Contains(got, `"bind": "object", "path": "sign", "props": "priv"`) {
		t.Errorf("props: %s (%s)", got, records["props"])
	}
	if got := strings.Join(sites["text"], ""); !strings.Contains(got, `"bind": "text", "path_regex": "^(?P\u003cR\u003e.+)\\.sha256\\.digest$"}, "method": "digest"`) {
		t.Errorf("text: %s (%s)", got, records["text"])
	}
	if !strings.Contains(records["bare"], "unbound metavariable callee $F") {
		t.Errorf("bare: a bare metavariable callee with no regex is skipped: %s", records["bare"])
	}
	got := strings.Join(sites["nested"], "")
	if strings.Contains(records["nested"], "nested formula") || !strings.Contains(got, `"not_calls": [{"min_arity": 2, "max_arity": 2, "arg_pattern": "$K, {...}", "not_calls": [{"min_arity": 2, "max_arity": 2, "arg_pattern": "$K, {..., kdf:$X, ...}", "not_calls": [{`) {
		t.Errorf("nested: %s (%s)", got, records["nested"])
	}
}

// A property read compiles to a read entry; a pattern-not-inside `$V =
// <read>; ...` on an argument to not_producers; a guard that reassigns a
// metavariable is left out; a named binder needs its local name and an
// inline require its require.
func TestCompileNodeReadsAndWrittenForms(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: enc
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-iron")
      ...
  - pattern: $NS.encrypt($PW, $OPTS)
  - pattern-not-inside: |
      $OPTS = $NS.defaults.encryption;
      ...
- id: reassigned
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-iron")
      ...
  - pattern-inside: |
      $O = $NS.defaults;
      $O = $OTHER;
      ...
  - pattern: $NS.encrypt($PW, $O)
- id: named
  languages: [javascript]
  patterns:
  - pattern-inside: |
      const { encrypt } = require("acme-iron")
      ...
  - pattern: encrypt($PW, $O)
- id: inline
  languages: [javascript]
  pattern: require("acme-iron").decrypt($PW, $O)
`)
	if got := strings.Join(sites["enc"], ""); !strings.Contains(got, `"not_producers": [{"use": "$OPTS", "via": "var", "from": [{"callee": {"bind": "import", "modules": ["acme-iron"], "path": "defaults.encryption", "member": true}, "method": "encryption", "min_arity": 0, "max_arity": null, "read": true}]}]`) {
		t.Errorf("enc: %s (%s)", got, records["enc"])
	}
	if !strings.Contains(records["reassigned"], "guard: metavariable reassigned") {
		t.Errorf("reassigned: %s", records["reassigned"])
	}
	if got := strings.Join(sites["named"], ""); !strings.Contains(got, `"local_regex": "^encrypt$"`) {
		t.Errorf("named: %s", got)
	}
	if got := strings.Join(sites["inline"], ""); !strings.Contains(got, `"inline": true`) {
		t.Errorf("inline: %s", got)
	}
}

// A guard that assigns a metavariable a module member's read, used as an
// argument, is a producer over the property reads.
func TestCompileNodeReadGuardProducer(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: cbc
  languages: [javascript]
  patterns:
  - pattern-inside: |
      $NS = require("acme-iron")
      ...
  - pattern-inside: |
      $O = $NS.defaults.encryption;
      ...
  - pattern: $NS.encrypt($PW, $O)
`)
	if got := strings.Join(sites["cbc"], ""); !strings.Contains(got, `"producers": [{"use": "$O", "via": "var", "from": [{"callee": {"bind": "import", "modules": ["acme-iron"], "path": "defaults.encryption", "member": true}, "method": "encryption", "min_arity": 0, "max_arity": null, "read": true}]}]`) {
		t.Errorf("cbc: %s (%s)", got, records["cbc"])
	}
}

// A guard assigning an object literal to a metavariable used as an argument
// is a producer over assigned object literals.
func TestCompileNodeObjectGuardProducer(t *testing.T) {
	sites, records := compileNode(t, `rules:
- id: gen
  languages: [javascript]
  patterns:
  - pattern-inside: |-
      $V = { ..., name: $ALG, ... };
  - pattern: crypto.subtle.generateKey($V, ...)
`)
	if got := strings.Join(sites["gen"], ""); !strings.Contains(got, `"producers": [{"use": "$V", "via": "var", "from": [{"callee": {"bind": "literal", "assigned": true}`) {
		t.Errorf("gen: %s (%s)", got, records["gen"])
	}
}
