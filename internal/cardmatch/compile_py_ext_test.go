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

// pyRulesMatch compiles the Python rules src (extensions on) and matches
// them, with no card, against frag.
func pyRulesMatch(t *testing.T, src string, frag *FragmentJSON) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	assets, err := Load("", "", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	found, _ := assets.mustMatch(t, frag)
	return ruleLines(found)
}

// compileRecords compiles src with the extensions and returns the rule
// records by id.
func compileRecords(t *testing.T, src string) map[string]string {
	t.Helper()
	_, rules := compileYAML(t, src)
	out := map[string]string{}
	for _, r := range rules {
		id := r[strings.Index(r, `"rule_id": "`)+12:]
		out[id[:strings.IndexByte(id, '"')]] = r
	}
	return out
}

func withRecv(e ExternalJSON, v string) ExternalJSON { e.ReceiverVar = v; return e }

// A nested call argument with a metavariable: the call written as the
// argument must match it, and the metavariable's regex groups and binding
// fill the metadata.
func TestCompiledNestedCallArgument(t *testing.T) {
	src := `rules:
- id: digest
  languages: [python]
  patterns:
  - pattern-either:
    - pattern: cryptography.hazmat.primitives.hashes.Hash(cryptography.hazmat.primitives.hashes.$H(...), ...)
    - pattern: cryptography.hazmat.primitives.hashes.Hash(algorithm=cryptography.hazmat.primitives.hashes.$H(...), ...)
  - metavariable-regex: {metavariable: $H, regex: '^(?:MD5|SHA1)$'}
  metadata: {crypto: {algorithmName: $H}}
- id: pss
  languages: [python]
  patterns:
  - pattern: $K.sign($D, cryptography.hazmat.primitives.asymmetric.padding.PSS(salt_length=$S))
  - metavariable-regex: {metavariable: $S, regex: '^32$'}
`
	imports := []graphfrag.GraphFragmentImport{{Line: 1, Module: "cryptography.hazmat.primitives", Name: "hashes"}}
	hash := "cryptography.hazmat.primitives.hashes.Hash"
	frag := pyFrag(imports,
		pyCall(hash, "hashes.Hash", 5, pos(0, "hashes.MD5()")),
		pyCall("cryptography.hazmat.primitives.hashes.MD5", "hashes.MD5", 5),
		pyCall(hash, "hashes.Hash", 6, kw(0, "algorithm", "hashes.SHA1()")),
		pyCall("cryptography.hazmat.primitives.hashes.SHA1", "hashes.SHA1", 6),
		pyCall(hash, "hashes.Hash", 7, pos(0, "hashes.SHA256()")),
		pyCall("cryptography.hazmat.primitives.hashes.SHA256", "hashes.SHA256", 7),
		pyCall(hash, "hashes.Hash", 8, pos(0, "alg")),
		nameOnly(pyCall("app.main.(k).sign", "k.sign", 9, pos(0, "d"), pos(1, "padding.PSS(salt_length=32)")), "k"),
		pyCall("cryptography.hazmat.primitives.asymmetric.padding.PSS", "padding.PSS", 9, kw(0, "salt_length", "32")),
		nameOnly(pyCall("app.main.(k).sign", "k.sign", 10, pos(0, "d"), pos(1, "padding.PSS(salt_length=20)")), "k"),
		pyCall("cryptography.hazmat.primitives.asymmetric.padding.PSS", "padding.PSS", 10, kw(0, "salt_length", "20")),
	)
	frag.Imports["app/main.py"] = append(imports, graphfrag.GraphFragmentImport{Line: 2, Module: "cryptography.hazmat.primitives.asymmetric", Name: "padding"})
	got := pyRulesMatch(t, src, frag)
	want := []string{`digest@5 {"algorithmName": "MD5"}`, `digest@6 {"algorithmName": "SHA1"}`, `pss@9 {}`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// A constant reference rule restricted to table positions: reported in a
// dict or list, not passed to a call, compared or inside isinstance(...).
func TestCompiledConstantTable(t *testing.T) {
	src := `rules:
- id: md5-class
  languages: [python]
  patterns:
  - pattern-either:
    - pattern: cryptography.hazmat.primitives.hashes.$H(...)
    - patterns:
      - pattern: cryptography.hazmat.primitives.hashes.$H
      - pattern-not-inside: cryptography.hazmat.primitives.hashes.$H(...)
      - pattern-either:
        - pattern-inside: "{..., $TK: $TV, ...}"
        - pattern-inside: "(..., $ENTRY, ...)"
        - pattern-inside: "[..., $ENTRY, ...]"
  - pattern-not-inside: isinstance(...)
  - pattern-not-inside: frozen(1)
  - pattern-not-inside: $L == $R
  - pattern-not-inside: $T[...]
  - metavariable-regex: {metavariable: $H, regex: '^(?:MD5)$'}
  metadata: {crypto: {algorithmName: $H}}
- id: tls-any
  languages: [python]
  patterns:
  - pattern: ssl.PROTOCOL_TLSv1
  - pattern-not-inside: $L in $R
`
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "cryptography.hazmat.primitives", Name: "hashes"}, {Line: 2, Module: "ssl"}},
		withSpan(pyCall("isinstance", "isinstance", 9, pos(0, "x"), pos(1, "hashes.MD5")), 5, 30),
		pyCall("cryptography.hazmat.primitives.hashes.MD5", "hashes.MD5", 10),
	)
	frag.SchemaVersion = "graph-fragment-1.24"
	frag.ConstantRefs = []graphfrag.GraphFragmentConstantRef{
		pyRef(5, 13, "hashes.MD5", "dict", valueOperand(`'md5'`, `'md5'`)),
		pyRef(6, 9, "hashes.MD5", "array", nil),
		pyRef(7, 9, "hashes.MD5", "arg", nil),
		pyRef(8, 9, "hashes.MD5", "compare", valueOperand("alg", "hashes.MD5")),
		pyRef(9, 20, "hashes.MD5", "array", nil),
		pyRef(11, 9, "hashes.SHA1", "dict", nil),
		pyRef(12, 9, "ssl.PROTOCOL_TLSv1", "assign", nil),
		pyRef(13, 9, "ssl.PROTOCOL_TLSv1", "in", valueOperand("p", "ssl.PROTOCOL_TLSv1")),
		pyRef(14, 9, "ssl.PROTOCOL_TLSv1", "compare", valueOperand("p", "x")),
		pyRef(15, 9, "ssl.PROTOCOL_TLSv1_2", "assign", nil),
		pyRef(16, 9, "other.MD5", "dict", nil),
		pyRef(17, 23, "hashes.MD5", "array", nil),
		pyRef(18, 25, "hashes.MD5", "array", nil),
		pyRef(19, 28, "hashes.MD5", "array", nil),
		pyRef(20, 13, "hashes.MD5", "array", nil),
	}
	// isinstance is a builtin: the fragment has no call for it, the source
	// line tells.
	frag.SourceLines = map[string]map[int]string{"app/main.py": {
		17: "    if isinstance(a, (hashes.MD5, x)):",
		18: "    if myisinstance(a, (hashes.MD5, x)):",
		19: "    if isinstance(a, b) or [hashes.MD5]:",
		20: "    frozen([hashes.MD5])",
	}}
	frag.ExternalCalls = append(frag.ExternalCalls, withSpan(pyCall("app.main.frozen", "frozen", 20, pos(0, "[hashes.MD5]")), 5, 25))
	got := pyRulesMatch(t, src, frag)
	want := []string{
		`md5-class@10 {"algorithmName": "MD5"}`,
		`md5-class@18 {"algorithmName": "MD5"}`,
		`md5-class@19 {"algorithmName": "MD5"}`,
		`md5-class@20 {"algorithmName": "MD5"}`,
		`md5-class@5 {"algorithmName": "MD5"}`,
		`md5-class@6 {"algorithmName": "MD5"}`,
		`tls-any@12 {}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// Origins: a receiver from a factory call (`$K = F(...)`), the local's
// latest assignment deciding, a `with ... as`, and an annotated parameter
// (the fragment's resolved receiver class).
func TestCompiledOrigins(t *testing.T) {
	src := `rules:
- id: sign
  languages: [python]
  patterns:
  - pattern: $KEY.sign($DATA, ...)
  - pattern-either:
    - pattern-inside: |
        $KEY = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
        ...
    - pattern-inside: |
        with acme.Signer(...) as $KEY:
          ...
    - pattern-inside: |
        def $F(..., $KEY: cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey, ...):
          ...
    - pattern-inside: |
        $KEY = Builder(...)
        ...
    - pattern-inside: |
        $KEY = boto3.client('kms', region=boto3.KMS_REGION)
        ...
`
	gen := "cryptography.hazmat.primitives.asymmetric.ed25519.(Ed25519PrivateKey).generate"
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "cryptography.hazmat.primitives.asymmetric", Name: "ed25519"}, {Line: 2, Module: "acme"}},
		withAssigned(pyCall(gen, "ed25519.Ed25519PrivateKey.generate", 5), "k"),
		nameOnly(pyCall("app.main.(k).sign", "k.sign", 6, pos(0, "d")), "k"),
		withAssigned(pyCall("app.other.make", "other.make", 7), "k"),
		nameOnly(pyCall("app.main.(k).sign", "k.sign", 8, pos(0, "d")), "k"),
		withAssigned(pyCall("acme.Signer", "acme.Signer", 9), "s"),
		nameOnly(pyCall("app.main.(s).sign", "s.sign", 10, pos(0, "d")), "s"),
		withRecv(pyCall("cryptography.hazmat.primitives.asymmetric.ed25519.(Ed25519PrivateKey).sign", "p.sign", 11, pos(0, "d")), "p"),
		nameOnly(pyCall("app.main.(q).sign", "q.sign", 12, pos(0, "d")), "q"),
		withAssigned(pyCall("app.builders.Builder", "Builder", 13), "b"),
		nameOnly(pyCall("app.main.(b).sign", "b.sign", 14, pos(0, "d")), "b"),
		withAssigned(pyCall("boto3.client", "boto3.client", 15, pos(0, `"kms"`), kw(1, "region", "KMS_REGION")), "c"),
		nameOnly(pyCall("app.main.(c).sign", "c.sign", 16, pos(0, "d")), "c"),
		withAssigned(pyCall("boto3.client", "boto3.client", 17, pos(0, `"s3"`), kw(1, "region", "KMS_REGION")), "c"),
		nameOnly(pyCall("app.main.(c).sign", "c.sign", 18, pos(0, "d")), "c"),
		withAssigned(pyCall("boto3.client", "boto3.client", 19, pos(0, `"kms"`), kw(1, "region", "OTHER")), "c"),
		nameOnly(pyCall("app.main.(c).sign", "c.sign", 20, pos(0, "d")), "c"),
	)
	frag.Imports["app/main.py"] = append(frag.Imports["app/main.py"], graphfrag.GraphFragmentImport{Line: 3, Module: "boto3", Name: "KMS_REGION"},
		graphfrag.GraphFragmentImport{Line: 4, Module: "app.builders", Name: "Builder"})
	got := pyRulesMatch(t, src, frag)
	if want := []string{`sign@10 {}`, `sign@11 {}`, `sign@14 {}`, `sign@16 {}`, `sign@6 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// Object flow: a taint rule whose sources are factory calls is matched as a
// call on an object from one of them; a source that says how the factory is
// called is no class typing.
func TestCompiledObjectFlow(t *testing.T) {
	src := `rules:
- id: encrypt
  languages: [python]
  mode: taint
  pattern-sources:
  - pattern-either:
    - pattern: gpg.Context(..., protocol=gpg.constants.protocol.CMS)
    - pattern: gpg.core.Context(..., protocol=gpg.constants.protocol.CMS)
  pattern-sinks:
  - patterns:
    - pattern: $CX.encrypt(...)
    - focus-metavariable: $CX
- id: keylist
  languages: [python]
  mode: taint
  pattern-sources:
  - pattern-either:
    - pattern: gpg.Context(...)
    - patterns:
      - pattern-inside: |
          def $F(..., $C: gpg.core.Context, ...):
            ...
      - pattern: $C
      - focus-metavariable: $C
    - pattern: weird[0]
  pattern-sinks:
  - pattern: $C.keylist(...)
`
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "gpg"}},
		withAssigned(pyCall("gpg.Context", "gpg.Context", 5, kw(0, "protocol", "gpg.constants.protocol.CMS")), "c"),
		nameOnly(pyCall("app.main.(c).encrypt", "c.encrypt", 6, pos(0, "m")), "c"),
		withAssigned(pyCall("gpg.Context", "gpg.Context", 7), "o"),
		withRecv(pyCall("gpg.(Context).encrypt", "o.encrypt", 8, pos(0, "m")), "o"),
		withRecv(pyCall("gpg.(Context).keylist", "o.keylist", 9), "o"),
		withRecv(pyCall("gpg.core.(Context).keylist", "p.keylist", 10), "p"),
		nameOnly(pyCall("app.main.(z).keylist", "z.keylist", 11), "z"),
	)
	got := pyRulesMatch(t, src, frag)
	if want := []string{`encrypt@6 {}`, `keylist@10 {}`, `keylist@9 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	recs := compileRecords(t, src)
	if !strings.Contains(recs["keylist"], `"dropped_clauses": ["taint source alternative not compiled"]`) {
		t.Errorf("keylist record %s", recs["keylist"])
	}
}

// Import pattern-insides give the callee its module: `from jose import jwt`
// + `jwt.encode(...)` is jose's, `import rsa as $A` + `$A.newkeys(...)` and
// `from rsa import $N` + `$N(...)` are rsa's.
func TestCompiledImportInsides(t *testing.T) {
	src := `rules:
- id: jose
  languages: [python]
  patterns:
  - pattern-inside: |
      from jose import jwt
      ...
  - pattern: jwt.encode(...)
- id: rsa
  languages: [python]
  patterns:
  - pattern-either:
    - pattern-inside: |
        import rsa as $R
        ...
    - pattern-inside: |
        from rsa import $N
        ...
  - pattern-either:
    - pattern: $R.newkeys(...)
    - patterns:
      - pattern: $N(...)
      - metavariable-regex: {metavariable: $N, regex: '^newkeys$'}
`
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "jose", Name: "jwt"}, {Line: 2, Module: "rsa", Name: "newkeys"}, {Line: 3, Module: "otherrsa", Alias: "o"}},
		pyCall("jose.jwt.encode", "jwt.encode", 5, pos(0, "c")),
		pyCall("jwt.encode", "pyjwt.encode", 6, pos(0, "c")),
		pyCall("rsa.newkeys", "newkeys", 7, pos(0, "512")),
		pyCall("otherrsa.newkeys", "o.newkeys", 8, pos(0, "512")),
	)
	if got, want := pyRulesMatch(t, src, frag), []string{`jose@5 {}`, `rsa@7 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// Other argument shapes: "=~/re/" string regexes, `a.$C.m(...)` callees, a
// metavariable-pattern of dotted names (qualified through the imports), a
// pattern-not-inside call.
func TestCompiledArgumentShapes(t *testing.T) {
	src := `rules:
- id: scheme
  languages: [python]
  patterns:
  - pattern: $H.contextGen(scheme="=~/^(?i)(bfv|int)$/", ...)
- id: load
  languages: [python]
  patterns:
  - pattern: paramiko.$K.from_private_key(...)
  - metavariable-regex: {metavariable: $K, regex: '^(?:RSAKey|ECDSAKey)$'}
  metadata: {crypto: {algorithmName: $K}}
- id: create
  languages: [python]
  patterns:
  - pattern: $C.create($AL, ...)
  - metavariable-pattern:
      metavariable: $AL
      patterns:
      - pattern-either:
        - pattern: vaultkit.core.enums.Algorithm.AES
        - pattern: vaultkit.enums.Algorithm.AES
- id: urandom
  languages: [python]
  patterns:
  - pattern: os.urandom(...)
  - pattern-not-inside: hashlib.pbkdf2_hmac(...)
  - pattern-not-inside: hashlib.scrypt(..., salt=$S, ...)
- id: self
  languages: [python]
  patterns:
  - pattern: os.getrandom(...)
  - pattern-not-inside: os.$F(...)
`
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "paramiko"}, {Line: 2, Module: "vaultkit.core", Name: "enums"}, {Line: 3, Module: "os"}, {Line: 4, Module: "hashlib"}},
		nameOnly(pyCall("app.main.(he).contextGen", "he.contextGen", 5, kw(0, "scheme", `"BFV"`)), "he"),
		nameOnly(pyCall("app.main.(he).contextGen", "he.contextGen", 6, kw(0, "scheme", `"ckks"`)), "he"),
		pyCall("paramiko.(RSAKey).from_private_key", "paramiko.RSAKey.from_private_key", 7, pos(0, "f")),
		pyCall("paramiko.(DSSKey).from_private_key", "paramiko.DSSKey.from_private_key", 8, pos(0, "f")),
		nameOnly(pyCall("app.main.(c).create", "c.create", 9, pos(0, "enums.Algorithm.AES")), "c"),
		nameOnly(pyCall("app.main.(c).create", "c.create", 10, pos(0, "enums.Algorithm.RSA")), "c"),
		withSpan(pyCall("hashlib.pbkdf2_hmac", "hashlib.pbkdf2_hmac", 11, pos(0, `"sha256"`), pos(1, "pw"), pos(2, "os.urandom(16)")), 5, 60),
		withSpan(pyCall("os.urandom", "os.urandom", 11, pos(0, "16")), 40, 54),
		pyCall("os.urandom", "os.urandom", 12, pos(0, "16")),
		withSpan(pyCall("os.urandom", "os.urandom", 13, pos(0, "16")), 5, 19),
		withSpan(pyCall("hashlib.pbkdf2_hmac", "os.urandom(16).pbkdf2_hmac", 13), 5, 40),
		withSpan(pyCall("os.getrandom", "os.getrandom", 14, pos(0, "16")), 5, 20),
	)
	got := pyRulesMatch(t, src, frag)
	want := []string{`create@9 {}`, `load@7 {"algorithmName": "RSAKey"}`, `scheme@5 {}`, `urandom@12 {}`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// What the extensions record and skip, and that they stay off in PoC mode.
func TestCompiledExtensionRecords(t *testing.T) {
	src := `rules:
- id: reassigned
  languages: [python]
  patterns:
  - pattern-inside: |
      $K = tokenkit.keys.SymKey.load(...)
      ...
  - pattern-not-inside:
      patterns:
      - pattern: |
          $K = $OTHER
          ...
      - metavariable-pattern:
          metavariable: $OTHER
          patterns:
          - pattern-not: tokenkit.keys.SymKey.load(...)
  - pattern: tokenkit.sig.compact($H, $P, $K, ...)
- id: unbound
  languages: [python]
  patterns:
  - pattern-inside: |
      $X = f.G(...)
      ...
  - pattern: h.m($Y)
- id: table-call
  languages: [python]
  patterns:
  - pattern-inside: "[..., $X, ...]"
  - pattern: h.m($Y)
- id: compared
  languages: [python]
  patterns:
  - pattern: h.m($Y)
  - pattern-not-inside: $A == $B
- id: nested-constant
  languages: [python]
  pattern: h.m(a.$X)
- id: origin-constant
  languages: [python]
  patterns:
  - pattern-inside: |
      $X = f.G(...)
      ...
  - pattern: ssl.PROTOCOL_TLSv1
- id: partial
  languages: [python]
  patterns:
  - pattern-either:
    - pattern-inside: |
        $X = f.G(...)
        ...
    - pattern-inside: |
        $Z = f.G(...)
        ...
  - pattern: $X.m()
- id: import-other
  languages: [python]
  patterns:
  - pattern-inside: |
      import foo
      ...
  - pattern: bar.m()
- id: mixed
  languages: [python]
  patterns:
  - pattern-either:
    - pattern-inside: |
        import f
        ...
    - pattern-inside: |
        $X = f.G(...)
        ...
  - pattern: $X.m()
- id: factory-types
  languages: [python]
  patterns:
  - pattern-inside: |
      $X = f.make(...)
      ...
  - pattern: $X.m()
`
	recs := compileRecords(t, src)
	for id, want := range map[string]string{
		"reassigned":      `"dropped_clauses": ["pattern-not-inside reassignment not checked"], "sinks": 1`,
		"unbound":         `"reason": "pattern-inside on a metavariable not bound in the call"`,
		"table-call":      `"reason": "pattern-inside table around a call"`,
		"compared":        `"dropped_clauses": ["pattern-not-inside comparison around a call"], "sinks": 1`,
		"nested-constant": `"reason": "argument is a sub-pattern with a metavariable"`,
		"origin-constant": `"reason": "pattern-inside origin around a constant"`,
		"partial":         `"dropped_clauses": ["pattern-inside alternative not compiled"], "sinks": 1`,
		"import-other":    `"dropped_clauses": ["pattern-inside import not about the callee type"], "sinks": 1`,
		"mixed":           `"reason": "pattern-inside that is not an import or package"`,
	} {
		if !strings.Contains(recs[id], want) {
			t.Errorf("%s: %s, want %s", id, recs[id], want)
		}
	}
	entries, _ := compileYAML(t, src)
	for _, e := range entries {
		if strings.Contains(e, `"rule_id": "factory-types"`) && !strings.Contains(e, `"types": [], "from": [{"call": "f.make"}]`) {
			t.Errorf("factory-types entry %s", e)
		}
	}
	_, poc := compileYAMLMode(t, src, true)
	for _, r := range poc {
		if !strings.Contains(r, `"status": "skipped"`) {
			t.Errorf("PoC mode compiled %s", r)
		}
	}
}

// "$X" string metavariables: the argument is a string literal (as written or
// resolved) whose content $X binds, and a regex on $X reads the content.
func TestCompiledStringMetavariable(t *testing.T) {
	src := `rules:
- id: kem
  languages: [python]
  patterns:
  - pattern-either:
    - pattern: oqs.KeyEncapsulation("$AL", ...)
    - pattern: oqs.KeyEncapsulation(alg_name="$AL", ...)
  - metavariable-regex: {metavariable: $AL, regex: '^ML-KEM-(?<bits>768)$'}
  metadata: {crypto: {algorithmName: $AL, size: $bits}}
- id: sig
  languages: [python]
  pattern: oqs.Signature("$AL")
`
	resolved := pos(0, "name")
	resolved.ResolvedValue = `"ML-KEM-768"`
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "oqs"}},
		pyCall("oqs.KeyEncapsulation", "oqs.KeyEncapsulation", 5, pos(0, `"ML-KEM-768"`)),
		pyCall("oqs.KeyEncapsulation", "oqs.KeyEncapsulation", 6, kw(0, "alg_name", `'ML-KEM-768'`)),
		pyCall("oqs.KeyEncapsulation", "oqs.KeyEncapsulation", 7, pos(0, `"ML-KEM-512"`)),
		pyCall("oqs.KeyEncapsulation", "oqs.KeyEncapsulation", 8, pos(0, "name")),
		pyCall("oqs.KeyEncapsulation", "oqs.KeyEncapsulation", 9, resolved),
		pyCall("oqs.Signature", "oqs.Signature", 10, pos(0, `"ML-DSA-65"`)),
		pyCall("oqs.Signature", "oqs.Signature", 11, pos(0, "name")),
	)
	got := pyRulesMatch(t, src, frag)
	want := []string{
		`kem@5 {"algorithmName": "ML-KEM-768", "size": "768"}`,
		`kem@6 {"algorithmName": "ML-KEM-768", "size": "768"}`,
		`kem@9 {"algorithmName": "ML-KEM-768", "size": "768"}`,
		`sig@10 {}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// Dict and list display arguments holding a focused metavariable, and taint
// written into a display: the string literals in it are the taint values.
func TestCompiledContainerArguments(t *testing.T) {
	src := `rules:
- id: hs
  languages: [python]
  mode: taint
  pattern-sources:
  - patterns:
    - pattern: $SEL
    - metavariable-regex: {metavariable: $SEL, regex: '"(?<alg>HS256)"'}
  pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: 'jwt.encode({"alg": $SEL, ...}, ...)'
      - pattern: authlib.jose.JsonWebToken([$SEL, ...])
    - focus-metavariable: $SEL
- id: header
  languages: [python]
  mode: taint
  pattern-sources:
  - patterns:
    - pattern: $ENC
    - metavariable-regex: {metavariable: $ENC, regex: '^"A256GCM"$'}
  pattern-sinks:
  - patterns:
    - pattern: joserfc.jwe.encrypt_compact($HDR, ...)
    - focus-metavariable: $HDR
`
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "authlib.jose", Name: "jwt"}, {Line: 2, Module: "authlib.jose", Name: "JsonWebToken"}, {Line: 3, Module: "joserfc", Name: "jwe"}},
		pyCall("authlib.jose.jwt.encode", "jwt.encode", 5, pos(0, `{"alg": "HS256", "typ": "JWT"}`), pos(1, "p")),
		pyCall("authlib.jose.jwt.encode", "jwt.encode", 6, pos(0, `{'alg': 'HS256'}`), pos(1, "p")),
		pyCall("authlib.jose.jwt.encode", "jwt.encode", 7, pos(0, `{"typ": "HS256"}`), pos(1, "p")),
		pyCall("authlib.jose.jwt.encode", "jwt.encode", 8, pos(0, `{"alg": "RS256"}`), pos(1, "p")),
		pyCall("authlib.jose.JsonWebToken", "JsonWebToken", 9, pos(0, `["RS256", "HS256"]`)),
		pyCall("authlib.jose.JsonWebToken", "JsonWebToken", 10, pos(0, `("HS256",)`)),
		pyCall("joserfc.jwe.encrypt_compact", "jwe.encrypt_compact", 11, pos(0, `{"alg": "RSA-OAEP", "enc": "A256GCM"}`), pos(1, "d")),
		pyCall("joserfc.jwe.encrypt_compact", "jwe.encrypt_compact", 12, pos(0, `{"enc": "A128GCM"}`), pos(1, "d")),
		pyCall("joserfc.jwe.encrypt_compact", "jwe.encrypt_compact", 13, pos(0, `{'enc': 'A256GCM'}`), pos(1, "d")),
		pyCall("joserfc.jwe.encrypt_compact", "jwe.encrypt_compact", 14, pos(0, `header("A256GCM")`), pos(1, "d")),
	)
	frag.Imports["app/main.py"][0].Module = "jwt" // `jwt` is PyJWT's here: rule's jwt.encode
	got := pyRulesMatch(t, src, frag)
	if want := []string{`header@11 {}`, `header@13 {}`, `header@14 {}`, `hs@5 {}`, `hs@6 {}`, `hs@9 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	recs := compileRecords(t, `rules:
- id: regex-on-container
  languages: [python]
  patterns:
  - pattern: 'f([$A, ...])'
  - metavariable-regex: {metavariable: $A, regex: x}
- id: origin-on-container
  languages: [python]
  patterns:
  - pattern-inside: |
      $A = f.G(...)
      ...
  - pattern: 'h.m({"k": $A})'
`)
	for _, id := range []string{"regex-on-container", "origin-on-container"} {
		if !strings.Contains(recs[id], `"status": "skipped"`) {
			t.Errorf("%s: %s", id, recs[id])
		}
	}
}

// Object-flow sources made of a factory minus pattern-not calls, and
// self fields assigned from a class instantiation.
func TestCompiledNegatedSources(t *testing.T) {
	src := `rules:
- id: encrypt
  languages: [python]
  mode: taint
  pattern-sources:
  - patterns:
    - pattern: gnupg.GPG(...)
    - pattern-not: gnupg.GPG(..., homedir=$DIR, ...)
  - patterns:
    - pattern-either:
      - pattern: self.$F
      - pattern: cls.$F
    - pattern-either:
      - pattern-inside: |
          class $C:
              ...
              def $M(...):
                  ...
                  self.$F = gnupg.GPG(...)
                  ...
  pattern-sinks:
  - pattern: $G.encrypt(...)
`
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "gnupg"}},
		withAssigned(pyCall("gnupg.GPG", "gnupg.GPG", 5), "g"),
		nameOnly(pyCall("app.main.(g).encrypt", "g.encrypt", 6, pos(0, "m")), "g"),
		withAssigned(pyCall("gnupg.GPG", "gnupg.GPG", 7, kw(0, "homedir", `"/x"`)), "h"),
		withRecv(pyCall("gnupg.(GPG).encrypt", "h.encrypt", 8, pos(0, "m")), "h"),
		withRecv(pyCall("gnupg.(GPG).encrypt", "self.gpg.encrypt", 9, pos(0, "m")), "self.gpg"),
		nameOnly(pyCall("app.main.(x).encrypt", "x.encrypt", 10, pos(0, "m")), "x"),
	)
	if got, want := pyRulesMatch(t, src, frag), []string{`encrypt@6 {}`, `encrypt@9 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	recs := compileRecords(t, strings.Replace(src, "self.$F = gnupg.GPG(...)", "self.$F = gnupg.make(...)", 1))
	if !strings.Contains(recs["encrypt"], `"dropped_clauses": ["taint source alternative not compiled"]`) {
		t.Errorf("a self field from a factory function: %s", recs["encrypt"])
	}
}

// A constraint on a dict entry's value in a display argument: the value of
// that key, qualified through the imports for dotted names (a key-management client's
// cipher_params).
func TestCompiledDictEntryConstraint(t *testing.T) {
	src := `rules:
- id: aes
  languages: [python]
  patterns:
  - pattern-inside: |
      $C = vaultkit.remote.RemoteClient(...)
      ...
  - pattern: "$C.encrypt(..., cipher_params={..., 'cipher_alg': $AL, ...}, ...)"
  - metavariable-pattern:
      metavariable: $AL
      patterns:
      - pattern-either:
        - pattern: vaultkit.core.enums.Algorithm.AES
        - pattern: vaultkit.enums.Algorithm.AES
`
	params := func(text string) Param { return kw(1, "cipher_params", text) }
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "vaultkit.remote", Name: "RemoteClient"}, {Line: 2, Module: "vaultkit.core", Name: "enums"}},
		withAssigned(pyCall("vaultkit.remote.RemoteClient", "RemoteClient", 4), "c"),
		nameOnly(pyCall("app.main.(c).encrypt", "c.encrypt", 5, pos(0, "d"),
			params(`{"cipher_alg": enums.Algorithm.AES, "cipher_mode": enums.Mode.CBC}`)), "c"),
		nameOnly(pyCall("app.main.(c).encrypt", "c.encrypt", 6, pos(0, "d"), params(`{"cipher_alg": enums.Algorithm.DES}`)), "c"),
		nameOnly(pyCall("app.main.(c).encrypt", "c.encrypt", 7, pos(0, "d"), params(`{"cipher_mode": enums.Algorithm.AES}`)), "c"),
		nameOnly(pyCall("app.main.(c).encrypt", "c.encrypt", 8, pos(0, "d"), params(`[enums.Algorithm.AES]`)), "c"),
		nameOnly(pyCall("app.main.(c).encrypt", "c.encrypt", 9, pos(0, "d"),
			params(`{"x": {"cipher_alg": 1}, "cipher_alg": vaultkit.core.enums.Algorithm.AES}`)), "c"),
	)
	if got, want := pyRulesMatch(t, src, frag), []string{`aes@5 {}`, `aes@9 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}
