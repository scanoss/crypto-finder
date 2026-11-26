// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"encoding/json"
	"testing"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Pattern text reads into the closed expression shapes, and prints back in
// the canonical spelling whatever the spacing it was written with.
func TestRustPatternExprShapes(t *testing.T) {
	for _, tc := range []struct{ text, canonical, shape string }{
		{
			"acme_kdf :: Kdf :: < Sha256 > :: new ( $S , ... )", "acme_kdf::Kdf::<Sha256>::new($S, ...)",
			`{"kind":"call","call":{"callee":{"segs":[{"name":"acme_kdf"},{"name":"Kdf","generics":[{"path":{"segs":[{"name":"Sha256"}]}}]},{"name":"new"}]},"args":[{"kind":"metavar","var":"$S"},{"kind":"ellipsis"}]}}`,
		},
		{
			"<$T as acme_hash::Digest>::digest(b\"x\")", `<$T as acme_hash::Digest>::digest(b"x")`,
			`{"kind":"call","call":{"callee":{"qself":{"self":{"var":"$T"},"trait":{"segs":[{"name":"acme_hash"},{"name":"Digest"}]}},"segs":[{"name":"digest"}]},"args":[{"kind":"literal","lit":"b\"x\""}]}}`,
		},
		{
			"$K.derive::<Vec<u8>>(&mut $OUT, &acme_sig::ALG_A)", "$K.derive::<Vec<u8>>(&mut $OUT, &acme_sig::ALG_A)",
			`{"kind":"call","call":{"receiver":{"kind":"metavar","var":"$K"},"method":"derive","turbofish":[{"path":{"segs":[{"name":"Vec","generics":[{"path":{"segs":[{"name":"u8"}]}}]}]}}],"args":[{"kind":"ref","sub":{"kind":"metavar","var":"$OUT"},"mut":true},{"kind":"ref","sub":{"kind":"path","path":{"segs":[{"name":"acme_sig"},{"name":"ALG_A"}]}}}]}}`,
		},
		{
			"acme::Key::new(...).unwrap()?", "acme::Key::new(...).unwrap()?",
			`{"kind":"try","sub":{"kind":"call","call":{"receiver":{"kind":"call","call":{"callee":{"segs":[{"name":"acme"},{"name":"Key"},{"name":"new"}]},"args":[{"kind":"ellipsis"}]}},"method":"unwrap","args":[]}}}`,
		},
		{
			"<... Signer::new(...) ...>", "<...Signer::new(...)...>",
			`{"kind":"deep","sub":{"kind":"call","call":{"callee":{"segs":[{"name":"Signer"},{"name":"new"}]},"args":[{"kind":"ellipsis"}]}}}`,
		},
		{
			"$F(Some(&$N[..]), self.key, -1)", "$F(Some(&$N[..]), self.key, -1)",
			`{"kind":"call","call":{"callee":{"segs":[{"var":"$F"}]},"args":[{"kind":"call","call":{"callee":{"segs":[{"name":"Some"}]},"args":[{"kind":"ref","sub":{"kind":"index","sub":{"kind":"metavar","var":"$N"},"index":{"kind":"range"}}}]}},{"kind":"field","sub":{"kind":"path","path":{"segs":[{"name":"self"}]}},"field":"key"},{"kind":"literal","lit":"-1"}]}}`,
		},
		{
			"::acme::Kdf::<(u8, $T), [u8; 32]>::new()", "::acme::Kdf::<(u8, $T), [u8; 32]>::new()",
			`{"kind":"call","call":{"callee":{"global":true,"segs":[{"name":"acme"},{"name":"Kdf","generics":[{"tuple":[{"path":{"segs":[{"name":"u8"}]}},{"var":"$T"}]},{"text":"[u8; 32]"}]},{"name":"new"}]},"args":[]}}`,
		},
	} {
		e, err := parseRustPatternExpr(tc.text)
		if err != nil {
			t.Errorf("%s: %v", tc.text, err)
			continue
		}
		if got := e.String(); got != tc.canonical {
			t.Errorf("%s: canonical %q, want %q", tc.text, got, tc.canonical)
		}
		if got := mustJSON(t, e); got != tc.shape {
			t.Errorf("%s: shape\n got %s\nwant %s", tc.text, got, tc.shape)
		}
	}
}

// Pattern text outside the closed set names the shape it lacks.
func TestRustPatternExprRefused(t *testing.T) {
	for text, want := range map[string]rustSkip{
		"acme::hash!($X)":             skipRustMacro,
		"$A << $B":                    skipRustExpr,
		"|x| acme::derive(x)":         skipRustExpr,
		`acme::f("unterminated)`:      skipRustSyntax,
		"acme::Kdf::<[$T; 2]>::new()": skipRustType,
		"acme::f(a b)":                skipRustExpr,
		"acme::cfg(). ... .finish()":  skipRustSyntax,
	} {
		_, err := parseRustPatternExpr(text)
		s, ok := asSkip(err)
		if !ok || s.reason != string(want) {
			t.Errorf("%s: %v, want %q", text, err, want)
		}
	}
}

// Source text reads into the same values as pattern text written the same
// way; text with no shape keeps its canonical spelling, which only a
// metavariable matches.
func TestReadRustExpr(t *testing.T) {
	for text, want := range map[string]string{
		"Kdf::<Sha256>::new(None, b\"ikm\")": `{"kind":"call","call":{"callee":{"segs":[{"name":"Kdf","generics":[{"path":{"segs":[{"name":"Sha256"}]}}]},{"name":"new"}]},"args":[{"kind":"path","path":{"segs":[{"name":"None"}]}},{"kind":"literal","lit":"b\"ikm\""}]}}`,
		"&acme_sig::ALG_A // trailing":       `{"kind":"ref","sub":{"kind":"path","path":{"segs":[{"name":"acme_sig"},{"name":"ALG_A"}]}}}`,
		"a +  b":                             `{"kind":"binary","sub":{"kind":"path","path":{"segs":[{"name":"a"}]}},"op":"+","right":{"kind":"path","path":{"segs":[{"name":"b"}]}}}`,
		"a << b":                             `{"kind":"text","lit":"a\u003c\u003cb"}`,
		"|x|   x . len ()":                   `{"kind":"text","lit":"|x|x.len()"}`,
		"'\\n'":                              `{"kind":"literal","lit":"'\\n'"}`,
		"r#\"a \"q\" b\"#":                   `{"kind":"literal","lit":"r#\"a \"q\" b\"#"}`,
		"&'a str":                            `{"kind":"text","lit":"\u0026'a str"}`,
		"f(|a, b| a.cmp(b), k)":              `{"kind":"call","call":{"callee":{"segs":[{"name":"f"}]},"args":[{"kind":"text","lit":"|a, b|a.cmp(b)"},{"kind":"path","path":{"segs":[{"name":"k"}]}}]}}`,
		"f(move |a, b| a, k)":                `{"kind":"call","call":{"callee":{"segs":[{"name":"f"}]},"args":[{"kind":"text","lit":"move|a, b|a"},{"kind":"path","path":{"segs":[{"name":"k"}]}}]}}`,
		"f(x as HashMap<K, V>, k)":           `{"kind":"call","call":{"callee":{"segs":[{"name":"f"}]},"args":[{"kind":"text","lit":"x as HashMap\u003cK, V\u003e"},{"kind":"path","path":{"segs":[{"name":"k"}]}}]}}`,
		"f(a + b.c::<HashMap<K, V>>(), k)":   `{"kind":"call","call":{"callee":{"segs":[{"name":"f"}]},"args":[{"kind":"binary","sub":{"kind":"path","path":{"segs":[{"name":"a"}]}},"op":"+","right":{"kind":"call","call":{"receiver":{"kind":"path","path":{"segs":[{"name":"b"}]}},"method":"c","turbofish":[{"path":{"segs":[{"name":"HashMap","generics":[{"path":{"segs":[{"name":"K"}]}},{"path":{"segs":[{"name":"V"}]}}]}]}}],"args":[]}}},{"kind":"path","path":{"segs":[{"name":"k"}]}}]}}`,
		"&s * &p - 2":                        `{"kind":"binary","sub":{"kind":"binary","sub":{"kind":"ref","sub":{"kind":"path","path":{"segs":[{"name":"s"}]}}},"op":"*","right":{"kind":"ref","sub":{"kind":"path","path":{"segs":[{"name":"p"}]}}}},"op":"-","right":{"kind":"literal","lit":"2"}}`,
	} {
		e, ok := readRustExpr(text)
		if !ok {
			t.Errorf("%s: not read", text)
			continue
		}
		if got := mustJSON(t, e); got != want {
			t.Errorf("%s:\n got %s\nwant %s", text, got, want)
		}
	}
	if e, _ := readRustExpr("$X.f()"); mustJSON(t, e) != `{"kind":"text","lit":"$X.f()"}` {
		t.Errorf("source text with a metavariable read as %s", mustJSON(t, e))
	}
}

// Qualified: the path names a module, a type or a trait before its last
// segment; how OpenGrep compares it with a written site depends on it.
func TestRustPathQualified(t *testing.T) {
	for text, want := range map[string]bool{
		"acme_kdf::Kdf::new(...)": true,
		"Kdf::new(...)":           true,
		"derive(...)":             false,
		"$F(...)":                 false,
		"::derive(...)":           true,
		"<T as Tr>::f(...)":       true,
	} {
		e, err := parseRustPatternExpr(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got := e.Call.Callee.Qualified(); got != want {
			t.Errorf("%s: qualified %v, want %v", text, got, want)
		}
	}
}

// The receiver span of a path call is the path in front of its last
// segment, wherever the generics are written.
func TestReadRustPathCallRecvSpan(t *testing.T) {
	for text, want := range map[string]string{
		"A::verify(x)":                  "A",
		"A::verify::<u8>(x)":            "A",
		"a::A::verify::<Hmac<Sha>>(x)":  "a::A",
		"A::<u8>::verify(x)":            "A::<u8>",
		"a::<B<C>>::A::verify::<u8>(x)": "a::<B<C>>::A",
	} {
		e, ok := readRustExpr(text)
		if !ok || e.Call == nil {
			t.Fatalf("%s: not read as a call", text)
		}
		if got := text[e.Call.RecvSpan[0]:e.Call.RecvSpan[1]]; got != want {
			t.Errorf("%s: receiver span %q, want %q", text, got, want)
		}
	}
}
