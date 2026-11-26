package jspat

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func mustPattern(t *testing.T, s string) *Node {
	t.Helper()
	n, err := ParseExpr(s, true)
	if err != nil {
		t.Fatalf("ParseExpr(%q, pattern): %v", s, err)
	}
	return n
}

func concrete(s string) *Node {
	n, _ := ParseExpr(s, false)
	return n
}

func envText(e Env) string {
	parts := make([]string, 0, len(e))
	for k, v := range e {
		parts = append(parts, k+"="+v.Node.Text)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func TestParseTexts(t *testing.T) {
	cases := []struct {
		in      string
		pattern bool
		kind    Kind
		text    string
	}{
		{`a.b.c`, true, Member, `a.b.c`},
		{`a["b"].c`, true, Member, `a["b"].c`},
		{`'x'`, true, String, `"x"`},
		{`"it's"`, true, String, `"it's"`},
		{`'say "hi"'`, true, String, `"say \"hi\""`},
		{`-1`, true, Number, `-1`},
		{`  f( a ,b )  `, true, Call, `f(a, b)`},
		{`new   a.B(1)`, true, New, `new a.B(1)`},
		{`x || "S"`, true, Binary, `x||"S"`},
		{`x ?? y`, true, Binary, `x??y`},
		{`(0, $NS.f)`, true, Sequence, `(0, $NS.f)`},
		{`await $X`, true, Unary, `await $X`},
		{`<... $K ...>`, true, Deep, `<...$K...>`},
		{`$X`, true, Metavar, `$X`},
		{`$X`, false, Ident, `$X`},
		{`$`, false, Ident, `$`},
		{`[1, ...]`, true, Array, `[1, ...]`},
		{`a?.b`, true, Member, `a?.b`},
		{"`plain`", true, String, `"plain"`},
		{`x[i]`, true, Index, `x[i]`},
		// concrete: unmodelled constructs
		{`(a, b) => a`, false, Opaque, `(a, b)=>a`},
		{`x => x`, false, Opaque, `x=>x`},
		{`async () => {}`, false, Opaque, `async()=>{}`},
		{`function (a) { return a }`, false, Opaque, `function(a){return a}`},
		{"`a${b}`", false, Opaque, "`a${b}`"},
		{`/ab+c/gi`, false, Opaque, `/ab+c/gi`},
		{`x as Buffer`, false, Opaque, `x as Buffer`},
		{`x!`, false, Opaque, `x!`},
		{`c ? a : b`, false, Opaque, `c?a:b`},
		{`...rest`, false, Opaque, `...rest`},
		{``, false, Opaque, ``},
	}
	for _, c := range cases {
		n, err := ParseExpr(c.in, c.pattern)
		if err != nil {
			t.Errorf("ParseExpr(%q): %v", c.in, err)
			continue
		}
		if n.Kind != c.kind || n.Text != c.text {
			t.Errorf("ParseExpr(%q) = kind %d text %q, want kind %d text %q", c.in, n.Kind, n.Text, c.kind, c.text)
		}
	}
}

// The callee of a `new` carries its own text, from its first token.
func TestNewCalleeText(t *testing.T) {
	n := mustPattern(t, `new $NS.x.Y($A, ...)`)
	if got := n.Kids[0].Text; got != `$NS.x.Y` {
		t.Errorf("callee text = %q, want %q", got, `$NS.x.Y`)
	}
}

func TestOpaqueReasons(t *testing.T) {
	for in, want := range map[string]string{
		`x => 1`:           "fn",
		`function(){}`:     "fn",
		`/a/`:              "regex",
		"`a${b}`":          "expr",
		`x as T`:           "expr",
		`foo(x => 1) as T`: "expr",
	} {
		if n := concrete(in); n.Kind != Opaque || n.Name != want {
			t.Errorf("%q: got kind %d name %q, want Opaque %q", in, n.Kind, n.Name, want)
		}
	}
}

func TestConcreteNestedOpaque(t *testing.T) {
	n := concrete(`f(x => x, {cb: function () {}, k: "v"}, [a as B, ...c])`)
	if n.Kind != Call || len(n.Kids) != 4 {
		t.Fatalf("got %+v", n)
	}
	if n.Kids[1].Kind != Opaque || n.Kids[1].Name != "fn" {
		t.Errorf("arrow arg: %+v", n.Kids[1])
	}
	obj := n.Kids[2]
	if obj.Kind != Object || obj.Props[0].Value.Kind != Opaque || obj.Props[1].Value.Kind != String {
		t.Errorf("object arg: %+v", obj)
	}
	arr := n.Kids[3]
	if arr.Kind != Array || len(arr.Kids) != 2 || arr.Kids[0].Kind != Opaque || !isSpread(arr.Kids[1]) {
		t.Errorf("array arg: %+v", arr)
	}
}

func TestStringDecoding(t *testing.T) {
	a := concrete(`"aA\x42\n"`)
	b := concrete(`'aAB\n'`)
	if a.Name != "aAB\n" || a.Text != b.Text {
		t.Errorf("got %q %q / %q", a.Name, a.Text, b.Text)
	}
}

func TestParsePatternErrors(t *testing.T) {
	for _, in := range []string{
		`x => 1`, `function (a) {}`, `a ? b : c`, `$X = 1`, `a +`, `f(`, `{a: }`, `"open`, ``, `{[k]: 1}`, `x++`, `a b`,
	} {
		if _, err := ParseExpr(in, true); !errors.Is(err, ErrUnsupported) {
			t.Errorf("ParseExpr(%q, pattern) err = %v, want ErrUnsupported", in, err)
		}
	}
	if _, err := ParseArgs(`a, ?`); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ParseArgs err = %v", err)
	}
}

type unifyCase struct {
	pat  string
	conc string
	want Verdict
	env  string
}

func TestUnify(t *testing.T) {
	cases := []unifyCase{
		// metavariables and repeated metavariables
		{`$X`, `foo.bar`, Yes, `$X=foo.bar`},
		{`$X`, `x => 1`, Yes, `$X=x=>1`},
		{`f($X, $X)`, `f(a, a)`, Yes, `$X=a`},
		{`f($X, $X)`, `f(a, b)`, No, ``},
		{`f($X, $X)`, `f("a", 'a')`, Yes, `$X="a"`},
		{`f($_, $_)`, `f(a, b)`, Yes, ``},
		// strings, numbers
		{`"AES"`, `'AES'`, Yes, ``},
		{`'AES'`, `"AES"`, Yes, ``},
		{`"AES"`, `"RSA"`, No, ``},
		{`"AES"`, `1`, No, ``},
		// "..." is any string literal (OpenGrep), and only a string literal.
		{`"..."`, `'RS256'`, Yes, ``},
		{`"..."`, `""`, Yes, ``},
		{`"..."`, `alg`, No, ``},
		{`"..."`, `1`, No, ``},
		{`{..., algorithm: "...", ...}`, `{ key, algorithm: 'HS256' }`, Yes, ``},
		{`{..., algorithm: "...", ...}`, `{ key, algorithm: alg }`, No, ``},
		{`16`, `16`, Yes, ``},
		{`16`, `32`, No, ``},
		{`-1`, `-1`, Yes, ``},
		// members
		{`a.b.c`, `a.b.c`, Yes, ``},
		{`a.b.c`, `a["b"].c`, Yes, ``},
		{`a.b.c`, `a.b.d`, No, ``},
		{`a.b.c`, `x.b.c`, No, ``},
		{`$NS.$F`, `acme.seal`, Yes, `$F=seal;$NS=acme`},
		{`$NS.$F.$F`, `acme.seal.seal`, Yes, `$F=seal;$NS=acme`},
		{`$NS.$F.$F`, `acme.seal.open`, No, ``},
		{`$NS.default.f(...)`, `acme.default.f()`, Yes, `$NS=acme`},
		// calls and new
		{`$NS.a.b(...)`, `acme.a.b(1, 2)`, Yes, `$NS=acme`},
		{`$NS.a.b(...)`, `acme.a.c()`, No, ``},
		{`$NS.a(...)`, `acme.a.b()`, No, ``},
		{`f()`, `f(1)`, No, ``},
		{`f($A)`, `f(1, 2)`, No, ``},
		{`new $NS.X(...)`, `new acme.X("k")`, Yes, `$NS=acme`},
		{`new $NS.X(...)`, `acme.X("k")`, No, ``},
		{`new X`, `new X()`, Yes, ``},
		// sequence callee
		{`(0, $NS.f)(...)`, `(0, acme.f)(1)`, Yes, `$NS=acme`},
		{`(0, $NS.f)(...)`, `(0, acme.g)(1)`, No, ``},
		{`(0, $NS.f)`, `acme.f`, No, ``},
		// operators
		{`$X || "S"`, `opt || 'S'`, Yes, `$X=opt`},
		{`$X || "S"`, `opt || 'T'`, No, ``},
		{`$X ?? $Y`, `a ?? b`, Yes, `$X=a;$Y=b`},
		{`$X ?? $Y`, `a || b`, No, ``},
		{`$X + "s"`, `a + "s"`, Yes, `$X=a`},
		{`await $X`, `await fetchKey()`, Yes, `$X=fetchKey()`},
		{`await $X`, `fetchKey()`, No, ``},
		{`!$X`, `!a`, Yes, `$X=a`},
		// objects
		{`{..., mode: "cbc", ...}`, `{mode: 'cbc', iv}`, Yes, ``},
		{`{..., mode: "cbc", ...}`, `{iv, mode: "cbc"}`, Yes, ``},
		{`{..., mode: "cbc", ...}`, `{mode: "ecb"}`, No, ``},
		{`{..., mode: "cbc", ...}`, `{iv}`, No, ``},
		{`{..., mode: "cbc", ...}`, `{...opts}`, Unknown, ``},
		{`{..., mode: "cbc", ...}`, `{...opts, mode: "cbc"}`, Yes, ``},
		{`{..., mode: "cbc", ...}`, `{...opts, mode: "ecb"}`, No, ``},
		{`{..., mode: "cbc", ...}`, `{[k]: 1}`, Unknown, ``},
		{`{mode: $M}`, `{mode: 1}`, Yes, `$M=1`},
		{`{mode: $M}`, `{mode: 1, extra: 2}`, No, ``},
		{`{mode: $M}`, `{mode: 1, ...opts}`, Unknown, ``},
		{`{mode: $M}`, `{iv: 1}`, No, ``},
		{`{mode: $M}`, `{}`, No, ``},
		{`{}`, `{}`, Yes, ``},
		{`{}`, `{a: 1}`, No, ``},
		{`{...}`, `{a: 1}`, Yes, ``},
		{`{"mode": "cbc"}`, `{mode: "cbc"}`, Yes, ``},
		{`{mode: "cbc"}`, `{'mode': 'cbc'}`, Yes, ``},
		{`{a}`, `{a}`, Yes, ``},
		{`{a: $A}`, `{a}`, Yes, `$A=a`},
		{`{..., $K: "cbc", ...}`, `{mode: "cbc"}`, Yes, `$K=mode`},
		{`{..., $K: "cbc", ...}`, `{mode: "ecb"}`, No, ``},
		{`{..., a: $V, b: $V, ...}`, `{a: 1, b: 1}`, Yes, `$V=1`},
		{`{..., a: $V, b: $V, ...}`, `{a: 1, b: 2}`, No, ``},
		{`{name: "x", opts: {..., hash: $H, ...}}`, `{name: 'x', opts: {iv: 1, hash: "sha"}}`, Yes, `$H="sha"`},
		{`{name: "x", opts: {hash: $H}}`, `{name: 'x', opts: {iv: 1, hash: "sha"}}`, No, ``},
		{`{..., opts: {..., hash: "sha", ...}, ...}`, `{opts: {...o}}`, Unknown, ``},
		{`{..., cb: $F, ...}`, `{cb: (e) => e}`, Yes, `$F=(e)=>e`},
		{`{..., cb: "x", ...}`, `{cb: (e) => e}`, No, ``},
		{`{..., k: "x", ...}`, `{k: ` + "`a${b}`" + `}`, Unknown, ``},
		{`{...}`, `opts`, No, ``},
		// arrays
		{`[$A, ...]`, `[1, 2, 3]`, Yes, `$A=1`},
		{`[$A, $B]`, `[1, 2, 3]`, No, ``},
		{`[$A, $B]`, `[1, ...rest]`, Unknown, ``},
		{`["a", "b"]`, `['a', 'b']`, Yes, ``},
		// deep
		{`<... "k" ...>`, `f(g("k"))`, Yes, ``},
		{`<... "k" ...>`, `"k"`, Yes, ``},
		{`<... "k" ...>`, `f(g("z"))`, No, ``},
		{`<... "k" ...>`, `f({a: [1, "k"]})`, Yes, ``},
		{`<... "k" ...>`, `f(x => 1)`, Unknown, ``},
		{`<... $K ...>`, `a`, Yes, `$K=a`},
		{`<... require("m") ...>`, `await require('m')`, Yes, ``},
		{`<... require("m") ...>`, `require("n")`, No, ``},
		// opaque concrete
		{`"a"`, "`x${y}`", Unknown, ``},
		{`{...}`, `(e) => e`, No, ``},
		{`f($A)`, `x => x`, No, ``},
		{`$A`, `/ab/`, Yes, `$A=/ab/`},
		{`/ab/`, `/ab/`, Yes, ``},
		{`/ab/`, `/ac/`, No, ``},
	}
	for _, c := range cases {
		p, err := ParseExpr(c.pat, true)
		if err != nil {
			t.Errorf("pattern %q: %v", c.pat, err)
			continue
		}
		before := Env{"$PRE": {Node: concrete("pre")}}
		env, got := Unify(p, concrete(c.conc), before)
		if got != c.want {
			t.Errorf("Unify(%q, %q) = %v, want %v", c.pat, c.conc, got, c.want)
			continue
		}
		if len(before) != 1 {
			t.Errorf("Unify(%q, %q) mutated its input env", c.pat, c.conc)
		}
		if got == Yes {
			delete(env, "$PRE")
			if g := envText(env); g != c.env {
				t.Errorf("Unify(%q, %q) env = %q, want %q", c.pat, c.conc, g, c.env)
			}
		}
	}
}

func TestUnifyKeepsEnv(t *testing.T) {
	env := Env{"$X": {Node: concrete("a")}}
	if _, v := Unify(mustPattern(t, `f($X)`), concrete(`f(a)`), env); v != Yes {
		t.Errorf("bound metavariable equal: %v", v)
	}
	if _, v := Unify(mustPattern(t, `f($X)`), concrete(`f(b)`), env); v != No {
		t.Errorf("bound metavariable different: %v", v)
	}
}

func args(t *testing.T, pat string) []*Node {
	t.Helper()
	ps, err := ParseArgs(pat)
	if err != nil {
		t.Fatalf("ParseArgs(%q): %v", pat, err)
	}
	return ps
}

func cargs(conc string, resolved ...string) []Concrete {
	nodes := ParseConcreteArgs(conc)
	out := make([]Concrete, len(nodes))
	for i, n := range nodes {
		out[i].Node = n
		if i < len(resolved) {
			out[i].Resolved = resolved[i]
		}
	}
	return out
}

func TestUnifyArgs(t *testing.T) {
	cases := []struct {
		pat      string
		conc     string
		resolved []string
		want     Verdict
		env      string
	}{
		{``, ``, nil, Yes, ``},
		{``, `a`, nil, No, ``},
		{`...`, ``, nil, Yes, ``},
		{`...`, `a, b, c`, nil, Yes, ``},
		{`$K, ...`, `key, a, b`, nil, Yes, `$K=key`},
		{`$K, ...`, ``, nil, No, ``},
		{`..., $L`, `a, b, last`, nil, Yes, `$L=last`},
		{`$A, ..., $B`, `a, b`, nil, Yes, `$A=a;$B=b`},
		{`$A, ..., $B`, `a`, nil, No, ``},
		{`$K, ..., {..., mode: $M, ...}`, `key, 16, {mode: "cbc", iv}`, nil, Yes, `$K=key;$M="cbc"`},
		{`$K, ..., {..., mode: $M, ...}`, `key, {iv}`, nil, No, ``},
		{`$K, ..., {..., mode: $M, ...}`, `key, 16, {...o}`, nil, Unknown, ``},
		{`..., {..., a: 1, ...}, ...`, `x, {b: 2}, {a: 1}, z`, nil, Yes, ``},
		{`$X, ..., $X`, `a, b, a`, nil, Yes, `$X=a`},
		{`$X, ..., $X`, `a, b, c`, nil, No, ``},
		{`$X, ..., $X`, `n, b, m`, []string{"v", "", "v"}, Yes, `$X=n`},
		{`"AES-GCM", ...`, `alg, k`, []string{"AES-GCM"}, Yes, ``},
		{`"AES-GCM", ...`, `alg, k`, []string{"RSA"}, No, ``},
		{`"AES-GCM", ...`, `alg, k`, nil, No, ``},
		{`"AES-GCM", ...`, `'AES-GCM', k`, nil, Yes, ``},
		{`{name: "AES-GCM"}, ...`, `{name: alg}, k`, []string{"", ""}, No, ``},
		{`$A, $B`, `a, ...rest`, nil, Unknown, ``},
		{`$A, $B`, `a, b`, nil, Yes, `$A=a;$B=b`},
		{`$A`, `(x) => x`, nil, Yes, `$A=(x)=>x`},
		{`$A, {...}`, `a, {x: 1}, c`, nil, No, ``},
		// `...$X` in an object pattern is a spread, not an ellipsis.
		{`{..., ...$R, ...}`, `{a: 1}`, nil, No, ``},
		{`{..., ...$R, ...}`, `{a: 1, ...opts}`, nil, Yes, `$R=opts`},
		{`{a: $A, ...$R}`, `{...opts, a: 1}`, nil, Yes, `$A=1;$R=opts`},
		// "=~/re/" is a regex string: searched in the string's value.
		{`"=~/^(?!-----BEGIN)/", ...`, `"secret", k`, nil, Yes, ``},
		{`"=~/^(?!-----BEGIN)/", ...`, `"-----BEGIN KEY", k`, nil, No, ``},
		{`"=~/aes/"`, `alg`, []string{"x-aes-y"}, Yes, ``},
		{`"=~/aes/"`, `alg`, nil, No, ``},
	}
	for _, c := range cases {
		env, got := UnifyArgs(args(t, c.pat), cargs(c.conc, c.resolved...), nil)
		if got != c.want {
			t.Errorf("UnifyArgs(%q, %q, %v) = %v, want %v", c.pat, c.conc, c.resolved, got, c.want)
			continue
		}
		if got == Yes {
			if g := envText(env); g != c.env {
				t.Errorf("UnifyArgs(%q, %q) env = %q, want %q", c.pat, c.conc, g, c.env)
			}
		}
	}
}

func TestResolvedBoundToMetavar(t *testing.T) {
	env, v := UnifyArgs(args(t, `$ALG, ...`), cargs(`name, k`, "AES"), nil)
	if v != Yes || env["$ALG"].Resolved != "AES" {
		t.Errorf("got %v %+v", v, env)
	}
}

func TestParseArgs(t *testing.T) {
	ps := args(t, `$K, ..., {..., mode: $M, ...},`)
	if len(ps) != 3 || ps[0].Kind != Metavar || ps[1].Kind != Ellipsis || ps[2].Kind != Object {
		t.Fatalf("got %+v", ps)
	}
	lo, hi := Arity(ps)
	if lo != 2 || hi != -1 {
		t.Errorf("Arity = %d,%d", lo, hi)
	}
	lo, hi = Arity(args(t, `$A, "x"`))
	if lo != 2 || hi != 2 {
		t.Errorf("Arity = %d,%d", lo, hi)
	}
	if got := ParseConcreteArgs(`a, f(b, c), x => 1`); len(got) != 3 || got[2].Kind != Opaque {
		t.Errorf("ParseConcreteArgs = %+v", got)
	}
	if got := ParseConcreteArgs(``); len(got) != 0 {
		t.Errorf("ParseConcreteArgs(empty) = %+v", got)
	}
}

func TestHead(t *testing.T) {
	for in, want := range map[string]string{
		`A.encrypt`:            "A",
		`A.b.c.encrypt`:        "A",
		`(0, A.encrypt)`:       "A",
		`(0, _acme.default.f)`: "_acme",
		`require("m").f`:       "",
		`f`:                    "f",
		`this.x.y`:             "this",
		`a["b"].c`:             "a",
		`$`:                    "$",
		`x => y`:               "",
		``:                     "",
	} {
		if got := Head(in); got != want {
			t.Errorf("Head(%q) = %q, want %q", in, got, want)
		}
	}
}

func bindingText(b Binding) string {
	src := ""
	if b.Source != nil {
		src = b.Source.Text
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s", b.Metavar, b.Fixed, b.Imported, src, b.ModuleVar)
}

func TestParseGuard(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"import default", "import $X from \"m\"\n...", []string{`$X|||"m"|`}},
		{"import default single quote", "import $X from 'm'", []string{`$X|||"m"|`}},
		{"import namespace", "import * as $X from \"m\"\n...", []string{`$X|||"m"|`}},
		{"import named any", `import {..., $X, ...} from "m"`, []string{`$X||$|"m"|`}},
		{"import named alias", `import { a as $X } from "m"`, []string{`$X||a|"m"|`}},
		{"import named fixed", `import { a } from "m"`, []string{`|a|$|"m"|`}},
		{"import named two", `import { a, b as c } from "m"`, []string{`|a|$|"m"|`, `|c|b|"m"|`}},
		{"import any", `import {...} from "m"`, []string{`|||"m"|`}},
		{"import side effect", `import "m"`, []string{`|||"m"|`}},
		{"import default and named", `import $X, {...} from "m"`, []string{`$X|||"m"|`}},
		{"import default and named member", `import $X, {..., $Y, ...} from "m"`, []string{`$X|||"m"|`, `$Y||$|"m"|`}},
		{"import module var", `import $X from $M`, []string{`$X|||$M|$M`}},
		{"import namespace module var", `import * as $X from $M`, []string{`$X|||$M|$M`}},
		{"require deep", "$X = <... require(\"m\") ...>\n...", []string{`$X|||require("m")|`}},
		{"require plain", `$X = require("m")`, []string{`$X|||require("m")|`}},
		{"require module var", `$X = require($M)`, []string{`$X|||require($M)|$M`}},
		{"import call deep", `$X = <... import("m") ...>`, []string{`$X|||import("m")|`}},
		{"wrapper", `$X = $E("m")`, []string{`$X|||$E("m")|`}},
		{"fixed local require", `crypto2 = require("m")`, []string{`|crypto2||require("m")|`}},
		{"destructure require", `var {..., $X, ...} = require("m")`, []string{`$X||$|require("m")|`}},
		{"destructure const fixed", `const { pbkdf2 } = require("m")`, []string{`|pbkdf2|$|require("m")|`}},
		{"destructure alias", `var {a: $X} = require("m")`, []string{`$X||a|require("m")|`}},
		{"destructure await import", `var {..., a, ...} = await import("m")`, []string{`|a|$|import("m")|`}},
		{"destructure any", `var {...} = require("m")`, []string{`|||require("m")|`}},
		{"destructure keyvar", `var {..., $K: $X, ...} = $Y`, []string{`$X||$K|$Y|`}},
		{"destructure global", `const { subtle: $X } = crypto`, []string{`$X||subtle|crypto|`}},
		{"destructure member", `const { subtle } = $Y.webcrypto`, []string{`|subtle|$|$Y.webcrypto|`}},
		{"alias", `$X = $Y`, []string{`$X|||$Y|`}},
		{"alias path", `$X = $Y.a.b`, []string{`$X|||$Y.a.b|`}},
		{"alias global", `$X = crypto.subtle`, []string{`$X|||crypto.subtle|`}},
		{"alias globalThis", `$X = globalThis.crypto.subtle`, []string{`$X|||globalThis.crypto.subtle|`}},
		{"new member", `$X = new $Y.Z(...)`, []string{`$X|||new $Y.Z(...)|`}},
		{"new var", `$X = new $Y(...)`, []string{`$X|||new $Y(...)|`}},
		{"call", `$X = $Y.f(...)`, []string{`$X|||$Y.f(...)|`}},
		{"await call", `$X = await $Y.a.f(...)`, []string{`$X|||$Y.a.f(...)|`}},
		{"generic call", `$X = $F($A, ...)`, []string{`$X|||$F($A, ...)|`}},
		{"try catch", "try { ... $X = <... require(\"m\") ...>; ... } catch ($E) { ... }", []string{`$X|||require("m")|`}},
		{"try catch no binding", "try {\n  ...\n  $X = require(\"m\")\n  ...\n} catch {\n  ...\n}", []string{`$X|||require("m")|`}},
		{"try finally", "try { $X = require(\"m\") } finally { ... }", []string{`$X|||require("m")|`}},
		{"block", "{ $X = require(\"m\") }", []string{`$X|||require("m")|`}},
		{"multi statement", "$NS = require(\"m\")\n...\n$X = $NS.a\n...", []string{`$NS|||require("m")|`, `$X|||$NS.a|`}},
		{"semicolons", `$NS = require("m"); $X = $NS.a;`, []string{`$NS|||require("m")|`, `$X|||$NS.a|`}},
		{"multi-line import", "import {\n  ...,\n  $X,\n  ...\n} from \"m\"\n...", []string{`$X||$|"m"|`}},
		{"multi-line deep", "$X = <...\n  require(\"m\")\n...>", []string{`$X|||require("m")|`}},
		{"comment", "// guard\n$X = require(\"m\") // trailing", []string{`$X|||require("m")|`}},
	}
	for _, c := range cases {
		g, err := ParseGuard(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		var got []string
		for _, b := range g.Bindings {
			got = append(got, bindingText(b))
		}
		if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s: bindings\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestBindingModule(t *testing.T) {
	for in, want := range map[string]string{
		"import $X from \"m\"":                  "m",
		`$X = <... require("n") ...>`:           "n",
		`$X = $E("o")`:                          "o",
		`var {..., a, ...} = await import("p")`: "p",
		`$X = $Y.a`:                             "",
		`$X = require($M)`:                      "",
	} {
		g, err := ParseGuard(in)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := g.Bindings[0].Module()
		if got != want || ok != (want != "") {
			t.Errorf("%q: Module() = %q,%v", in, got, ok)
		}
	}
}

func TestParseGuardUnsupported(t *testing.T) {
	for _, in := range []string{
		``,
		`...`,
		"class $C {\n  ...\n}",
		"function $F() {\n  $X = require(\"m\")\n}",
		`$X.y = require("m")`,
		`f($X)`,
		`$X = `,
		`if ($X) { ... }`,
		`import $X`,
		`try { ... }`,
		`var {a: {b}} = $Y`,
		`$X = "unterminated`,
	} {
		if _, err := ParseGuard(in); !errors.Is(err, ErrUnsupported) {
			t.Errorf("ParseGuard(%q) err = %v, want ErrUnsupported", in, err)
		}
	}
}
