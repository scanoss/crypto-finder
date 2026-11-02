// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strconv"
	"strings"
	"testing"
)

// rustMacroTestFunction is the function whose calls the macro tests inspect.
const rustMacroTestFunction = "main"

// parseRustMainCalls parses one main.rs into package "app" and returns the
// calls of its function main.
func parseRustMainCalls(t *testing.T, src string) []FunctionCall {
	t.Helper()
	dir := t.TempDir()
	writeRustTestFile(t, dir, src)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			if analysis.Functions[i].ID.Name == rustMacroTestFunction {
				return analysis.Functions[i].Calls
			}
		}
	}
	t.Fatal("function main not found")
	return nil
}

func findRustCall(calls []FunctionCall, key string) *FunctionCall {
	for i := range calls {
		if calls[i].Callee.String() == key {
			return &calls[i]
		}
	}
	return nil
}

func rustCallKeys(calls []FunctionCall) []string {
	keys := make([]string, 0, len(calls))
	for i := range calls {
		keys = append(keys, calls[i].Callee.String())
	}
	return keys
}

// A call written inside a formatting macro's arguments is evaluated by the
// enclosing function, so it is an edge from that function. Tree-sitter leaves
// macro arguments as an opaque token tree, and the parser used to drop them,
// which made `println!("{:?}", fingerprint(data))` the only caller of
// `fingerprint` and still left it unreachable.
func TestRustMacroArgs_CallInsidePrintlnIsAnEdgeWithPosition(t *testing.T) {
	src := "fn main() {\n" +
		"    let data = b\"x\";\n" +
		"    println!(\"{:?}\", fingerprint(data));\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	call := findRustCall(calls, "app.fingerprint")
	if call == nil {
		t.Fatalf("no edge main -> app.fingerprint; calls = %v", rustCallKeys(calls))
	}
	// `    println!("{:?}", fingerprint(data));`: `fingerprint` starts at
	// 0-based column 21, and the call ends after `)` at 0-based column 38.
	// FunctionCall columns are 1-based, end exclusive.
	if call.Line != 3 || call.StartCol != 22 || call.EndCol != 39 {
		t.Errorf("position = line %d cols [%d,%d), want line 3 cols [22,39)", call.Line, call.StartCol, call.EndCol)
	}
	if call.Raw != "fingerprint" {
		t.Errorf("Raw = %q, want %q", call.Raw, "fingerprint")
	}
	if len(call.Arguments) != 1 || call.Arguments[0] != "data" {
		t.Errorf("Arguments = %v, want [data]", call.Arguments)
	}
}

// A macro spanning several lines keeps each inner call on its own line.
func TestRustMacroArgs_MultiLineMacroKeepsLines(t *testing.T) {
	src := "fn main() {\n" +
		"    println!(\n" +
		"        \"{} {}\",\n" +
		"        first(a),\n" +
		"        second(b),\n" +
		"    );\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	for key, want := range map[string][3]int{"app.first": {4, 9, 17}, "app.second": {5, 9, 18}} {
		call := findRustCall(calls, key)
		if call == nil {
			t.Fatalf("no edge main -> %s; calls = %v", key, rustCallKeys(calls))
		}
		if got := [3]int{call.Line, call.StartCol, call.EndCol}; got != want {
			t.Errorf("%s position = %v, want %v", key, got, want)
		}
	}
}

func TestRustMacroArgs_NestedMacros(t *testing.T) {
	src := "fn main() {\n" +
		"    println!(\"{}\", format!(\"{}\", g(x)));\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	call := findRustCall(calls, "app.g")
	if call == nil {
		t.Fatalf("no edge main -> app.g; calls = %v", rustCallKeys(calls))
	}
	// `    println!("{}", format!("{}", g(x)));` puts `g` at 0-based col 33.
	if call.Line != 2 || call.StartCol != 34 || call.EndCol != 38 {
		t.Errorf("position = line %d cols [%d,%d), want line 2 cols [34,38)", call.Line, call.StartCol, call.EndCol)
	}
}

// A path call inside a macro resolves through the file's imports exactly as
// the same call outside a macro does.
func TestRustMacroArgs_PathCallResolvesLikeOutsideTheMacro(t *testing.T) {
	src := "use sha2::Digest;\n" +
		"fn main() {\n" +
		"    let y = 1;\n" +
		"    println!(\"{:?}\", crate_x::h(y));\n" +
		"    assert_eq!(sha2::Sha256::digest(b\"a\"), expected());\n" +
		"}\n"
	outside := "use sha2::Digest;\n" +
		"fn main() {\n" +
		"    let y = 1;\n" +
		"    let a = crate_x::h(y);\n" +
		"    let b = sha2::Sha256::digest(b\"a\");\n" +
		"    let c = expected();\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	baseline := parseRustMainCalls(t, outside)
	for _, key := range []string{"crate_x.h", "sha2.(Sha256).digest", "app.expected"} {
		if findRustCall(baseline, key) == nil {
			t.Fatalf("baseline outside a macro has no %s; calls = %v", key, rustCallKeys(baseline))
		}
		if findRustCall(calls, key) == nil {
			t.Errorf("no edge main -> %s; calls = %v", key, rustCallKeys(calls))
		}
	}
}

// A method call inside `assert!` resolves its receiver through the bindings in
// scope at the macro, and keeps the receiver variable for lifecycle recovery.
func TestRustMacroArgs_MethodCallInsideAssertUsesScopeBindings(t *testing.T) {
	src := "use aes_gcm::Aes256Gcm;\n" +
		"fn main() {\n" +
		"    let obj: Aes256Gcm = make();\n" +
		"    let z = 1;\n" +
		"    assert!(obj.m(z));\n" +
		"    debug_assert_ne!(obj.n(z), 0);\n" +
		"}\n"
	outside := "use aes_gcm::Aes256Gcm;\n" +
		"fn main() {\n" +
		"    let obj: Aes256Gcm = make();\n" +
		"    let z = 1;\n" +
		"    let a = obj.m(z);\n" +
		"    let b = obj.n(z);\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	baseline := parseRustMainCalls(t, outside)
	for _, key := range []string{"aes_gcm.(Aes256Gcm).m", "aes_gcm.(Aes256Gcm).n"} {
		if findRustCall(baseline, key) == nil {
			t.Fatalf("baseline outside a macro has no %s; calls = %v", key, rustCallKeys(baseline))
		}
		call := findRustCall(calls, key)
		if call == nil {
			t.Errorf("no edge main -> %s; calls = %v", key, rustCallKeys(calls))
			continue
		}
		if call.ReceiverVar != "obj" {
			t.Errorf("%s ReceiverVar = %q, want obj", key, call.ReceiverVar)
		}
	}
}

// The std expression macros all evaluate their arguments.
func TestRustMacroArgs_StdExpressionMacros(t *testing.T) {
	src := "use std::fmt::Write;\n" +
		"fn main() {\n" +
		"    let mut s = String::new();\n" +
		"    print!(\"{}\", c1());\n" +
		"    eprintln!(\"{}\", c2());\n" +
		"    eprint!(\"{}\", c3());\n" +
		"    write!(s, \"{}\", c4()).unwrap();\n" +
		"    writeln!(s, \"{}\", c5()).unwrap();\n" +
		"    let v = vec![c6(), c7()];\n" +
		"    dbg!(c8());\n" +
		"    debug_assert!(c9());\n" +
		"    debug_assert_eq!(c10(), 1);\n" +
		"    assert_ne!(c11(), 2);\n" +
		"    if v.is_empty() { panic!(\"{}\", c12()); }\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	for i := 1; i <= 12; i++ {
		key := "app.c" + strconv.Itoa(i)
		if findRustCall(calls, key) == nil {
			t.Errorf("no edge main -> %s; calls = %v", key, rustCallKeys(calls))
		}
	}
}

// Macro bodies that are not an expression list must neither crash the parser
// nor invent edges: a `macro_rules!` definition is a template, a
// `select!`-style body is a DSL, and `stringify!` never evaluates its tokens.
func TestRustMacroArgs_NonExpressionBodiesInventNoEdges(t *testing.T) {
	src := "macro_rules! twice {\n" +
		"    ($e:expr) => { tmpl_a($e); tmpl_a($e) };\n" +
		"}\n" +
		"fn main() {\n" +
		"    macro_rules! local { () => { tmpl_b() }; }\n" +
		"    tokio::select! {\n" +
		"        v = rx.recv() => sel_a(v),\n" +
		"        _ = sleep() => sel_b(),\n" +
		"    }\n" +
		"    let s = stringify!(str_a(x));\n" +
		"    tracing::info!(field = %bad_a(x), \"msg\");\n" +
		"    weird!(=> bad_b(x) <=);\n" +
		"    quote::quote!(quoted(x));\n" +
		"    real();\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	keys := rustCallKeys(calls)
	for _, key := range keys {
		for _, bad := range []string{"tmpl_", "sel_", "str_a", "bad_", "quoted"} {
			if strings.Contains(key, bad) {
				t.Errorf("invented edge main -> %s; calls = %v", key, keys)
			}
		}
	}
	if findRustCall(calls, "app.real") == nil {
		t.Errorf("no edge main -> app.real; calls = %v", keys)
	}
}

// A call already outside any macro is reported once, not once more by the
// macro walk; and the same call inside and outside a macro produce two edges.
func TestRustMacroArgs_NoDuplicateEdges(t *testing.T) {
	src := "fn main() {\n" +
		"    let d = f(x);\n" +
		"    println!(\"{:?} {:?}\", d, f(y));\n" +
		"}\n"
	calls := parseRustMainCalls(t, src)
	n := 0
	for _, key := range rustCallKeys(calls) {
		if key == "app.f" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("app.f edges = %d, want 2; calls = %v", n, rustCallKeys(calls))
	}
}
