package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// constArgValue returns the literal the parser traced for argument index of
// the call named callee, and false when the argument carries no source.
func constArgValue(t *testing.T, analysis *FileAnalysis, callee string, index int) (string, bool) {
	t.Helper()
	for i := range analysis.Functions {
		for j := range analysis.Functions[i].Calls {
			call := &analysis.Functions[i].Calls[j]
			if call.Callee.Name != callee {
				continue
			}
			if index >= len(call.ArgumentSources) {
				return "", false
			}
			nodes := call.ArgumentSources[index]
			if len(nodes) != 1 || len(nodes[0].SourceNodes) != 1 || nodes[0].SourceNodes[0].Type != "VALUE" {
				return "", false
			}
			return nodes[0].SourceNodes[0].Value, true
		}
	}
	t.Fatalf("call %q not found", callee)
	return "", false
}

func TestGoParser_ConstArgumentSources(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
		ok   bool
	}{
		{"package const", "const bits = 3072\nfunc f() { gen(rand, bits) }", "3072", true},
		{"typed const", "const bits int = 3072\nfunc f() { gen(rand, bits) }", "3072", true},
		{"grouped const", "const (\n\tother = 1\n\tbits = 3072\n)\nfunc f() { gen(rand, bits) }", "3072", true},
		{"multi-name spec", "const a, bits = 1, 3072\nfunc f() { gen(rand, bits) }", "3072", true},
		{"declared after use", "func f() { gen(rand, bits) }\nconst bits = 2048", "2048", true},
		{"function scope const", "func f() {\n\tconst bits = 4096\n\tgen(rand, bits)\n}", "4096", true},
		{"function const shadows package const", "const bits = 1024\nfunc f() {\n\tconst bits = 4096\n\tgen(rand, bits)\n}", "4096", true},
		{"string const", "const name = \"RSA\"\nfunc f() { gen(rand, name) }", "\"RSA\"", true},
		{"local var shadows const", "const bits = 3072\nfunc f() {\n\tbits := compute()\n\tgen(rand, bits)\n}", "", false},
		{"local var decl shadows const", "const bits = 3072\nfunc f() {\n\tvar bits = compute()\n\tgen(rand, bits)\n}", "", false},
		{"parameter shadows const", "const bits = 3072\nfunc f(bits int) { gen(rand, bits) }", "", false},
		{"range var shadows const", "const bits = 3072\nfunc f(xs []int) {\n\tfor _, bits := range xs {\n\t\tgen(rand, bits)\n\t}\n}", "", false},
		{"shadow in sibling scope does not leak", "const bits = 3072\nfunc f() {\n\t{\n\t\tbits := 1\n\t\t_ = bits\n\t}\n\tgen(rand, bits)\n}", "3072", true},
		{"local const declared after use does not apply", "const bits = 3072\nfunc f() {\n\tgen(rand, bits)\n\tconst bits = 1\n}", "3072", true},
		{"iota yields nothing", "const (\n\tbits = iota\n)\nfunc f() { gen(rand, bits) }", "", false},
		{"implicit repetition yields nothing", "const (\n\ta = 1024\n\tbits\n)\nfunc f() { gen(rand, bits) }", "", false},
		{"expression yields nothing", "const bits = 3 * 1024\nfunc f() { gen(rand, bits) }", "", false},
		{"hex yields nothing", "const bits = 0xC00\nfunc f() { gen(rand, bits) }", "", false},
		{"var is not a const", "var bits = 3072\nfunc f() { gen(rand, bits) }", "", false},
		{"for clause := shadows const", "const bits = 3072\nfunc f() {\n\tfor bits := 0; bits < 2; bits++ {\n\t\tgen(rand, bits)\n\t}\n}", "", false},
		{"for clause := shadows in the body", "const bits = 3072\nfunc f() {\n\tfor bits := 0; ; {\n\t\tgen(rand, bits)\n\t}\n}", "", false},
		{"select receive := shadows const", "const bits = 3072\nfunc f(c chan int) {\n\tselect {\n\tcase bits := <-c:\n\t\tgen(rand, bits)\n\t}\n}", "", false},
		{"select receive = does not shadow", "const bits = 3072\nfunc f(c chan int) {\n\tvar v int\n\tselect {\n\tcase v = <-c:\n\t\tgen(rand, bits)\n\t}\n}", "3072", true},
		{"labeled := shadows const", "const bits = 3072\nfunc f() {\nL:\n\tbits := 1\n\tgen(rand, bits)\n\tgoto L\n}", "", false},
		{"variadic parameter shadows const", "const bits = 3072\nfunc f(bits ...int) { gen(rand, bits) }", "", false},
		{"func literal parameter shadows const", "const bits = 3072\nfunc f() {\n\th := func(bits int) { gen(rand, bits) }\n\t_ = h\n}", "", false},
		{"type switch alias shadows const", "const bits = 3072\nfunc f(x any) {\n\tswitch bits := x.(type) {\n\tcase int:\n\t\tgen(rand, bits)\n\t}\n}", "", false},
		{"if init shadows const", "const bits = 3072\nfunc f() {\n\tif bits := compute(); bits > 0 {\n\t\tgen(rand, bits)\n\t}\n}", "", false},
		{"float typed const", "const bits float64 = 2\nfunc f() { gen(rand, bits) }", "", false},
		{"named type const", "type B int\nconst bits B = 2\nfunc f() { gen(rand, bits) }", "", false},
		{"integer typed const", "const bits uint16 = 3072\nfunc f() { gen(rand, bits) }", "3072", true},
		{"unknown identifier", "func f() { gen(rand, bits) }", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "main.go")
			src := "package main\n\n" + tt.src + "\n"
			if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			analysis, err := NewGoParser().ParseFile(file, "example/main")
			if err != nil {
				t.Fatal(err)
			}
			got, ok := constArgValue(t, analysis, "gen", 1)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("argument 1 = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
			if _, ok := constArgValue(t, analysis, "gen", 0); ok {
				t.Fatal("argument 0 (rand) must not resolve")
			}
		})
	}
}

func TestCParser_DefineArgumentSources(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
		ok   bool
	}{
		{"object-like define", "#define BITS 4096\nvoid f(void) { gen(ctx, BITS); }", "4096", true},
		{"parenthesized with suffix and comment", "#define BITS (4096U) /* RSA modulus */\nvoid f(void) { gen(ctx, BITS); }", "4096", true},
		{"string define", "#define NAME \"RSA\"\nvoid f(void) { gen(ctx, NAME); }", "\"RSA\"", true},
		{"define inside a function body", "void f(void) {\n#define BITS 3072\n gen(ctx, BITS); }", "3072", true},
		{"ifdef block", "#ifdef BIG\n#define BITS 4096\n#endif\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"ifndef default is overridable", "#ifndef BITS\n#define BITS 2048\n#endif\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"dead #if 0", "#if 0\n#define BITS 2048\n#endif\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"nested under #else", "#if X\n#else\n#define BITS 2048\n#endif\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"include guarded file", "#ifndef CFG_H\n#define CFG_H\n#define BITS 4096\nvoid f(void) { gen(ctx, BITS); }\n#endif", "4096", true},
		{"include guard with leading comment", "/* cfg */\n#ifndef CFG_H\n#define CFG_H\n#define BITS 4096\nvoid f(void) { gen(ctx, BITS); }\n#endif", "4096", true},
		{"conditional inside an include guard", "#ifndef CFG_H\n#define CFG_H\n#ifndef BITS\n#define BITS 2048\n#endif\nvoid f(void) { gen(ctx, BITS); }\n#endif", "", false},
		{"guard with other top-level code is not a file guard", "int x;\n#ifndef BITS\n#define BITS 2048\n#endif\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"function-like macro", "#define BITS(x) 4096\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"function-like call is not an argument identifier", "#define BITS(x) 4096\nvoid f(void) { gen(ctx, BITS(1)); }", "", false},
		{"defined twice under ifdef", "#ifdef BIG\n#define BITS 4096\n#else\n#define BITS 2048\n#endif\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"defined then redefined as function-like", "#define BITS 4096\n#undef BITS\n#define BITS(x) 2048\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"undef after definition", "#define BITS 4096\n#undef BITS\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"defined after the call", "void f(void) { gen(ctx, BITS); }\n#define BITS 4096\n", "", false},
		{"expression replacement", "#define BITS (1 << 12)\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"hex replacement", "#define BITS 0x1000\nvoid f(void) { gen(ctx, BITS); }", "", false},
		{"aliased macro", "#define BITS OTHER\nvoid f(void) { gen(ctx, BITS); }", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "a.c"), []byte(tt.src+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			analyses, err := NewCParser().ParseDirectory(dir, "example/c")
			if err != nil || len(analyses) != 1 {
				t.Fatalf("ParseDirectory = %d analyses, err %v", len(analyses), err)
			}
			got, ok := constArgValue(t, analyses[0], "gen", 1)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("argument 1 = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

// TestGoParser_ConstLookupScalesLinearly pins the cost of resolving identifier
// arguments in one function with thousands of statements, package consts and
// calls. Rescanning every enclosing scope per argument took minutes here.
func TestGoParser_ConstLookupScalesLinearly(t *testing.T) {
	const n = 2000
	var b strings.Builder
	b.WriteString("package main\n\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "const c%d = %d\n", i, i+1)
	}
	b.WriteString("\nfunc f() {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\tx%d := %d\n\tgen(rand, c%d)\n", i, i, i)
	}
	b.WriteString("}\n")
	file := filepath.Join(t.TempDir(), "big.go")
	if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	analysis, err := NewGoParser().ParseFile(file, "example/main")
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	resolved := 0
	for _, call := range analysis.Functions[0].Calls {
		if call.Callee.Name == "gen" && len(call.ArgumentSources) == 2 && len(call.ArgumentSources[1]) == 1 {
			resolved++
		}
	}
	if resolved != n {
		t.Fatalf("resolved %d of %d const arguments", resolved, n)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("parsing took %s, want near-linear time", elapsed)
	}
	t.Logf("parsed %d consts and %d calls in %s", n, n, elapsed)
}
