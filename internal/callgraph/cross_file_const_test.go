package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func analysisFor(t *testing.T, analyses []*FileAnalysis, dir, name string) *FileAnalysis {
	t.Helper()
	for _, a := range analyses {
		if a.FilePath == filepath.Join(dir, name) {
			return a
		}
	}
	t.Fatalf("no analysis for %s", name)
	return nil
}

const goUse = "package main\n\nfunc f() { gen(rand, bits) }\n"

func TestGoParser_CrossFileConstArgumentSources(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		tests bool
		use   string
		want  string
		ok    bool
	}{
		{"const in a sibling file", map[string]string{"use.go": goUse, "c.go": "package main\n\nconst bits = 3072\n"}, false, "use.go", "3072", true},
		{"typed const in a grouped sibling", map[string]string{"use.go": goUse, "c.go": "package main\n\nconst (\n\ta = 1\n\tbits uint16 = 2048\n)\n"}, false, "use.go", "2048", true},
		{"string const", map[string]string{"use.go": goUse, "c.go": "package main\n\nconst bits = \"RSA\"\n"}, false, "use.go", "\"RSA\"", true},
		{"other package clause in the directory", map[string]string{"use.go": goUse, "c.go": "package other\n\nconst bits = 3072\n"}, false, "use.go", "", false},
		{"same const in two files", map[string]string{"use.go": goUse, "a.go": "package main\n\nconst bits = 1\n", "b.go": "package main\n\nconst bits = 2\n"}, false, "use.go", "", false},
		{"const per build tag", map[string]string{"use.go": goUse, "a.go": "//go:build linux\n\npackage main\n\nconst bits = 1024\n", "b.go": "//go:build !linux\n\npackage main\n\nconst bits = 4096\n"}, false, "use.go", "", false},
		{"sole const behind a build tag", map[string]string{"use.go": goUse, "a.go": "//go:build linux\n\npackage main\n\nconst bits = 1024\n"}, false, "use.go", "", false},
		{"sole const behind a legacy build tag", map[string]string{"use.go": goUse, "a.go": "// +build linux\n\npackage main\n\nconst bits = 1024\n"}, false, "use.go", "", false},
		{"sole const in a GOOS-suffixed file", map[string]string{"use.go": goUse, "a_linux.go": "package main\n\nconst bits = 1024\n"}, false, "use.go", "", false},
		{"sole const in a GOOS_GOARCH file", map[string]string{"use.go": goUse, "a_linux_arm64.go": "package main\n\nconst bits = 1024\n"}, false, "use.go", "", false},
		{"unconstrained name that merely ends in a word", map[string]string{"use.go": goUse, "c_config.go": "package main\n\nconst bits = 1024\n"}, false, "use.go", "1024", true},
		{"var of the same name in another file", map[string]string{"use.go": goUse, "a.go": "package main\n\nconst bits = 1\n", "b.go": "package main\n\nvar bits = 2\n"}, false, "use.go", "", false},
		{"func of the same name in another file", map[string]string{"use.go": goUse, "a.go": "package main\n\nconst bits = 1\n", "b.go": "package main\n\nfunc bits() int { return 2 }\n"}, false, "use.go", "", false},
		{"type of the same name in another file", map[string]string{"use.go": goUse, "a.go": "package main\n\nconst bits = 1\n", "b.go": "package main\n\ntype bits int\n"}, false, "use.go", "", false},
		{"sibling var is not a const", map[string]string{"use.go": goUse, "a.go": "package main\n\nvar bits = 1\n"}, false, "use.go", "", false},
		{"sibling iota", map[string]string{"use.go": goUse, "a.go": "package main\n\nconst bits = iota\n"}, false, "use.go", "", false},
		{"sibling expression", map[string]string{"use.go": goUse, "a.go": "package main\n\nconst bits = 3 * 1024\n"}, false, "use.go", "", false},
		{"local var shadows a sibling const", map[string]string{"use.go": "package main\n\nfunc f() {\n\tbits := compute()\n\tgen(rand, bits)\n}\n", "a.go": "package main\n\nconst bits = 3072\n"}, false, "use.go", "", false},
		{"parameter shadows a sibling const", map[string]string{"use.go": "package main\n\nfunc f(bits int) { gen(rand, bits) }\n", "a.go": "package main\n\nconst bits = 3072\n"}, false, "use.go", "", false},
		{"local const shadows a sibling const", map[string]string{"use.go": "package main\n\nfunc f() {\n\tconst bits = 1\n\tgen(rand, bits)\n}\n", "a.go": "package main\n\nconst bits = 3072\n"}, false, "use.go", "1", true},
		{"same-file const beats nothing else", map[string]string{"use.go": "package main\n\nconst bits = 2048\nfunc f() { gen(rand, bits) }\n"}, false, "use.go", "2048", true},
		{"test-file const is invisible to a non-test file", map[string]string{"use.go": goUse, "a_test.go": "package main\n\nconst bits = 3072\n"}, true, "use.go", "", false},
		{"test file sees a non-test const", map[string]string{"use_test.go": goUse, "a.go": "package main\n\nconst bits = 3072\n"}, true, "use_test.go", "3072", true},
		{"test file sees a test const", map[string]string{"use_test.go": goUse, "a_test.go": "package main\n\nconst bits = 3072\n"}, true, "use_test.go", "3072", true},
		{"test file const colliding with a non-test const", map[string]string{"use_test.go": goUse, "a_test.go": "package main\n\nconst bits = 1\n", "a.go": "package main\n\nconst bits = 2\n"}, true, "use_test.go", "", false},
		{"non-test use ignores a colliding test declaration", map[string]string{"use.go": goUse, "a_test.go": "package main\n\nvar bits = 1\n", "a.go": "package main\n\nconst bits = 2\n"}, true, "use.go", "2", true},
		{"nil is not a const", map[string]string{"use.go": "package main\n\nfunc f() { gen(rand, nil) }\n", "a.go": "package main\n\nconst nil = 1\n"}, false, "use.go", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			analyses, err := NewGoParser(WithIncludeTests(tt.tests)).ParseDirectory(dir, "example/main")
			if err != nil {
				t.Fatal(err)
			}
			got, ok := constArgValue(t, analysisFor(t, analyses, dir, tt.use), 1)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("argument 1 = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestCParser_CrossFileDefineArgumentSources(t *testing.T) {
	use := func(body string) string { return body + "void f(void) { gen(ctx, BITS); }\n" }
	guarded := "#ifndef B_H\n#define B_H\n#define BITS 4096\n#endif\n"
	tests := []struct {
		name  string
		files map[string]string
		want  string
		ok    bool
	}{
		{"quoted header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#define BITS 4096\n"}, "4096", true},
		{"guarded header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": guarded}, "4096", true},
		{"header in a subdirectory", map[string]string{"a.c": use("#include \"inc/b.h\"\n"), "inc/b.h": "#define BITS 2048\n"}, "2048", true},
		{"string define", map[string]string{"a.c": "#include \"b.h\"\nvoid f(void) { gen(ctx, BITS); }\n", "b.h": "#define BITS \"RSA\"\n"}, "\"RSA\"", true},
		{"system include is out", map[string]string{"a.c": use("#include <b.h>\n"), "b.h": "#define BITS 4096\n"}, "", false},
		{"include that resolves to nothing", map[string]string{"a.c": use("#include \"missing.h\"\n")}, "", false},
		{"include below the call", map[string]string{"a.c": "void f(void) { gen(ctx, BITS); }\n#include \"b.h\"\n", "b.h": "#define BITS 4096\n"}, "", false},
		{"conditional define in the header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#ifdef BIG\n#define BITS 4096\n#endif\n"}, "", false},
		{"ifndef default in the header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#ifndef BITS\n#define BITS 2048\n#endif\n"}, "", false},
		{"redefined in the header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#define BITS 4096\n#define BITS 2048\n"}, "", false},
		{"undef in the header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#define BITS 4096\n#undef BITS\n"}, "", false},
		{"function-like in the header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#define BITS(x) 4096\n"}, "", false},
		{"expression in the header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#define BITS (1 << 12)\n"}, "", false},
		{"defined in two headers", map[string]string{"a.c": use("#include \"b.h\"\n#include \"c.h\"\n"), "b.h": "#define BITS 4096\n", "c.h": "#define BITS 4096\n"}, "", false},
		{"defined in one header, conditionally in another", map[string]string{"a.c": use("#include \"b.h\"\n#include \"c.h\"\n"), "b.h": "#define BITS 4096\n", "c.h": "#ifdef X\n#define BITS 1024\n#endif\n"}, "", false},
		{"one header reached twice", map[string]string{"a.c": use("#include \"b.h\"\n#include \"c.h\"\n"), "b.h": "#define BITS 4096\n", "c.h": "#include \"b.h\"\n"}, "4096", true},
		{"nested header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#include \"c.h\"\n", "c.h": "#define BITS 3072\n"}, "3072", true},
		{"nested header relative to its includer", map[string]string{"a.c": use("#include \"inc/b.h\"\n"), "inc/b.h": "#include \"c.h\"\n", "inc/c.h": "#define BITS 3072\n"}, "3072", true},
		{"include cycle", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#include \"c.h\"\n#define BITS 3072\n", "c.h": "#include \"b.h\"\n"}, "3072", true},
		{"include chain deeper than the bound", map[string]string{
			"a.c": use("#include \"h1.h\"\n"), "h1.h": "#include \"h2.h\"\n", "h2.h": "#include \"h3.h\"\n", "h3.h": "#include \"h4.h\"\n",
			"h4.h": "#include \"h5.h\"\n", "h5.h": "#include \"h6.h\"\n", "h6.h": "#include \"h7.h\"\n", "h7.h": "#include \"h8.h\"\n",
			"h8.h": "#include \"h9.h\"\n", "h9.h": "#define BITS 3072\n",
		}, "", false},
		{"conditional include", map[string]string{"a.c": use("#ifdef X\n#include \"b.h\"\n#endif\n"), "b.h": "#define BITS 4096\n"}, "", false},
		{"header included conditionally by another header", map[string]string{"a.c": use("#include \"b.h\"\n"), "b.h": "#ifdef X\n#include \"c.h\"\n#endif\n", "c.h": "#define BITS 4096\n"}, "", false},
		{"redefined in the including file before the call", map[string]string{"a.c": use("#include \"b.h\"\n#undef BITS\n#define BITS 1024\n"), "b.h": "#define BITS 4096\n"}, "", false},
		{"undef'd in the including file before the call", map[string]string{"a.c": use("#include \"b.h\"\n#undef BITS\n"), "b.h": "#define BITS 4096\n"}, "", false},
		{"defined in the including file before the include", map[string]string{"a.c": use("#define BITS 1024\n#include \"b.h\"\n"), "b.h": "#define BITS 4096\n"}, "", false},
		{"redefined in the including file after the call", map[string]string{"a.c": "#include \"b.h\"\nvoid f(void) { gen(ctx, BITS); }\n#undef BITS\n#define BITS 1024\n", "b.h": "#define BITS 4096\n"}, "4096", true},
		{"own define unaffected by an unrelated header", map[string]string{"a.c": use("#include \"b.h\"\n#define BITS 1024\n"), "b.h": "#define OTHER 4096\n"}, "1024", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			analyses, err := NewCParser().ParseDirectory(dir, "example/c")
			if err != nil {
				t.Fatal(err)
			}
			got, ok := constArgValue(t, analysisFor(t, analyses, dir, "a.c"), 1)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("argument 1 = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

// TestGoParser_CrossFileConstScalesLinearly pins that resolving a const
// declared in a sibling file builds the package index once per directory, not
// once per file or per argument.
func TestGoParser_CrossFileConstScalesLinearly(t *testing.T) {
	const files = 400
	tree := map[string]string{}
	var consts strings.Builder
	consts.WriteString("package main\n\n")
	for i := 0; i < files; i++ {
		fmt.Fprintf(&consts, "const c%d = %d\n", i, i+1)
		tree[fmt.Sprintf("u%d.go", i)] = fmt.Sprintf("package main\n\nfunc f%d() { gen(rand, c%d) }\n", i, i)
	}
	tree["consts.go"] = consts.String()
	dir := writeTree(t, tree)

	start := time.Now()
	analyses, err := NewGoParser().ParseDirectory(dir, "example/main")
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	resolved := 0
	for _, a := range analyses {
		if resolvesGen(a) {
			resolved++
		}
	}
	if resolved != files {
		t.Fatalf("resolved %d of %d cross-file const arguments", resolved, files)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("parsing took %s, want near-linear time", elapsed)
	}
	t.Logf("resolved %d cross-file consts in %s", files, elapsed)
}

func resolvesGen(a *FileAnalysis) bool {
	for i := range a.Functions {
		for j := range a.Functions[i].Calls {
			call := &a.Functions[i].Calls[j]
			if call.Callee.Name == "gen" && len(call.ArgumentSources) == 2 && len(call.ArgumentSources[1]) == 1 {
				return true
			}
		}
	}
	return false
}

// TestCParser_CrossFileDefineScalesLinearly pins that a header shared by many
// files is parsed once and that resolution costs a header lookup, not a rescan.
func TestCParser_CrossFileDefineScalesLinearly(t *testing.T) {
	const files = 400
	tree := map[string]string{}
	var header strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&header, "#define H%d %d\n", i, i+1)
	}
	tree["all.h"] = header.String()
	for i := 0; i < files; i++ {
		tree[fmt.Sprintf("u%d.c", i)] = fmt.Sprintf("#include \"all.h\"\nvoid f%d(void) { gen(ctx, H%d); }\n", i, i)
	}
	dir := writeTree(t, tree)

	start := time.Now()
	analyses, err := NewCParser().ParseDirectory(dir, "example/c")
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	resolved := 0
	for _, a := range analyses {
		if resolvesGen(a) {
			resolved++
		}
	}
	if resolved != files {
		t.Fatalf("resolved %d of %d header define arguments", resolved, files)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("parsing took %s, want near-linear time", elapsed)
	}
	t.Logf("resolved %d header defines in %s", files, elapsed)
}
