package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseJavaMethodWithBody(t *testing.T, body string) *FileAnalysis {
	t.Helper()
	dir := t.TempDir()
	src := "package demo;\npublic class K {\n    void f(int p, boolean b) {\n" + body + "    }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "K.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "demo")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}
	return analyses[0]
}

func initArgumentSources(t *testing.T, analysis *FileAnalysis) []SourceNode {
	t.Helper()
	for i := range analysis.Functions {
		calls := analysis.Functions[i].Calls
		for j := range calls {
			if strings.HasPrefix(calls[j].Callee.Name, "init#") && len(calls[j].ArgumentSources) == 1 {
				return calls[j].ArgumentSources[0]
			}
		}
	}
	t.Fatalf("no init(arg) call found in %#v", analysis.Functions)
	return nil
}

// TestJavaParser_ReassignedLocalHasNoSource pins that the argument tracer
// follows a local or parameter only when its declaration is its single write.
func TestJavaParser_ReassignedLocalHasNoSource(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantSource bool
	}{
		{"single write", "        int n = 256;\n        kg.init(n);\n", true},
		{"final", "        final int n = 256;\n        kg.init(n);\n", true},
		{"reassigned", "        int n = 128;\n        n = 256;\n        kg.init(n);\n", false},
		{"branch", "        int n = 128;\n        if (b) { n = 256; }\n        kg.init(n);\n", false},
		{"compound", "        int n = 128;\n        n *= 2;\n        kg.init(n);\n", false},
		{"increment", "        int n = 128;\n        n++;\n        kg.init(n);\n", false},
		{"prefix decrement", "        int n = 128;\n        --n;\n        kg.init(n);\n", false},
		{"same name written in an anonymous class", "        int n = 256;\n        Object o = new Object() { void g() { int n = 1; n = 2; n++; } };\n        kg.init(n);\n", true},
		{"parameter", "        p = 5;\n        kg.init(p);\n", false},
		{"unwritten parameter", "        kg.init(p);\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := initArgumentSources(t, parseJavaMethodWithBody(t, "        javax.crypto.KeyGenerator kg = null;\n"+tc.body))
			if len(sources) != 1 {
				t.Fatalf("sources = %#v, want one variable node", sources)
			}
			if got := len(sources[0].SourceNodes) > 0 || sources[0].Type == "PARAMETER"; got != tc.wantSource {
				t.Fatalf("has source = %v, want %v: %#v", got, tc.wantSource, sources[0])
			}
		})
	}
}

// TestJavaParser_ReassignmentScanIsOncePerMethod guards the cost of the
// reassignment index: a method with many traced arguments walks its body a
// fixed number of times, not once per argument.
func TestJavaParser_ReassignmentScanIsOncePerMethod(t *testing.T) {
	small := measureScans(t, 2)
	large := measureScans(t, 200)
	if small == 0 {
		t.Fatal("no body walk counted: the guard would be vacuous")
	}
	if small != large {
		t.Fatalf("body walks = %d for 2 arguments and %d for 200: the scan must not grow with the arguments", small, large)
	}
}

func measureScans(t *testing.T, arguments int) int64 {
	t.Helper()
	var body strings.Builder
	body.WriteString("        javax.crypto.KeyGenerator kg = null;\n        int n = 1;\n")
	for i := 0; i < arguments; i++ {
		fmt.Fprintf(&body, "        kg.init(n, %d);\n", i)
	}
	before := javaAssignmentScans.Load()
	parseJavaMethodWithBody(t, body.String())
	return javaAssignmentScans.Load() - before
}
