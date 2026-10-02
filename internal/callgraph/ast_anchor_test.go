// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	treec "github.com/smacker/go-tree-sitter/c"
	treecpp "github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// referenceNamedASTPath is the original per-call anchor walk: it scans every
// named child of every ancestor through NamedChild for each call. It is
// quadratic but it defines the anchor strings that occurrence keys and chain
// identity were built on, so the indexed walk must reproduce it byte for byte.
func referenceNamedASTPath(node *sitter.Node) string {
	var parts []string
	for current, parent := node, node.Parent(); current != nil && parent != nil; current, parent = parent, parent.Parent() {
		index := referenceNamedChildIndex(parent, current)
		if index < 0 {
			return ""
		}
		parts = append(parts, fmt.Sprintf("%s[%d]", current.Type(), index))
		if isFunctionContainer(parent.Type()) {
			for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
				parts[left], parts[right] = parts[right], parts[left]
			}
			return strings.Join(parts, "/")
		}
	}
	return ""
}

func referenceNamedChildIndex(parent, child *sitter.Node) int {
	index := 0
	for i := 0; i < int(parent.NamedChildCount()); i++ {
		namedChild := parent.NamedChild(i)
		if strings.Contains(namedChild.Type(), "comment") {
			continue
		}
		if namedChild.Equal(child) {
			return index
		}
		index++
	}
	return -1
}

var anchorGrammars = map[string]*sitter.Language{
	".go":   golang.GetLanguage(),
	".py":   python.GetLanguage(),
	".js":   javascript.GetLanguage(),
	".ts":   typescript.GetLanguage(),
	".tsx":  tsx.GetLanguage(),
	".java": java.GetLanguage(),
	".c":    treec.GetLanguage(),
	".h":    treec.GetLanguage(),
	".cpp":  treecpp.GetLanguage(),
	".rs":   rust.GetLanguage(),
}

// anchorInlineCorpus covers shapes the fixture files may not: comments
// between siblings (skipped by the index), syntax errors, nested function
// containers and calls outside any function.
var anchorInlineCorpus = map[string]string{
	"comments.go": "package p\n\n// c\nvar a = f() // c\n\nfunc g() {\n\t// c\n\tf()\n\t/* c */ h(f())\n\tx := func() { f() }\n\t_ = x\n}\n",
	"broken.go":   "package p\n\nfunc g() {\n\tf(\n\th()\n}\n\nfunc k() { f() }\n",
	"module.py":   "# c\nimport os\nos.getenv('A')  # c\n\nclass K:\n    # c\n    x = f()\n    def m(self):\n        return [g(i) for i in h()]\n\nlambda: f()\n",
	"top.js":      "// c\nf();\nconst a = () => { /* c */ g(); return h(f()); };\nfunction k() { return function () { f(); }; }\nclass C { m() { f(); } }\n",
	"clinit.java": "class A {\n  // c\n  static final int X = f();\n  static { g(); /* c */ h(); }\n  int m() { return f(g()); }\n  Runnable r = () -> f();\n}\n",
	"init.c":      "int f(int);\nint g = 1;\n/* c */\nint h(void) { return f(f(g)); }\n",
	"lib.rs":      "// c\nstatic X: i32 = 0;\nfn f() -> i32 { g(); let c = || h(); c() }\nimpl S { fn m(&self) { self.f(); } }\n",
}

func TestCallAnchorsMatchReferenceWalk(t *testing.T) {
	sources := map[string][]byte{}
	for name, src := range anchorInlineCorpus {
		sources["inline/"+name] = []byte(src)
	}
	for _, root := range []string{"testdata", "../../testdata", "../scan/testdata", "../../pkg/graphfrag/testdata", "."} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if root == "." && path != "." {
					return filepath.SkipDir
				}
				return nil
			}
			if anchorGrammars[filepath.Ext(path)] == nil {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// This package's own sources add real-world Go shapes; the
			// largest are skipped because the reference walk is quadratic.
			if root == "." && len(src) > 8<<10 {
				return nil
			}
			sources[path] = src
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	nodes, anchored := 0, 0
	languages := map[string]bool{}
	for path, src := range sources {
		ext := filepath.Ext(path)
		languages[ext] = true
		parser := sitter.NewParser()
		parser.SetLanguage(anchorGrammars[ext])
		tree, err := parser.ParseCtx(context.Background(), nil, src)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		var anchors callAnchors
		var visit func(*sitter.Node)
		visit = func(node *sitter.Node) {
			nodes++
			want := referenceNamedASTPath(node)
			if got := anchors.namedASTPath(node); got != want {
				t.Errorf("%s: %s at %d:%d anchor = %q, want %q", path, node.Type(), node.StartPoint().Row+1, node.StartPoint().Column+1, got, want)
			}
			if want != "" {
				anchored++
			}
			for i := 0; i < int(node.ChildCount()); i++ {
				visit(node.Child(i))
			}
		}
		visit(tree.RootNode())
		tree.Close()
	}
	t.Logf("%d files, %d nodes, %d with an anchor", len(sources), nodes, anchored)
	for ext := range anchorGrammars {
		if !languages[ext] {
			t.Errorf("corpus has no %s file", ext)
		}
	}
	if anchored == 0 || anchored == nodes {
		t.Fatalf("corpus must hold both anchored and unanchored nodes: %d of %d anchored", anchored, nodes)
	}
}
