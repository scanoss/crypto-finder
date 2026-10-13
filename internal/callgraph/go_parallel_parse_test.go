// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// serialSelectiveParser is serialOnlyParser for the Go parser that keeps
// every optional interface but cloning and file splitting: it still reads only
// a package's listed files, skips the directories the go tool skips and names
// nested modules, so both paths walk the same files.
type serialSelectiveParser struct {
	serialOnlyParser
	selective SelectiveParser
}

func (s *serialSelectiveParser) SkipsDirNamed(name string) bool {
	return s.inner.(*GoParser).SkipsDirNamed(name)
}

func (s *serialSelectiveParser) NestedModulePath(dir string) string {
	return s.inner.(*GoParser).NestedModulePath(dir)
}

func (s *serialSelectiveParser) ParseDirectorySelected(dir, packagePath string, keep func(path string) bool) ([]*FileAnalysis, error) {
	return s.selective.ParseDirectorySelected(dir, packagePath, keep)
}

// fullGraphDump renders every declaration of graph, with its calls, implicit
// calls and entry facts, plus canonicalGraphDump's caller and edge indexes.
func fullGraphDump(t *testing.T, graph *CallGraph) string {
	t.Helper()
	keys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		encoded, err := json.Marshal(graph.Functions[key])
		if err != nil {
			t.Fatalf("marshal %s: %v", key, err)
		}
		fmt.Fprintf(&b, "FN %s %s\n", key, encoded)
	}
	b.WriteString(canonicalGraphDump(graph))
	return b.String()
}

func buildSerialAndParallelGo(t *testing.T, packages []PackageDir) (serial, parallel string) {
	t.Helper()
	inner := NewGoParser()
	serialGraph, err := NewBuilderForEcosystem(ecosystemGo, &serialSelectiveParser{serialOnlyParser: serialOnlyParser{inner: inner}, selective: inner}).
		BuildFromDirectories(packages, nil)
	if err != nil {
		t.Fatalf("serial BuildFromDirectories: %v", err)
	}
	parallelGraph, err := NewBuilderForEcosystem(ecosystemGo, NewGoParser()).BuildFromDirectories(packages, nil)
	if err != nil {
		t.Fatalf("parallel BuildFromDirectories: %v", err)
	}
	if len(parallelGraph.Functions) == 0 {
		t.Fatal("parallel graph is empty; fixture did not parse")
	}
	return fullGraphDump(t, serialGraph), fullGraphDump(t, parallelGraph)
}

// TestBuilder_GoParallelParseMatchesSerial pins that parsing the files of all
// packages in one pool, one file per unit, merges into the same graph as the
// serial walk: several packages (one include-scoped), multi-file directories
// whose files share package consts, build-tag variants of one function, and
// callback references whose names a local variable shadows.
func TestBuilder_GoParallelParseMatchesSerial(t *testing.T) {
	app := writeTree(t, map[string]string{
		"go.mod":         "module example.com/app\n",
		"main.go":        "package main\n\nimport (\n\t\"sort\"\n\t\"example.com/lib\"\n)\n\nfunc main() {\n\tlib.Hash(bits)\n\tsort.Slice(nil, less)\n\trun()\n}\n\nfunc less(i, j int) bool { return i < j }\n",
		"consts.go":      "package main\n\nconst bits = 3072\n",
		"run_linux.go":   "package main\n\nimport \"example.com/lib\"\n\nfunc run() { lib.Hash(1) }\n",
		"run_windows.go": "package main\n\nimport \"example.com/lib\"\n\nfunc run() { lib.Sign(2) }\n",
		"shadow.go":      "package main\n\nimport \"sort\"\n\nfunc shadow() {\n\tsort := mySorter{}\n\tsort.Slice(nil, less)\n\tfor _, x := range []int{1} {\n\t\t_ = x\n\t}\n}\n\ntype mySorter struct{}\n\nfunc (mySorter) Slice(any, func(int, int) bool) {}\n",
		"sub/sub.go":     "package sub\n\nimport \"example.com/lib\"\n\nfunc Use() { lib.Sign(size) }\n",
		"sub/size.go":    "package sub\n\nconst size = 256\n",
	})
	lib := writeTree(t, map[string]string{
		"go.mod":      "module example.com/lib\n",
		"hash.go":     "package lib\n\nimport \"crypto/sha256\"\n\nfunc Hash(n int) { sha256.Sum256(nil); helper() }\n",
		"sign.go":     "package lib\n\nimport \"crypto/ed25519\"\n\nfunc Sign(n int) { ed25519.Sign(nil, nil) }\n",
		"helper.go":   "package lib\n\nfunc helper() {}\n",
		"unused.go":   "package lib\n\nfunc Unused() { Hash(0) }\n",
		"inner/in.go": "package inner\n\nfunc In() {}\n",
	})
	packages := []PackageDir{
		{Dir: app, ImportPath: "example.com/app"},
		{Dir: lib, ImportPath: "example.com/lib", Version: "v1.0.0", IncludeFiles: []string{
			filepath.Join(lib, "hash.go"), filepath.Join(lib, "sign.go"), filepath.Join(lib, "helper.go"),
		}},
	}
	serial, parallel := buildSerialAndParallelGo(t, packages)
	if serial != parallel {
		t.Fatalf("parallel parse produced a different graph than serial parse:\nserial:\n%s\nparallel:\n%s", serial, parallel)
	}
	if strings.Contains(parallel, "Unused") {
		t.Fatal("a file outside the dependency's IncludeFiles was parsed")
	}
}

// TestBuilder_GoParallelParseMatchesSerialOnCorpus compares the serial and
// parallel graphs of real Go trees, one package per directory listed in
// CALLGRAPH_PARITY_GO_DIRS (colon-separated).
func TestBuilder_GoParallelParseMatchesSerialOnCorpus(t *testing.T) {
	dirs := os.Getenv("CALLGRAPH_PARITY_GO_DIRS")
	if dirs == "" {
		t.Skip("set CALLGRAPH_PARITY_GO_DIRS to compare serial and parallel graphs of real trees")
	}
	list := strings.Split(dirs, ":")
	packages := make([]PackageDir, 0, len(list))
	for i, dir := range list {
		packages = append(packages, PackageDir{Dir: dir, ImportPath: fmt.Sprintf("corpus%d", i), Version: "v0"})
	}
	serial, parallel := buildSerialAndParallelGo(t, packages)
	if serial != parallel {
		if out := os.Getenv("CALLGRAPH_PARITY_DUMP"); out != "" {
			_ = os.WriteFile(out+".serial", []byte(serial), 0o644)
			_ = os.WriteFile(out+".parallel", []byte(parallel), 0o644)
		}
		t.Fatalf("graphs differ: serial %d bytes, parallel %d bytes", len(serial), len(parallel))
	}
	t.Logf("identical graphs, %d bytes of dump", len(serial))
}
