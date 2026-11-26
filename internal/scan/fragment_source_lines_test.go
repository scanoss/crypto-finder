// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const multiLineCallSource = `package app;
import javax.crypto.Cipher;
public class Caller {
    void run() throws Exception {
        Cipher c = Cipher.getInstance(
            "AES/GCM/NoPadding");
        helper(1,
               2);
        helper(3, 4);
    }
    void helper(int a, int b) {}
}
`

func multiLineCallResult(t *testing.T) *engine.DepScanResult {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "Caller.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(multiLineCallSource), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{}
	return &engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java"}
}

// A fragment carries what a detector needs to report a call site without the
// source: the end line of a call written over several lines, and the text of
// every line a call site covers. Both export paths agree.
func TestGraphFragmentCarriesCallEndLinesAndSourceLines(t *testing.T) {
	t.Parallel()
	result := multiLineCallResult(t)

	inMemory := buildGraphFragmentExport(result)
	file := filepath.Join(t.TempDir(), "fragment.json")
	if err := writeGraphFragmentJSONFile(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var streamed graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &streamed); err != nil {
		t.Fatal(err)
	}
	streamed.RestoreElided()

	for name, fragment := range map[string]graphfrag.GraphFragmentExport{"in memory": inMemory, "streamed": streamed} {
		external := map[int]int{}
		for _, call := range fragment.ExternalCalls {
			external[call.Line] = call.EndLine
		}
		if external[5] != 6 {
			t.Errorf("%s: Cipher.getInstance on lines 5-6 has end_line %d, want 6", name, external[5])
		}
		internal := map[int]int{}
		for _, edge := range fragment.InternalEdges {
			internal[edge.Line] = edge.EndLine
		}
		for _, edge := range fragment.CompactInternalEdges {
			internal[edge.Line] = edge.EndLine
		}
		if internal[7] != 8 || internal[9] != 0 {
			t.Errorf("%s: helper end lines = %v, want 7->8 and none on the one-line call at 9", name, internal)
		}
		want := map[string]map[int]string{"app/Caller.java": {
			5: `        Cipher c = Cipher.getInstance(`,
			6: `            "AES/GCM/NoPadding");`,
			7: `        helper(1,`,
			8: `               2);`,
			9: `        helper(3, 4);`,
		}}
		if !reflect.DeepEqual(fragment.SourceLines, want) {
			t.Errorf("%s: source_lines = %#v, want %#v", name, fragment.SourceLines, want)
		}
	}
}

// A C fragment's source_lines also carry the line of each #include
// directive, string literal, declaration and field store, in both export
// paths;
// a directive written in a function body is marked local, and its string
// literals are listed apart.
func TestGraphFragmentSourceLinesCarryCIncludes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := "#include <acme/seal.h>\n#include \"acme/local.h\"\n\nint seal(struct acme_job *job) {\n" +
		"    #include <acme/inner.h>\n    int bits = 256;\n    job->mode = ACME_GCM;\n    return acme_seal(bits, \"acme-256\");\n}\n" +
		"static const char *names[] = {\n    \"acme-128\",\n};\n"
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("c", callgraph.NewCParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	result := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, RootModule: "app", Ecosystem: "c"}
	inMemory := buildGraphFragmentExport(result)
	file := filepath.Join(t.TempDir(), "fragment.json")
	if err := writeGraphFragmentJSONFile(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var streamed graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &streamed); err != nil {
		t.Fatal(err)
	}
	want := map[string]map[int]string{"main.c": {
		1:  `#include <acme/seal.h>`,
		2:  `#include "acme/local.h"`,
		5:  `    #include <acme/inner.h>`,
		6:  `    int bits = 256;`,
		7:  `    job->mode = ACME_GCM;`,
		8:  `    return acme_seal(bits, "acme-256");`,
		11: `    "acme-128",`,
	}}
	for name, fragment := range map[string]graphfrag.GraphFragmentExport{"in memory": inMemory, "streamed": streamed} {
		if !reflect.DeepEqual(fragment.SourceLines, want) {
			t.Errorf("%s: source_lines = %#v, want %#v", name, fragment.SourceLines, want)
		}
		var local []bool
		for _, imp := range fragment.Imports["main.c"] {
			local = append(local, imp.Local)
		}
		if !reflect.DeepEqual(local, []bool{false, false, true}) {
			t.Errorf("%s: includes local = %v, want only the one in the body", name, local)
		}
		wantStrings := map[string][]graphfrag.GraphFragmentString{"main.c": {
			{Line: 8, StartCol: 28, EndCol: 38, Text: `"acme-256"`}, {Line: 11, StartCol: 5, EndCol: 15, Text: `"acme-128"`},
		}}
		if !reflect.DeepEqual(fragment.Strings, wantStrings) {
			t.Errorf("%s: strings = %+v, want %+v", name, fragment.Strings, wantStrings)
		}
	}
}
