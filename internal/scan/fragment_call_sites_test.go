// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const callSitesSource = `package app;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
public class Sites {
    static final Set<String> NAMES = new HashSet<String>();
    static {
        NAMES.add("a");
        NAMES.add("b");
        NAMES.add("c");
        Set<String> methods = new LinkedHashSet<>();
        methods.add("x");
        methods.add("y");
    }
    void run(byte[] a, byte[] b) {
        Object[] d = { new Digest(512), new Digest(256), new Digest(512) };
        java.util.Arrays.equals(a.clone(), b.clone());
        h(1);
        h(1, 2);
    }
    void h(int x) {}
    void h(int x, int y) {}
}
class Digest {
    Digest(int bits) {}
}
`

func callSitesResult(t *testing.T) *engine.DepScanResult {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "Sites.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(callSitesSource), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java"}
}

// fragmentSites lists the call sites of a fragment as "method/arity@line:col",
// internal edges (both encodings) and external calls alike.
func fragmentSites(fragment *graphfrag.GraphFragmentExport) []string {
	out := make([]string, 0, len(fragment.InternalEdges)+len(fragment.CompactInternalEdges)+len(fragment.ExternalCalls))
	for _, e := range fragment.InternalEdges {
		out = append(out, fmt.Sprintf("%s/%d@%d:%d", e.MethodName, e.Arity, e.Line, e.StartCol))
	}
	for _, e := range fragment.CompactInternalEdges {
		out = append(out, fmt.Sprintf("%s/%d@%d:%d", fragment.InternalEdgeStrings[e.MethodName], e.Arity, e.Line, e.StartCol))
	}
	for _, c := range fragment.ExternalCalls {
		out = append(out, fmt.Sprintf("%s/%d@%d:%d", c.MethodName, c.Arity, c.Line, c.StartCol))
	}
	sort.Strings(out)
	return out
}

var wantCallSites = []string{
	"<init>/0@11:31", "<init>/0@6:38",
	"<init>/1@16:24", "<init>/1@16:41", "<init>/1@16:58",
	"add/1@10:9", "add/1@12:9", "add/1@13:9", "add/1@8:9", "add/1@9:9",
	"clone/0@17:33", "clone/0@17:44",
	"equals/2@17:9",
	"h/1@18:9", "h/2@19:9",
}

func assertEveryCallSite(t *testing.T, result *engine.DepScanResult) {
	t.Helper()
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
	for name, fragment := range map[string]*graphfrag.GraphFragmentExport{"in memory": &inMemory, "streamed": &streamed} {
		if got := fragmentSites(fragment); !reflect.DeepEqual(got, wantCallSites) {
			t.Errorf("%s: sites = %v, want %v", name, got, wantCallSites)
		}
	}
}

// Every call is its own fragment site with its method name, arity and
// columns: three calls of one callee on one line keep their own columns.
func TestGraphFragmentWritesEveryCallSite(t *testing.T) {
	t.Parallel()
	assertEveryCallSite(t, callSitesResult(t))
}

// An edge the call graph recorded no per-site resolution for (a call the
// type resolver re-resolved) is still written once per call, with the method
// name and arity of its callee, not as one site without them.
func TestGraphFragmentWritesEveryCallSiteWithoutEdgeResolutions(t *testing.T) {
	t.Parallel()
	result := callSitesResult(t)
	result.CallGraph.EdgeResolutions = nil
	assertEveryCallSite(t, result)
}
