// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// elideSources is a call through an interface with two implementations,
// whose argument is traced in the caller's file and through a call into
// another file.
var elideSources = map[string]string{
	"app/Hash.java": `package app;
public interface Hash { byte[] digest(byte[] data); }
`,
	"app/Sha.java": `package app;
public class Sha implements Hash { public byte[] digest(byte[] data) { return data; } }
`,
	"app/Md.java": `package app;
public class Md implements Hash { public byte[] digest(byte[] data) { return data; } }
`,
	"app/Keys.java": `package app;
public class Keys { static byte[] load(String name) { return name.getBytes(); } }
`,
	"app/Run.java": `package app;
public class Run {
    byte[] run(Hash hash, String name) {
        byte[] data = Keys.load(name);
        return hash.digest(data);
    }
}
`,
}

func elideResult(t *testing.T) *engine.DepScanResult {
	t.Helper()
	dir := t.TempDir()
	for name, text := range elideSources {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java"}
}

// sortedJSON encodes each value, sorted: the two writers order edges
// differently.
func sortedJSON[T any](t *testing.T, values []T) []string {
	t.Helper()
	out := make([]string, len(values))
	for i := range values {
		data, err := json.Marshal(values[i])
		if err != nil {
			t.Fatal(err)
		}
		out[i] = string(data)
	}
	sort.Strings(out)
	return out
}

// The written document leaves out what graph-fragment-1.22 shares, and
// restores to the fragment built in memory.
func TestGraphFragmentWriterElidesWhatDecodingRestores(t *testing.T) {
	t.Parallel()
	result := elideResult(t)
	inMemory := buildGraphFragmentExport(result)
	file := filepath.Join(t.TempDir(), "fragment.json")
	if err := writeGraphFragmentJSONFile(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	var raw graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	meta := raw.ScanMetadata
	if !meta.SharedEntryCalls || !meta.ImplicitSourceFiles || !meta.DerivedFunctionNames || !meta.DerivedTargetNames {
		t.Fatalf("elision flags not set: %+v", meta)
	}
	entryCalls, digestEdges := 0, 0
	for _, edge := range raw.CompactInternalEdges {
		if raw.InternalEdgeStrings[edge.MethodName] == "digest" {
			digestEdges++
			if edge.EntryCall != nil {
				entryCalls++
			}
		}
	}
	if digestEdges < 2 || entryCalls != 1 {
		t.Errorf("hash.digest(data): %d edges with %d entry calls written, want several with 1", digestEdges, entryCalls)
	}
	for _, fn := range raw.Functions {
		if fn.FunctionName != "" || fn.Package != "" {
			t.Errorf("%s: derivable names written", fn.Key)
		}
	}

	var streamed graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &streamed); err != nil {
		t.Fatal(err)
	}
	streamed.RestoreElided()
	streamed.ExpandInternalEdges()
	equal := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s: %d decoded, %d built", name, len(got), len(want))
			return
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s differ:\n got %s\nwant %s", name, got[i], want[i])
			}
		}
	}
	equal("functions", sortedJSON(t, streamed.Functions), sortedJSON(t, inMemory.Functions))
	equal("internal edges", sortedJSON(t, streamed.InternalEdges), sortedJSON(t, inMemory.InternalEdges))
	equal("external calls", sortedJSON(t, streamed.ExternalCalls), sortedJSON(t, inMemory.ExternalCalls))
	equal("call anchors", sortedJSON(t, streamed.CallAnchors), sortedJSON(t, inMemory.CallAnchors))
	equal("constant refs", sortedJSON(t, streamed.ConstantRefs), sortedJSON(t, inMemory.ConstantRefs))

	var traced bool
	for _, edge := range streamed.InternalEdges {
		if edge.MethodName != "digest" || edge.EntryCall == nil {
			continue
		}
		for _, node := range edge.EntryCall.Parameters[0].SourceNodes {
			traced = traced || (node.Location != nil && node.Location.FilePath == "app/Run.java")
		}
	}
	if !traced {
		t.Error("the digest argument's location lost the caller's file")
	}
}
