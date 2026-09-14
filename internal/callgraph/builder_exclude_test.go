package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A workspace whose members live UNDER the root — an npm workspace, unlike a
// Cargo virtual manifest — needs the root walked for its own source while each
// member is walked once as its own package. Without a per-package exclusion the
// root walk re-parses every member under a second import path, and with
// module-scoped identity one function then holds two identities, which is the
// collision class the Node parser pass removed.
func TestBuilder_PackageExcludeDirsKeepsMembersOutOfTheRootWalk(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	member := filepath.Join(root, "packages", "app")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "index.js"),
		"import crypto from \"node:crypto\";\nexport function rootHash(d){ return crypto.createHash(\"sha256\").update(d).digest(\"hex\"); }\n")
	write(filepath.Join(member, "index.js"),
		"import crypto from \"node:crypto\";\nexport function memberHash(d){ return crypto.createHash(\"sha512\").update(d).digest(\"hex\"); }\n")

	build := func(exclude []string) *CallGraph {
		t.Helper()
		graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{
			{Dir: member, ImportPath: "@ws/app"},
			{Dir: root, ImportPath: "ws-root", ExcludeDirs: exclude},
		}, nil)
		if err != nil {
			t.Fatalf("BuildFromDirectories: %v", err)
		}
		return graph
	}

	countByName := func(graph *CallGraph, name string) int {
		n := 0
		for _, fn := range graph.Functions {
			if fn.ID.Name == name {
				n++
			}
		}
		return n
	}

	// Positive control: WITHOUT the exclusion the member is parsed twice, under
	// two import paths, so its one function holds two identities. If this stops
	// being true the test below proves nothing.
	if got := countByName(build(nil), "memberHash"); got != 2 {
		t.Fatalf("control: memberHash identities without exclusion = %d, want 2; the exclusion test would be vacuous", got)
	}

	graph := build([]string{member})
	if got := countByName(graph, "memberHash"); got != 1 {
		t.Errorf("memberHash identities = %d, want 1: the member must be parsed once", got)
	}
	if got := countByName(graph, "rootHash"); got != 1 {
		t.Errorf("rootHash identities = %d, want 1: the root's own source must still be parsed", got)
	}

	seen := map[string]string{}
	for key, fn := range graph.Functions {
		id := fmt.Sprintf("%s|%s|%s", fn.ID.Package, fn.ID.Type, fn.ID.Name)
		if prev, dup := seen[id]; dup {
			t.Errorf("identity %q held by both %s and %s", id, prev, key)
		}
		seen[id] = key
	}
}
