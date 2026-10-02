package dependency

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Distributions sharing a namespace directory own the files under it that
// their RECORD lists and that exist; one without a RECORD owns what no
// sibling's RECORD lists; one with a directory of its own keeps all of it.
func TestOwnSharedRoots(t *testing.T) {
	site := t.TempDir()
	for rel, contents := range map[string]string{
		"google/a/x.py":             "",
		"google/b/y.py":             "",
		"google/c/z.py":             "",
		"solo/s.py":                 "",
		"ns_a-1.0.dist-info/RECORD": "google/a/x.py,sha256=x,1\ngoogle/a/gone.py,,\n../../../bin/tool,,\nns_a-1.0.dist-info/RECORD,,\n",
		"ns_a-0.9.dist-info/RECORD": "google/b/y.py,,\n",
		"NS_B-2.0.dist-info/RECORD": "\"google/b/y.py\",sha256=x,1\n",
		"solo-3.0.dist-info/RECORD": "solo/s.py,,\n",
	} {
		path := filepath.Join(site, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	namespace := filepath.Join(site, "google")
	deps := []Dependency{
		{Module: "ns-a", Version: "1.0", Dir: namespace},
		{Module: "ns.b", Version: "2.0", Dir: namespace},
		{Module: "legacy", Version: "0.1", Dir: namespace},
		{Module: "solo", Version: "3.0", Dir: filepath.Join(site, "solo")},
	}
	ownSharedRoots(deps, []string{site, site, site, site})

	want := [][]string{
		{filepath.Join(namespace, "a", "x.py")},
		{filepath.Join(namespace, "b", "y.py")},
		{filepath.Join(namespace, "c", "z.py")},
		nil,
	}
	for i := range deps {
		if !reflect.DeepEqual(deps[i].Files, want[i]) {
			t.Errorf("%s Files = %v, want %v", deps[i].Module, deps[i].Files, want[i])
		}
	}
}

func TestListsFile(t *testing.T) {
	files := []string{"/sp/google/a.py", "/sp/google/b.py"}
	for path, want := range map[string]bool{"/sp/google/a.py": true, "/sp/google/b.py": true, "/sp/google/c.py": false} {
		if got := ListsFile(files, path); got != want {
			t.Errorf("ListsFile(%q) = %v, want %v", path, got, want)
		}
	}
	if !ListsFile(nil, "/anything") {
		t.Error("nil Files must include every path")
	}
}
