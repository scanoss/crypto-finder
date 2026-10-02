package dependency

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeSitePackages(t *testing.T, site string, files map[string]string) {
	t.Helper()
	for rel, contents := range files {
		path := filepath.Join(site, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A distribution covers every top-level package and module it installed,
// whatever order importlib.metadata reports them in. A directory of its own
// stays its root; anything else is rooted at site-packages with the files of
// each root listed, its share of a namespace directory by RECORD.
func TestPipResolver_Resolve_CoversEveryTopLevelRoot(t *testing.T) {
	site := filepath.Join(t.TempDir(), "site-packages")
	writeSitePackages(t, site, map[string]string{
		"configobj/__init__.py":        "",
		"configobj/compat/__init__.py": "",
		"validate/__init__.py":         "",
		"_speedups.cpython-312.so":     "",
		"six.py":                       "",
		"solo/__init__.py":             "",
		"google/a/x.py":                "",
		"google/b/y.py":                "",
		"nsb_util.py":                  "",
		"ns_a-1.0.dist-info/RECORD":    "google/a/x.py,,\n",
		"ns_b-2.0.dist-info/RECORD":    "google/b/y.py,,\nnsb_util.py,,\n",
	})
	bin := t.TempDir()
	writeExecutable(t, bin, "python3", `#!/bin/sh
if [ "$1" = "-m" ] && [ "$3" = "list" ]; then
  echo '[{"name":"configobj","version":"5.0"},{"name":"six","version":"1.16"},{"name":"solo","version":"3.0"},{"name":"ns-a","version":"1.0"},{"name":"ns-b","version":"2.0"}]'
  exit 0
fi
if [ "$1" = "-m" ] && [ "$3" = "show" ]; then
  for p in configobj:5.0 six:1.16 solo:3.0 ns-a:1.0 ns-b:2.0; do
    printf 'Name: %s\nVersion: %s\nLocation: `+site+`\nRequires:\n---\n' "${p%%:*}" "${p#*:}"
  done
  exit 0
fi
if [ "$1" = "-c" ]; then
  echo '{"validate":["configobj"],"configobj":["configobj"],"configobj/compat":["configobj"],"_speedups":["configobj"],"six":["six"],"solo":["solo"],"google":["ns-a","ns-b"],"nsb_util":["ns-b"]}'
  exit 0
fi
exit 1
`)
	prependPath(t, bin)
	t.Setenv("VIRTUAL_ENV", "")

	in := func(rels ...string) []string {
		files := make([]string, len(rels))
		for i, rel := range rels {
			files[i] = filepath.Join(site, filepath.FromSlash(rel))
		}
		return files
	}
	want := []Dependency{
		{Module: "configobj", Version: "5.0", Dir: site, Files: in("configobj/__init__.py", "configobj/compat/__init__.py", "validate/__init__.py")},
		{Module: "six", Version: "1.16", Dir: site, Files: in("six.py")},
		{Module: "solo", ImportPath: "solo", Version: "3.0", Dir: filepath.Join(site, "solo")},
		{Module: "ns-a", ImportPath: "google", Version: "1.0", Dir: filepath.Join(site, "google"), Files: in("google/a/x.py")},
		{Module: "ns-b", Version: "2.0", Dir: site, Files: in("google/b/y.py", "nsb_util.py")},
	}
	project := t.TempDir()
	for run := range 20 {
		result, err := NewPipResolver().Resolve(context.Background(), project)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result.Dependencies, want) {
			t.Fatalf("run %d: Dependencies =\n%+v\nwant\n%+v", run, result.Dependencies, want)
		}
	}
}

// Distributions sharing a namespace directory own the files under it that
// their RECORD lists and that exist; one without a RECORD owns what no
// sibling's RECORD lists; one with a directory of its own keeps all of it.
func TestPlaceDistributions_SharedNamespace(t *testing.T) {
	site := t.TempDir()
	writeSitePackages(t, site, map[string]string{
		"google/a/x.py":             "",
		"google/b/y.py":             "",
		"google/c/z.py":             "",
		"solo/s.py":                 "",
		"ns_a-1.0.dist-info/RECORD": "google/a/x.py,sha256=x,1\ngoogle/a/gone.py,,\n../../../bin/tool,,\nns_a-1.0.dist-info/RECORD,,\n",
		"ns_a-0.9.dist-info/RECORD": "google/b/y.py,,\n",
		"NS_B-2.0.dist-info/RECORD": "\"google/b/y.py\",sha256=x,1\n",
		"solo-3.0.dist-info/RECORD": "solo/s.py,,\n",
	})
	deps := []Dependency{
		{Module: "ns-a", Version: "1.0"},
		{Module: "ns.b", Version: "2.0"},
		{Module: "legacy", Version: "0.1"},
		{Module: "solo", Version: "3.0"},
	}
	google := []string{"google"}
	placeDistributions(deps, []installedDistribution{{site, google}, {site, google}, {site, google}, {site, []string{"solo"}}})

	namespace := filepath.Join(site, "google")
	want := []Dependency{
		{Module: "ns-a", ImportPath: "google", Version: "1.0", Dir: namespace, Files: []string{filepath.Join(namespace, "a", "x.py")}},
		{Module: "ns.b", ImportPath: "google", Version: "2.0", Dir: namespace, Files: []string{filepath.Join(namespace, "b", "y.py")}},
		{Module: "legacy", ImportPath: "google", Version: "0.1", Dir: namespace, Files: []string{filepath.Join(namespace, "c", "z.py")}},
		{Module: "solo", ImportPath: "solo", Version: "3.0", Dir: filepath.Join(site, "solo")},
	}
	if !reflect.DeepEqual(deps, want) {
		t.Errorf("placed =\n%+v\nwant\n%+v", deps, want)
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
