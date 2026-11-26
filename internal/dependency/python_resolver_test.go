// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// pyFixture copies testdata/python/<name> to a temporary directory, so a test
// can add files without touching the fixture.
func pyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", "python", name)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func resolvePy(t *testing.T, dir string) *ResolveResult {
	t.Helper()
	t.Setenv("VIRTUAL_ENV", "")
	r := NewPythonResolver()
	if !r.CanResolve(dir) {
		t.Fatalf("CanResolve(%s) = false", dir)
	}
	result, err := r.Resolve(context.Background(), dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return result
}

func pyKeys(result *ResolveResult) []string {
	keys := make([]string, 0, len(result.Dependencies))
	for _, d := range result.Dependencies {
		keys = append(keys, Ref{Module: d.Module, Version: d.Version}.Key())
	}
	return keys
}

func pyDep(t *testing.T, result *ResolveResult, key string) Dependency {
	t.Helper()
	for _, d := range result.Dependencies {
		if (Ref{Module: d.Module, Version: d.Version}).Key() == key {
			return d
		}
	}
	t.Fatalf("no dependency %s in %v", key, pyKeys(result))
	return Dependency{}
}

func pyRequires(result *ResolveResult, key string) []string {
	refs := result.VersionedGraph[key]
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.Key())
	}
	return out
}

func assertEqual[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

func TestPythonResolverUvLock(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "uv"))
	assertEqual(t, "source", result.Source, "uv.lock")
	// pytest and what only it needs (iniconfig, colorama) are dev.
	assertEqual(t, "dependencies", pyKeys(result), []string{
		"certifi@2025.1.31", "cffi@1.17.1", "charset-normalizer@3.4.1", "cryptography@44.0.2", "idna@3.10",
		"pycparser@2.22", "pyjwt@2.10.1", "pysocks@1.7.1", "requests@2.32.3", "urllib3@2.3.0",
	})
	assertEqual(t, "direct", result.DirectDependencies, []string{"pyjwt", "requests"})
	assertEqual(t, "requests requires", pyRequires(result, "requests@2.32.3"),
		[]string{"certifi@2025.1.31", "charset-normalizer@3.4.1", "idna@3.10", "pysocks@1.7.1", "urllib3@2.3.0"})
	assertEqual(t, "pyjwt requires", pyRequires(result, "pyjwt@2.10.1"), []string{"cryptography@44.0.2"})

	assertEqual(t, "requests extras", pyDep(t, result, "requests@2.32.3").Extras, []string{"socks"})
	assertEqual(t, "pyjwt extras", pyDep(t, result, "pyjwt@2.10.1").Extras, []string{"crypto"})
	// An extra's requirement carries extra == "<name>"; a platform marker is
	// kept as written; a dependency also required unconditionally has none.
	assertEqual(t, "pysocks markers", pyDep(t, result, "pysocks@1.7.1").Markers, []string{`extra == "socks"`})
	assertEqual(t, "cryptography markers", pyDep(t, result, "cryptography@44.0.2").Markers, []string{`extra == "crypto"`})
	assertEqual(t, "cffi markers", pyDep(t, result, "cffi@1.17.1").Markers, []string{"platform_python_implementation != 'PyPy'"})
	assertEqual(t, "pycparser markers", pyDep(t, result, "pycparser@2.22").Markers, []string(nil))
	assertEqual(t, "requests markers", pyDep(t, result, "requests@2.32.3").Markers, []string(nil))
}

func TestPythonResolverPoetryLock(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "poetry"))
	assertEqual(t, "source", result.Source, "poetry.lock")
	// Both numpy versions: the union of the marker branches.
	assertEqual(t, "dependencies", pyKeys(result), []string{
		"bcrypt@4.3.0", "cffi@1.17.1", "cryptography@44.0.2", "numpy@2.0.2", "numpy@2.2.4",
		"paramiko@3.5.1", "pycparser@2.22", "pynacl@1.5.0",
	})
	assertEqual(t, "direct", result.DirectDependencies, []string{"numpy", "paramiko"})
	assertEqual(t, "paramiko requires", pyRequires(result, "paramiko@3.5.1"),
		[]string{"bcrypt@4.3.0", "cryptography@44.0.2", "pynacl@1.5.0"})
	assertEqual(t, "numpy 2.0.2 markers", pyDep(t, result, "numpy@2.0.2").Markers, []string{`python_version < "3.10"`})
	assertEqual(t, "numpy 2.2.4 markers", pyDep(t, result, "numpy@2.2.4").Markers, []string{`python_version >= "3.10"`})
	// cffi's own marker; pynacl requires it unconditionally, so the edge
	// marker from cryptography does not add.
	assertEqual(t, "cffi markers", pyDep(t, result, "cffi@1.17.1").Markers, []string{`platform_python_implementation != "PyPy"`})
}

func TestPythonResolverPipfileLock(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "pipfile"))
	assertEqual(t, "source", result.Source, "Pipfile.lock")
	// The develop section is dev; Pipfile.lock has no edges.
	assertEqual(t, "dependencies", pyKeys(result), []string{
		"certifi@2025.1.31", "pycryptodome@3.22.0", "pysocks@1.7.1", "requests@2.32.3",
	})
	assertEqual(t, "direct", result.DirectDependencies, []string{"pycryptodome", "requests"})
	assertEqual(t, "edges", len(result.VersionedGraph), 0)
	assertEqual(t, "requests extras", pyDep(t, result, "requests@2.32.3").Extras, []string{"socks"})
	assertEqual(t, "requests markers", pyDep(t, result, "requests@2.32.3").Markers, []string{"python_version >= '3.8'"})
	// Every dependency has a Graph entry, so Paths tells the transitive ones
	// (left for the server's component data) from the direct ones.
	paths := Paths(result, nil)
	if p, ok := paths["requests"]; !ok || len(p.Steps) != 1 {
		t.Errorf("requests path = %+v, want direct", p)
	}
	if _, ok := paths["certifi"]; ok {
		t.Errorf("certifi has a path; without edges it is unattributed")
	}
}

func TestPythonResolverPdmLock(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "pdm"))
	assertEqual(t, "source", result.Source, "pdm.lock")
	// The crypto extra's group is runtime, the test group dev; the entry
	// with extras merges into requests.
	assertEqual(t, "dependencies", pyKeys(result), []string{
		"certifi@2025.1.31", "pycryptodome@3.22.0", "pysocks@1.7.1", "requests@2.32.3", "urllib3@2.3.0",
	})
	assertEqual(t, "direct", result.DirectDependencies, []string{"pycryptodome", "requests"})
	assertEqual(t, "requests requires", pyRequires(result, "requests@2.32.3"),
		[]string{"certifi@2025.1.31", "pysocks@1.7.1", "urllib3@2.3.0"})
	assertEqual(t, "requests extras", pyDep(t, result, "requests@2.32.3").Extras, []string{"socks"})
	assertEqual(t, "pycryptodome markers", pyDep(t, result, "pycryptodome@3.22.0").Markers, []string{`extra == "crypto"`})
}

func TestPythonResolverPylock(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "pylock"))
	assertEqual(t, "source", result.Source, "pylock.toml")
	// The editable project has no version and is not a dependency; the
	// Windows-only pywin32 is in (union) with its marker.
	assertEqual(t, "dependencies", pyKeys(result), []string{
		"cffi@1.17.1", "cryptography@44.0.2", "pycparser@2.22", "pywin32@310",
	})
	assertEqual(t, "direct", result.DirectDependencies, []string{"cryptography", "pywin32"})
	assertEqual(t, "cryptography requires", pyRequires(result, "cryptography@44.0.2"), []string{"cffi@1.17.1"})
	assertEqual(t, "pywin32 markers", pyDep(t, result, "pywin32@310").Markers, []string{"sys_platform == 'win32'"})
}

func TestPythonResolverPipCompile(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "pip-compile"))
	assertEqual(t, "source", result.Source, "requirements.txt")
	assertEqual(t, "dependencies", len(result.Dependencies), 9)
	// "# via -r requirements.in" makes a requirement direct, "# via <name>"
	// an edge from it.
	assertEqual(t, "direct", result.DirectDependencies, []string{"pyjwt", "requests", "urllib3"})
	assertEqual(t, "requests requires", pyRequires(result, "requests@2.32.3"),
		[]string{"certifi@2025.1.31", "charset-normalizer@3.4.1", "idna@3.10", "urllib3@2.3.0"})
	assertEqual(t, "cffi requires", pyRequires(result, "cffi@1.17.1"), []string{"pycparser@2.22"})
	assertEqual(t, "pyjwt extras", pyDep(t, result, "pyjwt@2.10.1").Extras, []string{"crypto"})
	assertEqual(t, "cffi markers", pyDep(t, result, "cffi@1.17.1").Markers, []string{`platform_python_implementation != "PyPy"`})
	paths := Paths(result, nil)
	assertEqual(t, "pycparser path length", len(paths["pycparser"].Steps), 4)
}

func TestPythonResolverPipFreezeWithInclude(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "freeze"))
	assertEqual(t, "dependencies", pyKeys(result), []string{"bcrypt@4.3.0", "flask@3.1.0", "itsdangerous@2.2.0", "pynacl@1.5.0"})
	// No annotations: every line is the project's own.
	assertEqual(t, "direct", result.DirectDependencies, []string{"bcrypt", "flask", "itsdangerous", "pynacl"})
}

func TestPythonResolverPartiallyPinnedRequirementsAreDeclaredOnly(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "partial"))
	assertEqual(t, "source", result.Source, "declared")
	// The == pin is a dependency; the range is unpinned; requirements-dev.txt
	// is not read beside requirements.txt.
	assertEqual(t, "dependencies", pyKeys(result), []string{"pyopenssl@25.0.0"})
	assertEqual(t, "unpinned", result.Unpinned, []UnpinnedDependency{
		{Module: "cryptography", Specifier: ">=42,<45", Manifest: "requirements.txt"},
	})
}

func TestPythonResolverDeclaredOnly(t *testing.T) {
	result := resolvePy(t, pyFixture(t, "declared"))
	assertEqual(t, "dependencies", pyKeys(result), []string{"jinja2@3.1.6"})
	assertEqual(t, "direct", result.DirectDependencies, []string{"jinja2"})
	assertEqual(t, "unpinned", result.Unpinned, []UnpinnedDependency{
		{Module: "cryptography", Specifier: ">=42", Manifest: "pyproject.toml"},
		{Module: "pywin32-ctypes", Specifier: ">=0.2.0", Marker: "sys_platform == 'win32'", Manifest: "pyproject.toml"},
		{Module: "fido2", Specifier: "~=1.1", Marker: `extra == "fido"`, Manifest: "pyproject.toml"},
	})
}

func TestPythonResolverInstalledEnvironment(t *testing.T) {
	dir := pyFixture(t, "venv")
	result := resolvePy(t, dir)
	site := filepath.Join(dir, "venv", "lib", "python3.12", "site-packages")
	assertEqual(t, "source", result.Source, site)
	// The editable project declares pyjwt[crypto]; requests and pip, which
	// nothing declared reaches, are left out.
	assertEqual(t, "dependencies", pyKeys(result), []string{"cffi@1.17.1", "cryptography@44.0.2", "pycparser@2.22", "pyjwt@2.10.1"})
	assertEqual(t, "direct", result.DirectDependencies, []string{"pyjwt"})
	assertEqual(t, "pyjwt requires", pyRequires(result, "pyjwt@2.10.1"), []string{"cryptography@44.0.2"})
	assertEqual(t, "cryptography markers", pyDep(t, result, "cryptography@44.0.2").Markers, []string{`extra == "crypto"`})
	assertEqual(t, "cffi markers", pyDep(t, result, "cffi@1.17.1").Markers, []string{`platform_python_implementation != "PyPy"`})
	assertEqual(t, "pyjwt extras", pyDep(t, result, "pyjwt@2.10.1").Extras, []string{"crypto"})

	crypto := pyDep(t, result, "cryptography@44.0.2")
	assertEqual(t, "cryptography dir", crypto.Dir, site)
	assertEqual(t, "cryptography files", crypto.Files, []string{
		filepath.Join(site, "cryptography", "__init__.py"),
		filepath.Join(site, "cryptography", "fernet.py"),
		filepath.Join(site, "cryptography", "hazmat", "primitives", "hashes.py"),
	})
	// A console script outside site-packages is not the distribution's code.
	assertEqual(t, "pyjwt files", pyDep(t, result, "pyjwt@2.10.1").Files, []string{
		filepath.Join(site, "jwt", "__init__.py"), filepath.Join(site, "jwt", "algorithms.py"),
	})
}

func TestPythonResolverEnvironmentWithoutDeclarationsKeepsAllButPip(t *testing.T) {
	dir := pyFixture(t, "venv")
	site := filepath.Join(dir, "venv", "lib", "python3.12", "site-packages")
	if err := os.RemoveAll(filepath.Join(site, "webapp-0.1.0.dist-info")); err != nil {
		t.Fatal(err)
	}
	// .venv is looked at before venv.
	if err := os.Rename(filepath.Join(dir, "venv"), filepath.Join(dir, ".venv")); err != nil {
		t.Fatal(err)
	}
	result := resolvePy(t, dir)
	assertEqual(t, "dependencies", pyKeys(result), []string{
		"cffi@1.17.1", "cryptography@44.0.2", "pycparser@2.22", "pyjwt@2.10.1", "requests@2.32.3",
	})
	assertEqual(t, "direct", len(result.DirectDependencies), 0)
}

func TestPythonResolverPinnedRequirementsWinOverEnvironment(t *testing.T) {
	dir := pyFixture(t, "venv")
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pyjwt==2.10.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "source", resolvePy(t, dir).Source, "requirements.txt")
}

// TestPythonResolverEnvironmentCompletesPinnedRequirements: requirements
// pinned with == give the versions of what they list, and the installed
// environment adds what those pins require, transitively, as a project that
// pins only its direct dependencies installs it. A pin the environment holds
// at another version is kept, and its requirements are not followed: the
// environment's are another release's.
func TestPythonResolverEnvironmentCompletesPinnedRequirements(t *testing.T) {
	site := filepath.Join(".venv", "lib", "python3.12", "site-packages")
	dist := func(name, version string, requires ...string) map[string]string {
		info := filepath.Join(site, name+"-"+version+".dist-info")
		meta := "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"
		for _, r := range requires {
			meta += "Requires-Dist: " + r + "\n"
		}
		return map[string]string{
			filepath.Join(info, "METADATA"):          meta + "\n",
			filepath.Join(info, "RECORD"):            name + "/__init__.py,,\n",
			filepath.Join(site, name, "__init__.py"): "",
		}
	}
	files := map[string]string{"requirements.txt": "liba==1.0.0\nlibc==3.0.0\n"}
	for _, d := range []map[string]string{
		dist("liba", "1.0.0", "libb==1.0.0"),
		dist("libb", "1.0.0", "libd"),
		dist("libc", "2.0.0", "libe"),
		dist("libd", "0.5"),
		dist("libe", "1.0"),
		dist("other", "1.0"),
	} {
		for k, v := range d {
			files[k] = v
		}
	}
	dir := writeTree(t, files)
	result := resolvePy(t, dir)
	assertEqual(t, "source", result.Source, "requirements.txt")
	assertEqual(t, "dependencies", pyKeys(result), []string{"liba@1.0.0", "libb@1.0.0", "libc@3.0.0", "libd@0.5"})
	assertEqual(t, "direct", result.DirectDependencies, []string{"liba", "libc"})
	assertEqual(t, "liba requires", pyRequires(result, "liba@1.0.0"), []string{"libb@1.0.0"})
	assertEqual(t, "libb requires", pyRequires(result, "libb@1.0.0"), []string{"libd@0.5"})
	assertEqual(t, "libc requires", pyRequires(result, "libc@3.0.0"), []string{})
	installed := filepath.Join(dir, site)
	assertEqual(t, "libb dir", pyDep(t, result, "libb@1.0.0").Dir, installed)
	assertEqual(t, "libb files", pyDep(t, result, "libb@1.0.0").Files, []string{filepath.Join(installed, "libb", "__init__.py")})
	assertEqual(t, "libc dir", pyDep(t, result, "libc@3.0.0").Dir, "")
}

func TestPythonResolverMalformedLockFails(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	dir := pyFixture(t, "declared")
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte("version = 1\n[[package]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPythonResolver().Resolve(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "uv.lock") {
		t.Fatalf("Resolve with a malformed uv.lock: err = %v, want an error naming it", err)
	}
}

func TestPythonResolverNothingToRead(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	dir := t.TempDir()
	if NewPythonResolver().CanResolve(dir) {
		t.Fatal("CanResolve on an empty directory")
	}
	result, err := NewPythonResolver().Resolve(context.Background(), dir)
	if err != nil || len(result.Dependencies) != 0 {
		t.Fatalf("Resolve = %+v, %v", result, err)
	}
}

func TestParsePyRequirement(t *testing.T) {
	cases := []struct {
		raw  string
		want pyRequirement
	}{
		{
			"requests[socks,Security]>=2.0 ; python_version >= \"3.8\"",
			pyRequirement{Name: "requests", Extras: []string{"socks", "security"}, Specifier: ">=2.0", Marker: `python_version >= "3.8"`},
		},
		{"zope.interface (>=5.0, <7)", pyRequirement{Name: "zope-interface", Specifier: ">=5.0,<7"}},
		{"Flask_Login===0.6.3", pyRequirement{Name: "flask-login", Specifier: "===0.6.3"}},
		{"pkg @ https://example.com/pkg-1.0.tar.gz", pyRequirement{Name: "pkg", URL: "https://example.com/pkg-1.0.tar.gz"}},
		{
			"cffi>=1.12; platform_python_implementation != 'PyPy'",
			pyRequirement{Name: "cffi", Specifier: ">=1.12", Marker: "platform_python_implementation != 'PyPy'"},
		},
	}
	for _, c := range cases {
		got, ok := parsePyRequirement(c.raw)
		if !ok {
			t.Errorf("parsePyRequirement(%q) failed", c.raw)
			continue
		}
		assertEqual(t, c.raw, got, c.want)
	}
	if _, ok := parsePyRequirement("--hash=sha256:abc"); ok {
		t.Error("an option line parsed as a requirement")
	}
}

func TestPinnedPyVersion(t *testing.T) {
	for spec, want := range map[string]string{"==1.0": "1.0", "===1.0.post1": "1.0.post1", "==2024.8.30": "2024.8.30"} {
		if got, ok := pinnedPyVersion(spec); !ok || got != want {
			t.Errorf("pinnedPyVersion(%q) = %q, %v", spec, got, ok)
		}
	}
	for _, spec := range []string{"", ">=1.0", "==1.*", "==1.0,<2", "~=1.0", "!=1.0"} {
		if _, ok := pinnedPyVersion(spec); ok {
			t.Errorf("pinnedPyVersion(%q) pinned", spec)
		}
	}
}

func TestPyExtraMarker(t *testing.T) {
	assertEqual(t, "plain", pyExtraMarker("socks", ""), `extra == "socks"`)
	assertEqual(t, "and", pyExtraMarker("ssh", `sys_platform == "linux"`), `extra == "ssh" and sys_platform == "linux"`)
	assertEqual(t, "or", pyExtraMarker("x", `a == "1" or b == "2"`), `extra == "x" and (a == "1" or b == "2")`)
	assertEqual(t, "none", pyExtraMarker("", "m"), "m")
}

func TestPoetrySpecifier(t *testing.T) {
	for in, want := range map[string]string{"*": "", "2.31.0": "==2.31.0", "^3.5": "^3.5", ">=1,<2": ">=1,<2", "1.*": "1.*"} {
		assertEqual(t, in, poetrySpecifier(in), want)
	}
	if !slices.Equal(addSorted(nil, "b", "a", "b", ""), []string{"a", "b"}) {
		t.Error("addSorted")
	}
}
