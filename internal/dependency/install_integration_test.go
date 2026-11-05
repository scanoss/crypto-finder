package dependency

import (
	"archive/zip"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// requireRealInstall skips unless the real tool is on PATH and its registry
// answers: these tests download a package.
func requireRealInstall(t *testing.T, tool, registry string) {
	t.Helper()
	if testing.Short() {
		t.Skip("downloads a package; skipped with -short")
	}
	if _, err := exec.LookPath(tool); err != nil {
		t.Skip(tool + " not installed")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", registry)
	if err != nil {
		t.Skipf("%s unreachable: %v", registry, err)
	}
	_ = conn.Close()
}

func TestNpmInstall_RealNpmCI(t *testing.T) {
	requireRealInstall(t, "npm", "registry.npmjs.org:443")
	root := writeTree(t, map[string]string{npmManifest: msManifest, npmLockfile: msLockfile})

	result, err := NewNpmResolver(WithNpmInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	ms, ok := depsByModule(result)["ms"]
	if !ok || ms.Version != "2.1.3" || !isFile(ms.Dir+"/index.js") {
		t.Fatalf("ms = %+v (found %v), want 2.1.3 installed on disk", ms, ok)
	}
}

// Over an existing node_modules the install adds the missing package and keeps
// what is there: an installed dev package and a file the user changed in it.
func TestNpmInstall_RealInstallKeepsExistingPackages(t *testing.T) {
	requireRealInstall(t, "npm", "registry.npmjs.org:443")
	root := writeTree(t, map[string]string{
		npmManifest: `{"name":"fixture","version":"1.0.0","dependencies":{"ms":"2.1.3"},"devDependencies":{"is-number":"7.0.0"}}`,
		npmLockfile: `{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "fixture", "version": "1.0.0", "dependencies": {"ms": "2.1.3"}, "devDependencies": {"is-number": "7.0.0"}},
    "node_modules/is-number": {
      "version": "7.0.0",
      "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
      "integrity": "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/ms": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
      "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==",
      "license": "MIT"
    }
  }
}`,
		"node_modules/is-number/package.json": `{"name":"is-number","version":"7.0.0"}`,
		"node_modules/is-number/patched.js":   "module.exports = 'local edit'",
	})

	result, err := NewNpmResolver(WithNpmInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ms, ok := depsByModule(result)["ms"]; !ok || !isFile(ms.Dir+"/index.js") {
		t.Fatalf("ms = %+v (found %v), want it installed on disk", ms, ok)
	}
	if !isFile(root + "/node_modules/is-number/patched.js") {
		t.Fatalf("the installed dev package and its local edit were deleted")
	}
}

func TestPipInstall_RealVenv(t *testing.T) {
	requireRealInstall(t, "python3", "pypi.org:443")
	isolatePipEnv(t)
	root := writeTree(t, map[string]string{requirementsFile: "six==1.16.0\n"})

	result, err := NewPipResolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := moduleNames(result); len(got) != 1 || got[0] != "six" {
		t.Fatalf("modules = %v, want only six: the venv holds the project's dependencies and nothing else", got)
	}
	six := result.Dependencies[0]
	if six.Version != "1.16.0" {
		t.Fatalf("six version = %q, want 1.16.0", six.Version)
	}
	if _, err := os.Stat(six.Dir); err != nil {
		t.Fatalf("six Dir %q is not on disk: %v", six.Dir, err)
	}
}

// A project installed from its own directory is first-party source: the
// environment keeps its dependencies and drops the project.
func TestPipInstall_RealProjectInstallDropsTheProject(t *testing.T) {
	requireRealInstall(t, "python3", "pypi.org:443")
	isolatePipEnv(t)
	root := writeTree(t, map[string]string{
		"setup.py":           "from setuptools import setup\nsetup(name='myproj', version='0.1', packages=['myproj'], install_requires=['six==1.16.0'])\n",
		"myproj/__init__.py": "",
	})

	result, err := NewPipResolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := moduleNames(result); len(got) != 1 || got[0] != "six" {
		t.Fatalf("modules = %v, want only six", got)
	}
}

// Provisioning runs pip in the project directory, so a project module named
// like a standard-library one must not shadow it: that would run project code
// on the scanning host.
func TestPipInstall_RealProjectModulesDoNotShadowTheStandardLibrary(t *testing.T) {
	requireRealInstall(t, "python3", "pypi.org:443")
	isolatePipEnv(t)
	marker := "open(__file__ + '.ran', 'w').close()\n"
	root := writeTree(t, map[string]string{
		"requirements.txt":  "six==1.16.0\n",
		"json.py":           marker,
		"email/__init__.py": marker,
	})
	// Scanning from inside the project puts it in crypto-finder's own working
	// directory too, which the listing commands inherit.
	t.Chdir(root)

	result, err := NewPipResolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := moduleNames(result); len(got) != 1 || got[0] != "six" {
		t.Fatalf("modules = %v, want only six", got)
	}
	for _, ran := range []string{"json.py.ran", "email/__init__.py.ran"} {
		if _, err := os.Stat(filepath.Join(root, ran)); err == nil {
			t.Errorf("%s exists: provisioning imported the project's module instead of the standard library", ran)
		}
	}
}

// A wheel installed from a local file is a vendored or offline dependency, not
// first-party source: it carries archive_info, not dir_info, and stays.
func TestPipInstall_RealLocalWheelStaysADependency(t *testing.T) {
	requireRealInstall(t, "python3", "pypi.org:443")
	isolatePipEnv(t)
	root := writeTree(t, map[string]string{
		"requirements.txt": "./vendor/vendoredpkg-0.1-py3-none-any.whl\nsix==1.16.0\n",
		"app.py":           "import vendoredpkg\n",
	})
	writeWheel(t, filepath.Join(root, "vendor", "vendoredpkg-0.1-py3-none-any.whl"), "vendoredpkg", "0.1")

	result, err := NewPipResolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := moduleNames(result)
	if len(got) != 2 || got[0] != "six" || got[1] != "vendoredpkg" {
		t.Fatalf("modules = %v, want [six vendoredpkg]", got)
	}
}

// writeWheel writes a minimal pure-Python wheel holding one empty package.
func writeWheel(t *testing.T, path, name, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	distInfo := name + "-" + version + ".dist-info/"
	files := []struct{ name, body string }{
		{name + "/__init__.py", ""},
		{distInfo + "METADATA", "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"},
		{distInfo + "WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"},
		{distInfo + "top_level.txt", name + "\n"},
		{distInfo + "RECORD", ""},
	}
	for _, file := range files {
		w, err := zw.Create(file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(file.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// Without --install-dependencies the user's interpreter is listed as they set
// it up, PYTHONPATH included, and scanning from inside the project does not
// run its modules in place of the standard library.
func TestPip_RealDefaultModeKeepsPythonPathAndIgnoresProjectModules(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real interpreter; skipped with -short")
	}
	if err := exec.CommandContext(context.Background(), "python3", "-m", "pip", "--version").Run(); err != nil {
		t.Skip("python3 with pip not installed")
	}
	isolatePipEnv(t)
	marker := "open(__file__ + '.ran', 'w').close()\n"
	deps := writeTree(t, map[string]string{
		"onpath_pkg/__init__.py":                 "",
		"onpath_pkg-1.0.dist-info/METADATA":      "Metadata-Version: 2.1\nName: onpath-pkg\nVersion: 1.0\n",
		"onpath_pkg-1.0.dist-info/RECORD":        "onpath_pkg/__init__.py,,\n",
		"onpath_pkg-1.0.dist-info/top_level.txt": "onpath_pkg\n",
	})
	t.Setenv("PYTHONPATH", deps)
	root := writeTree(t, map[string]string{
		"app.py":            "import onpath_pkg\n",
		"json.py":           marker,
		"email/__init__.py": marker,
	})
	t.Chdir(root)

	result, err := NewPipResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !slices.Contains(moduleNames(result), "onpath-pkg") {
		t.Error("onpath-pkg, installed on PYTHONPATH, is not listed")
	}
	for _, ran := range []string{"json.py.ran", "email/__init__.py.ran"} {
		if _, err := os.Stat(filepath.Join(root, ran)); err == nil {
			t.Errorf("%s exists: listing imported the project's module instead of the standard library", ran)
		}
	}
}
