package dependency

import (
	"context"
	"net"
	"os"
	"os/exec"
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
