package dependency

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakePython is an ambient python3 that implements what provisioning and
// resolution ask of it: `-m venv --without-pip`, `-m pip --version`, and
// `-m pip [--python <venv>] install|list|show|uninstall`. Installing a
// requirement makes a package directory under the target environment's site
// dir; a requirement starting with "broken" fails to build, and a
// requirements file holding one, or the word fail-whole, fails as a whole, as
// does an install of several requirements that holds one. Installing a project
// directory installs its dependency projdep, and fails when the directory
// holds a "broken" entry, as a project its build backend refuses does. As
// real pip does, an install of only a -c constraint fails, and so does a
// requirement given on the command line under --require-hashes, which has no
// hash there. Its own environment holds pip, as a real ambient interpreter
// does.
type fakePython struct {
	ambient string
	log     string
}

func newFakePython(t *testing.T, pipVersion string) fakePython {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	ambientEnv := filepath.Join(dir, "ambient-env")
	if err := os.MkdirAll(filepath.Join(ambientEnv, "site", "pip"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ambientEnv, "installed"), []byte("pip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, dir, "venv-python", `#!/bin/sh
[ "$1" = "-I" ] && shift
echo "venv-python $*" >> '`+log+`'
exit 1
`)
	writeExecutable(t, dir, "python3", `#!/bin/sh
[ "$1" = "-I" ] && shift
echo "python3 $*" >> '`+log+`'
if [ "$1 $2" = "-m venv" ]; then
  mkdir -p "$4/bin" && cp '`+filepath.Join(dir, "venv-python")+`' "$4/bin/python"; exit 0
fi
if [ "$1" = "-c" ]; then echo "3.12.0 fake"; exit 0; fi
if [ "$1 $2 $3" = "-m pip --version" ]; then echo "pip `+pipVersion+` from /fake (python 3.12)"; exit 0; fi
if [ "$3" = "--python" ]; then env=$(dirname "$(dirname "$4")"); shift 4; else env='`+ambientEnv+`'; shift 2; fi
cmd=$1; shift
install_one() {
  case "$1" in broken*) echo "error: failed building wheel for $1" >&2; return 1;; esac
  mkdir -p "$env/site/$1" && echo "$1" >> "$env/installed"
}
case $cmd in
install)
  last=; prev=; for a in "$@"; do prev=$last; last=$a; done
  if [ "$prev" = "-c" ]; then echo "ERROR: You must give at least one requirement to install" >&2; exit 1; fi
  if [ "$prev" = "-r" ]; then
    if grep -q -e broken -e fail-whole "$last"; then echo "whole file failed" >&2; exit 1; fi
    while read -r l; do [ -n "$l" ] && install_one "$l"; done < "$last"; exit 0
  fi
  case " $* " in *" --require-hashes "*) echo "ERROR: Hashes are required in --require-hashes mode" >&2; exit 1;; esac
  if [ -d "$last" ]; then
    if [ -e "$last/broken" ]; then echo "error: Multiple top-level packages discovered in a flat-layout" >&2; exit 1; fi
    install_one projdep; exit $?
  fi
  skip=; reqs=
  for a in "$@"; do
    if [ -n "$skip" ]; then skip=; continue; fi
    case "$a" in -c) skip=1;; -*) ;; *) reqs="$reqs $a";; esac
  done
  case "$reqs " in *" broken"*) echo "error: failed building wheel" >&2; exit 1;; esac
  for a in $reqs; do install_one "$a"; done; exit 0;;
list)
  printf '['; sep=
  if [ -f "$env/installed" ]; then while read -r n; do printf '%s{"name":"%s","version":"1.0"}' "$sep" "$n"; sep=,; done < "$env/installed"; fi
  printf ']\n';;
show)
  for n in "$@"; do printf 'Name: %s\nVersion: 1.0\nLocation: %s/site\nRequires: \n---\n' "$n" "$env"; done;;
esac
exit 0
`)
	return fakePython{ambient: filepath.Join(dir, "python3"), log: log}
}

func (f fakePython) resolver(opts ...PipResolverOption) *PipResolver {
	r := NewPipResolver(opts...)
	r.lookPath = func(string) (string, error) { return f.ambient, nil }
	return r
}

func (f fakePython) count(t *testing.T, substr string) int {
	t.Helper()
	raw, err := os.ReadFile(f.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.Count(string(raw), substr)
}

// isolatePipEnv keeps provisioned environments in the test's own cache and out
// of any environment the developer has activated.
func isolatePipEnv(t *testing.T) string {
	t.Helper()
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	t.Setenv("VIRTUAL_ENV", "")
	return cache
}

func moduleNames(result *ResolveResult) []string {
	names := make([]string, 0, len(result.Dependencies))
	for _, d := range result.Dependencies {
		names = append(names, d.Module)
	}
	sort.Strings(names)
	return names
}

func TestPipInstall_ResolvesProvisionedVenvNotAmbient(t *testing.T) {
	cache := isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{requirementsFile: "six\nidna\n"})

	result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := moduleNames(result), []string{"idna", "six"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v (the project's requirements, not the ambient pip)", got, want)
	}
	for _, dep := range result.Dependencies {
		if !strings.HasPrefix(dep.Dir, cache) || strings.HasPrefix(dep.Dir, root) {
			t.Fatalf("%s Dir = %s, want it in the user cache and outside the scan tree", dep.Module, dep.Dir)
		}
	}
	if fake.count(t, "-m venv --without-pip") != 1 {
		t.Fatalf("venv was not created without pip")
	}

	if _, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if n := fake.count(t, "-m venv"); n != 1 {
		t.Fatalf("venv created %d times, want the complete one reused", n)
	}
}

func TestPipInstall_RetriesEachRequirementAfterWholeFileFails(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{requirementsFile: "six\nbroken-pkg\nidna\n"})

	result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := moduleNames(result), []string{"idna", "six"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v despite broken-pkg", got, want)
	}

	if _, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if n := fake.count(t, "-m venv"); n != 2 {
		t.Fatalf("venv created %d times, want an incomplete one never reused", n)
	}
}

// A -c constraint is not a requirement of its own: the retry passes it with
// every requirement, and a retry in which every requirement installed caches
// the environment like a whole-file install does.
func TestPipInstall_RetryAppliesConstraintsToEveryRequirement(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{
		requirementsFile:  "# fail-whole\n-c constraints.txt\nsix\nidna\n",
		"constraints.txt": "six==1.16.0\n",
	})

	result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := moduleNames(result), []string{"idna", "six"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v", got, want)
	}
	for _, req := range []string{"six", "idna"} {
		if n := fake.count(t, "install --disable-pip-version-check --no-input -c constraints.txt "+req+"\n"); n != 1 {
			t.Fatalf("%s retried %d times with -c constraints.txt, want once", req, n)
		}
	}
	if n := fake.count(t, "-c constraints.txt\n"); n != 0 {
		t.Fatalf("-c constraints.txt was installed on its own %d times", n)
	}

	if _, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if n := fake.count(t, "-m venv"); n != 1 {
		t.Fatalf("venv created %d times, want the fully retried one cached and reused", n)
	}
}

// Under --require-hashes the retry cannot pass each requirement's --hash, so it
// drops the option rather than fail every requirement for a missing hash.
func TestPipInstall_RetryDropsRequireHashes(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{
		requirementsFile: "--require-hashes\nsix --hash=sha256:abc\nbroken-pkg --hash=sha256:def\n",
	})

	result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := moduleNames(result), []string{"six"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v installed by the retry", got, want)
	}
}

func TestPipInstall_FailsWhenNothingInstalls(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{requirementsFile: "broken-a\nbroken-b\n"})

	_, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err == nil || !strings.Contains(err.Error(), "whole file failed") {
		t.Fatalf("err = %v, want a failure carrying pip's stderr", err)
	}
}

// Without static [project].dependencies, the project is built to learn its
// dependencies.
func TestPipInstall_BuildsProjectWithoutStaticDependencies(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree map[string]string
	}{
		{"dynamic dependencies", map[string]string{"pyproject.toml": "[project]\nname = \"app\"\ndynamic = [\"dependencies\"]\n"}},
		{"setup.py", map[string]string{"setup.py": "setup()\n"}},
		{"pyproject.toml without [project]", map[string]string{"pyproject.toml": "[build-system]\nrequires = [\"setuptools\"]\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePipEnv(t)
			fake := newFakePython(t, "24.0")
			root := writeTree(t, tc.tree)

			result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got, want := moduleNames(result), []string{"projdep"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("modules = %v, want %v", got, want)
			}
			if n := fake.count(t, "--no-input "+root+"\n"); n != 1 {
				t.Fatalf("project built %d times, want once", n)
			}
		})
	}
}

// Static [project].dependencies are installed as requirements: the project's
// build backend never runs, so a project it could not build still yields them.
func TestPipInstall_InstallsStaticDependenciesWithoutBuildingTheProject(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{
		"pyproject.toml":     "[project]\nname = \"app\"\ndependencies = [\"six\", \"idna\"]\n",
		"broken/__init__.py": "",
	})

	result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := moduleNames(result), []string{"idna", "six"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v", got, want)
	}
	if n := fake.count(t, " install --disable-pip-version-check --no-input "+root+"\n"); n != 0 {
		t.Fatalf("pip installed the project directory %d times, want never", n)
	}
}

func TestPipInstall_RetriesEachStaticDependency(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"six\", \"broken-pkg\", \"idna\"]\n",
	})

	result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := moduleNames(result), []string{"idna", "six"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v despite broken-pkg", got, want)
	}
	for _, req := range []string{"six", "broken-pkg", "idna"} {
		if n := fake.count(t, "--no-input "+req+"\n"); n != 1 {
			t.Fatalf("%s retried %d times on its own, want once", req, n)
		}
	}
}

// A project pip cannot build, such as a flat layout with several top-level
// packages and a pyproject.toml holding only tool configuration, has no Python
// dependencies to scan, as without --install-dependencies: the scan goes on,
// and the empty environment is not cached.
func TestPipInstall_ProjectThatCannotBuildYieldsNoDependencies(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{
		"pyproject.toml":     "[tool.black]\nline-length = 88\n",
		"app/__init__.py":    "",
		"broken/__init__.py": "",
	})

	for range 2 {
		result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
		if err != nil {
			t.Fatalf("Resolve: %v, want the scan to go on", err)
		}
		if len(result.Dependencies) != 0 {
			t.Fatalf("modules = %v, want none", moduleNames(result))
		}
	}
	if n := fake.count(t, "-m venv"); n != 2 {
		t.Fatalf("venv created %d times, want the failed one never reused", n)
	}
}

// Without a manifest there is nothing to install, and the ambient packages are
// the tool's environment: install mode resolves none of them. Without install
// mode the same project lists them, as it always has.
func TestPipInstall_NoManifestResolvesNothing(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{"app.py": "import os\n"})

	result, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(result.Dependencies) != 0 || fake.count(t, "-m venv") != 0 {
		t.Fatalf("install mode resolved %v (venv runs %d), want nothing", moduleNames(result), fake.count(t, "-m venv"))
	}

	result, err = fake.resolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve without install: %v", err)
	}
	if got := moduleNames(result); !reflect.DeepEqual(got, []string{"pip"}) {
		t.Fatalf("without install modules = %v, want the ambient [pip]", got)
	}
}

func TestPipInstall_UserVenvWins(t *testing.T) {
	for _, tc := range []struct {
		name string
		venv func(t *testing.T, root string) string
	}{
		{"project .venv", func(_ *testing.T, root string) string { return filepath.Join(root, ".venv") }},
		{"VIRTUAL_ENV", func(t *testing.T, _ string) string {
			venv := t.TempDir()
			t.Setenv("VIRTUAL_ENV", venv)
			return venv
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePipEnv(t)
			fake := newFakePython(t, "24.0")
			root := writeTree(t, map[string]string{requirementsFile: "six\n"})
			venv := tc.venv(t, root)
			writeExecutableAll(t, filepath.Join(venv, "bin"), "python")

			env, ok, err := fake.resolver(WithPipInstall()).pythonFor(context.Background(), root)
			if err != nil || !ok {
				t.Fatalf("pythonFor: ok=%v err=%v", ok, err)
			}
			if want := filepath.Join(venv, "bin", "python"); env.python != want {
				t.Fatalf("python = %s, want the user's %s", env.python, want)
			}
			if n := fake.count(t, "-m venv"); n != 0 {
				t.Fatalf("provisioned a venv although the user has one")
			}
		})
	}
}

func TestPipInstall_OldAmbientPipFailsClearly(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "22.0.4")
	root := writeTree(t, map[string]string{requirementsFile: "six\n"})

	_, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root)
	if err == nil || !strings.Contains(err.Error(), "pip 22.3 or later") {
		t.Fatalf("err = %v, want it to name the pip version needed", err)
	}
}

func writeExecutableAll(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, dir, name, "#!/bin/sh\nexit 1\n")
}

func TestParseRequirementUnits(t *testing.T) {
	header, units := parseRequirementUnits(`# pinned
--index-url https://mirror.example/simple
--require-hashes
-c constraints.txt
--no-index
six==1.16.0 --hash=sha256:abc
requests[security] >= 2.0 ; python_version > "3.8"  # comment
-r other.txt
-e .
git+https://example.com/repo.git#egg=pkg
idna \
  ==3.7
`)
	if want := []string{"--index-url", "https://mirror.example/simple", "-c", "constraints.txt", "--no-index"}; !reflect.DeepEqual(header, want) {
		t.Fatalf("header = %q, want %q", header, want)
	}
	want := [][]string{
		{"six==1.16.0"},
		{`requests[security] >= 2.0 ; python_version > "3.8"`},
		{"-r", "other.txt"},
		{"-e", "."},
		{"git+https://example.com/repo.git#egg=pkg"},
		{"idna    ==3.7"},
	}
	if !reflect.DeepEqual(units, want) {
		t.Fatalf("units = %q, want %q", units, want)
	}
}

// A cached environment is reused only while every file the install reads is
// unchanged: requirements.txt, what it includes, and the build files of each
// local project it installs. Creating a missing include counts as a change.
func TestPipInstall_RebuildsWhenAFileTheInstallReadsChanges(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tree    map[string]string
		changed string
	}{
		{"-r include", map[string]string{requirementsFile: "-r requirements/base.txt\n", "requirements/base.txt": "six\n"}, "requirements/base.txt"},
		{"nested include relative to its includer", map[string]string{
			requirementsFile:          "--requirement=requirements/base.txt\n",
			"requirements/base.txt":   "-r common.txt\n",
			"requirements/common.txt": "six\n",
		}, "requirements/common.txt"},
		{"include cycle", map[string]string{requirementsFile: "six\n-r other.txt\n", "other.txt": "-r requirements.txt\nidna\n"}, "other.txt"},
		{"-c constraint", map[string]string{requirementsFile: "-c constraints.txt\nsix\n", "constraints.txt": "six==1.16.0\n"}, "constraints.txt"},
		{"missing include", map[string]string{requirementsFile: "six\n-r extra.txt\n"}, "extra.txt"},
		{"static [project].dependencies", map[string]string{"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"six\"]\n"}, "pyproject.toml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePipEnv(t)
			fake := newFakePython(t, "24.0")
			root := writeTree(t, tc.tree)
			resolve := func() {
				t.Helper()
				if _, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root); err != nil {
					t.Fatalf("Resolve: %v", err)
				}
			}

			resolve()
			resolve()
			if n := fake.count(t, "-m venv"); n != 1 {
				t.Fatalf("venv created %d times before any change, want 1", n)
			}
			changed := filepath.Join(root, tc.changed)
			if err := os.MkdirAll(filepath.Dir(changed), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(changed, []byte("changed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			resolve()
			if n := fake.count(t, "-m venv"); n != 2 {
				t.Fatalf("venv created %d times after %s changed, want it rebuilt", n, tc.changed)
			}
		})
	}
}

// A project build reads its dependencies wherever the build backend looks,
// such as a setuptools dynamic file, so no key covers its inputs: its
// environment is rebuilt for every scan instead of reused stale.
func TestPipInstall_ProjectBuildIsNeverReused(t *testing.T) {
	dynamic := "[project]\nname = \"app\"\ndynamic = [\"dependencies\"]\n" +
		"[tool.setuptools.dynamic]\ndependencies = {file = [\"requirements.in\"]}\n"
	for _, tc := range []struct {
		name string
		tree map[string]string
	}{
		{"project build", map[string]string{"pyproject.toml": dynamic, "requirements.in": "six\n"}},
		{"-e .", map[string]string{requirementsFile: "-e .\n", "pyproject.toml": dynamic, "requirements.in": "six\n"}},
		{"--editable path", map[string]string{requirementsFile: "--editable ./lib\n", "lib/setup.py": "setup()\n"}},
		{"bare local path", map[string]string{requirementsFile: "./lib[extra]\n", "lib/setup.cfg": "[metadata]\n"}},
		{"file: URL", map[string]string{requirementsFile: "file:lib#egg=lib\n", "lib/pyproject.toml": "[project]\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePipEnv(t)
			fake := newFakePython(t, "24.0")
			root := writeTree(t, tc.tree)
			for range 2 {
				if _, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), root); err != nil {
					t.Fatalf("Resolve: %v", err)
				}
			}
			if n := fake.count(t, "-m venv"); n != 2 {
				t.Fatalf("venv created %d times over two scans of a local project build, want 2", n)
			}
		})
	}
}

// A relative target reaches Resolve as given. pip runs inside it, so the paths
// handed to it must be absolute, or `myapp` is installed from PyPI.
func TestPipInstall_RelativeTargetInstallsTheProjectDirectory(t *testing.T) {
	isolatePipEnv(t)
	fake := newFakePython(t, "24.0")
	root := writeTree(t, map[string]string{"setup.cfg": "[metadata]\nname = app\n"})
	t.Chdir(filepath.Dir(root))

	if _, err := fake.resolver(WithPipInstall()).Resolve(context.Background(), filepath.Base(root)); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if n := fake.count(t, " install --disable-pip-version-check --no-input "+root+"\n"); n != 1 {
		t.Fatalf("pip installed the absolute project directory %d times, want 1", n)
	}
}

// An environment used for one scan only stays until a later provision finds it
// older than staleStagingAge; a complete environment and a recent one stay.
func TestSweepStaleStaging(t *testing.T) {
	parent := t.TempDir()
	old := time.Now().Add(-2 * staleStagingAge)
	for name, mtime := range map[string]time.Time{"k1.tmp-1": old, "k2.tmp-2": time.Now(), "k3": old} {
		dir := filepath.Join(parent, name)
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	sweepStaleStaging(parent, time.Now().Add(-staleStagingAge))
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	left := make([]string, 0, len(entries))
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if !slices.Equal(left, []string{"k2.tmp-2", "k3"}) {
		t.Fatalf("left %v, want [k2.tmp-2 k3]", left)
	}
}
