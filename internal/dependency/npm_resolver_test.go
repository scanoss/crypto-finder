package dependency

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree materializes a fixture project: every key is a path relative to the
// project root, every value its contents. Directories are created as needed.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func depsByModule(result *ResolveResult) map[string]Dependency {
	out := make(map[string]Dependency, len(result.Dependencies))
	for _, d := range result.Dependencies {
		out[d.Module] = d
	}
	return out
}

func TestNpmResolver_Ecosystem(t *testing.T) {
	if got := NewNpmResolver().Ecosystem(); got != "node" {
		t.Fatalf("Ecosystem() = %q, want %q", got, "node")
	}
}

// A dependency whose Dir does not exist parses to nothing, so the Dir is the
// part of the result that carries the evidence. Every assertion here is on a
// directory that is really on disk.
func TestNpmResolver_ResolvesInstalledTreeFromLockfileV3(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"}},
		    "node_modules/node-forge":{"version":"1.4.0","dependencies":{"safe-buffer":"^5.2.1"}},
		    "node_modules/safe-buffer":{"version":"5.2.1"}
		  }
		}`,
		"node_modules/node-forge/package.json":  `{"name":"node-forge","version":"1.4.0"}`,
		"node_modules/node-forge/lib/md.js":     "module.exports = {};\n",
		"node_modules/safe-buffer/package.json": `{"name":"safe-buffer","version":"5.2.1"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.RootModule != "app" {
		t.Errorf("RootModule = %q, want %q", result.RootModule, "app")
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("Dependencies = %d, want 2: %+v", len(result.Dependencies), result.Dependencies)
	}

	byMod := depsByModule(result)
	forge, ok := byMod["node-forge"]
	if !ok {
		t.Fatalf("node-forge missing from %+v", result.Dependencies)
	}
	if forge.Version != "1.4.0" {
		t.Errorf("node-forge version = %q, want 1.4.0", forge.Version)
	}
	if !filepath.IsAbs(forge.Dir) {
		t.Errorf("Dir = %q, want an absolute path", forge.Dir)
	}
	if _, statErr := os.Stat(filepath.Join(forge.Dir, "lib", "md.js")); statErr != nil {
		t.Errorf("Dir %q does not hold the dependency source: %v", forge.Dir, statErr)
	}

	if got := result.Graph["app"]; len(got) != 1 || got[0] != "node-forge" {
		t.Errorf("Graph[app] = %v, want [node-forge]", got)
	}
	if got := result.Graph["node-forge"]; len(got) != 1 || got[0] != "safe-buffer" {
		t.Errorf("Graph[node-forge] = %v, want [safe-buffer]", got)
	}
	edges := result.VersionedGraph["node-forge@1.4.0"]
	if len(edges) != 1 || edges[0].Key() != "safe-buffer@5.2.1" {
		t.Errorf("VersionedGraph[node-forge@1.4.0] = %v, want [safe-buffer@5.2.1]", edges)
	}
}

// npm installs a second copy under the dependent when versions conflict. Both
// copies are real source on disk and they are different code, so a resolver that
// guesses `node_modules/<name>` reports one of them twice.
func TestNpmResolver_ResolvesNestedInstallToTheDirectoryOnDisk(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"legacy":"1.0.0","shared":"2.0.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"legacy":"1.0.0","shared":"2.0.0"}},
		    "node_modules/legacy":{"version":"1.0.0","dependencies":{"shared":"1.0.0"}},
		    "node_modules/legacy/node_modules/shared":{"version":"1.0.0"},
		    "node_modules/shared":{"version":"2.0.0"}
		  }
		}`,
		"node_modules/legacy/package.json":                     `{"name":"legacy","version":"1.0.0"}`,
		"node_modules/legacy/node_modules/shared/package.json": `{"name":"shared","version":"1.0.0"}`,
		"node_modules/legacy/node_modules/shared/old.js":       "module.exports = 1;\n",
		"node_modules/shared/package.json":                     `{"name":"shared","version":"2.0.0"}`,
		"node_modules/shared/new.js":                           "module.exports = 2;\n",
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(result.Dependencies) != 3 {
		t.Fatalf("Dependencies = %d, want 3: %+v", len(result.Dependencies), result.Dependencies)
	}

	dirs := map[string]string{}
	for _, d := range result.Dependencies {
		if d.Module == "shared" {
			dirs[d.Version] = d.Dir
		}
	}
	if len(dirs) != 2 {
		t.Fatalf("expected both shared versions, got %v", dirs)
	}
	if dirs["1.0.0"] == dirs["2.0.0"] {
		t.Fatalf("both shared copies resolved to one directory %q", dirs["1.0.0"])
	}
	if _, err := os.Stat(filepath.Join(dirs["1.0.0"], "old.js")); err != nil {
		t.Errorf("shared@1.0.0 Dir %q is not the nested copy: %v", dirs["1.0.0"], err)
	}
	if _, err := os.Stat(filepath.Join(dirs["2.0.0"], "new.js")); err != nil {
		t.Errorf("shared@2.0.0 Dir %q is not the hoisted copy: %v", dirs["2.0.0"], err)
	}

	// legacy depends on shared@1.0.0, the nested copy, not the hoisted 2.0.0.
	edges := result.VersionedGraph["legacy@1.0.0"]
	if len(edges) != 1 || edges[0].Key() != "shared@1.0.0" {
		t.Errorf("VersionedGraph[legacy@1.0.0] = %v, want [shared@1.0.0]", edges)
	}
}

func TestNpmResolver_ResolvesLockfileV1NestedShape(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"legacy":"1.0.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":1,
		  "dependencies":{
		    "legacy":{"version":"1.0.0","requires":{"shared":"1.0.0"},
		      "dependencies":{"shared":{"version":"1.0.0"}}}
		  }
		}`,
		"node_modules/legacy/package.json":                     `{"name":"legacy","version":"1.0.0"}`,
		"node_modules/legacy/node_modules/shared/package.json": `{"name":"shared","version":"1.0.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	byMod := depsByModule(result)
	if _, ok := byMod["legacy"]; !ok {
		t.Fatalf("legacy missing: %+v", result.Dependencies)
	}
	shared, ok := byMod["shared"]
	if !ok {
		t.Fatalf("nested shared missing: %+v", result.Dependencies)
	}
	if !strings.Contains(shared.Dir, filepath.Join("legacy", "node_modules", "shared")) {
		t.Errorf("shared Dir = %q, want the copy nested under legacy", shared.Dir)
	}
}

// A lockfile with no install is a tree that looks resolved and parses to nothing.
// It must fail loudly: dependency_scanner.go turns a Resolve error into
// CodeDependencyResolutionFailed, while a hollow result would be reported as a
// clean scan with no findings.
func TestNpmResolver_AbsentNodeModulesIsAnExplicitFailure(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"}},
		    "node_modules/node-forge":{"version":"1.4.0"}
		  }
		}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err == nil {
		t.Fatalf("Resolve returned no error; got %d dependencies", len(result.Dependencies))
	}
	if !strings.Contains(err.Error(), "node_modules") {
		t.Errorf("error %q does not name node_modules, so the cause is not actionable", err)
	}
}

// A project with no lockfile at all is a different cause and must say so.
func TestNpmResolver_MissingLockfileIsNamed(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0"}`,
	})
	if _, err := NewNpmResolver().Resolve(context.Background(), root); err == nil {
		t.Fatal("Resolve returned no error for a project with no lockfile")
	} else if !strings.Contains(err.Error(), "package-lock.json") {
		t.Errorf("error %q does not name the missing lockfile", err)
	}
}

// Dev dependencies are build tooling: including them multiplies the scanned tree
// without adding anything that ships. The exclusion is deliberate, so it is
// pinned rather than left to be rediscovered.
func TestNpmResolver_DevDependenciesAreExcluded(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"},"devDependencies":{"tap":"^16.0.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0"},
		    "node_modules/node-forge":{"version":"1.4.0"},
		    "node_modules/tap":{"version":"16.0.0","dev":true}
		  }
		}`,
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
		"node_modules/tap/package.json":        `{"name":"tap","version":"16.0.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, dev := depsByModule(result)["tap"]; dev {
		t.Errorf("dev dependency tap was resolved: %+v", result.Dependencies)
	}
	if _, prod := depsByModule(result)["node-forge"]; !prod {
		t.Errorf("production dependency node-forge missing: %+v", result.Dependencies)
	}
}

// A scoped package's directory is node_modules/@scope/name, two path segments.
func TestNpmResolver_ScopedPackageResolves(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"@noble/hashes":"^1.3.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"@noble/hashes":"^1.3.0"}},
		    "node_modules/@noble/hashes":{"version":"1.3.0"}
		  }
		}`,
		"node_modules/@noble/hashes/package.json": `{"name":"@noble/hashes","version":"1.3.0"}`,
		"node_modules/@noble/hashes/sha256.js":    "module.exports = {};\n",
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	dep, ok := depsByModule(result)["@noble/hashes"]
	if !ok {
		t.Fatalf("@noble/hashes missing: %+v", result.Dependencies)
	}
	if _, err := os.Stat(filepath.Join(dep.Dir, "sha256.js")); err != nil {
		t.Errorf("scoped Dir %q is wrong: %v", dep.Dir, err)
	}
}
