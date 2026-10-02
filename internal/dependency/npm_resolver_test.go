package dependency

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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

// npmDevTree is a v3 install holding production packages, dev-only packages
// at the top level and nested under another dev package, and a devOptional
// package, which npm installs without dev when an optional dependency needs it.
func npmDevTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"},"devDependencies":{"tap":"^16.0.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"},"devDependencies":{"tap":"^16.0.0"}},
		    "node_modules/node-forge":{"version":"1.4.0"},
		    "node_modules/tap":{"version":"16.0.0","dev":true,"dependencies":{"jsonwebtoken":"^9.0.0"}},
		    "node_modules/tap/node_modules/jsonwebtoken":{"version":"9.0.0","dev":true},
		    "node_modules/fsevents":{"version":"2.3.3","devOptional":true,"optional":true}
		  }
		}`,
		"node_modules/node-forge/package.json":                    `{"name":"node-forge","version":"1.4.0"}`,
		"node_modules/tap/package.json":                           `{"name":"tap","version":"16.0.0"}`,
		"node_modules/tap/node_modules/jsonwebtoken/package.json": `{"name":"jsonwebtoken","version":"9.0.0"}`,
		"node_modules/fsevents/package.json":                      `{"name":"fsevents","version":"2.3.3"}`,
	})
}

// The default inventory is the production tree, as for Go (the production
// import closure) and Java (compile scope): an installed dev-only package is
// build tooling and is neither scanned nor put in the graph.
func TestNpmResolver_DevDependenciesExcludedByDefault(t *testing.T) {
	result, err := NewNpmResolver().Resolve(context.Background(), npmDevTree(t))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := npmModules(result), []string{"fsevents", "node-forge"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v", got, want)
	}
	for node := range result.Graph {
		if strings.Contains(node, "tap") || strings.Contains(node, "jsonwebtoken") {
			t.Fatalf("dev package %q is in the graph: %v", node, result.Graph)
		}
	}
}

// WithNpmDevDependencies restores dev packages, so cryptography that exists
// only there can still be inventoried: jsonwebtoken as a devDependency brings
// a jwa subtree calling crypto.createHmac and crypto.createSign.
func TestNpmResolver_WithDevDependenciesResolvesThem(t *testing.T) {
	result, err := NewNpmResolver(WithNpmDevDependencies()).Resolve(context.Background(), npmDevTree(t))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := npmModules(result), []string{"fsevents", "jsonwebtoken", "node-forge", "tap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v, want %v", got, want)
	}
}

// A v1 lockfile nests a dev package's own dependencies under it; they are dev
// too and leave with it.
func TestNpmResolver_V1DevDependenciesExcludedByDefault(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"},"devDependencies":{"tap":"^16.0.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":1,
		  "dependencies":{
		    "node-forge":{"version":"1.4.0"},
		    "tap":{"version":"16.0.0","dev":true,"dependencies":{"jsonwebtoken":{"version":"9.0.0","dev":true}}}
		  }
		}`,
		"node_modules/node-forge/package.json":                    `{"name":"node-forge","version":"1.4.0"}`,
		"node_modules/tap/package.json":                           `{"name":"tap","version":"16.0.0"}`,
		"node_modules/tap/node_modules/jsonwebtoken/package.json": `{"name":"jsonwebtoken","version":"9.0.0"}`,
	})
	for _, tc := range []struct {
		opts []NpmResolverOption
		want []string
	}{
		{nil, []string{"node-forge"}},
		{[]NpmResolverOption{WithNpmDevDependencies()}, []string{"jsonwebtoken", "node-forge", "tap"}},
	} {
		result, err := NewNpmResolver(tc.opts...).Resolve(context.Background(), root)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got := npmModules(result); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("modules with %d options = %v, want %v", len(tc.opts), got, tc.want)
		}
	}
}

func npmModules(result *ResolveResult) []string {
	modules := make([]string, 0, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		modules = append(modules, dep.Module)
	}
	sort.Strings(modules)
	return modules
}

// An uninstalled dev package is ordinary: `npm install --omit=dev` is a normal
// production image. It must not fail the scan the way a missing required
// package does.
func TestNpmResolver_UninstalledDevDependencyDoesNotFail(t *testing.T) {
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
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("an omitted dev dependency must not fail the scan: %v", err)
	}
	if len(result.Dependencies) != 1 {
		t.Errorf("Dependencies = %d, want 1: %+v", len(result.Dependencies), result.Dependencies)
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

// A workspace member is the user's OWN code. npm records it twice in a v3
// lockfile: once at its real path (`packages/inner`) and once as a symlink entry
// under node_modules carrying `"link": true` and no version. Reporting either as
// a dependency attributes the user's own source to an external package, and the
// link entry has no version to form a coordinate from at all.
// A member stays a member when npm marks it dev: it is the project's own code,
// not an installed package, so the dev filter does not apply to it.
func TestNpmResolver_WorkspaceMembersAreNotDependencies(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"mono","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"inner":"*","node-forge":"^1.4.0"}}`,
		"package-lock.json": `{
		  "name":"mono","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"mono","version":"1.0.0","dependencies":{"inner":"*","node-forge":"^1.4.0"}},
		    "packages/inner":{"name":"inner","version":"1.0.0","dev":true},
		    "node_modules/inner":{"resolved":"packages/inner","link":true},
		    "node_modules/node-forge":{"version":"1.4.0"}
		  }
		}`,
		"packages/inner/package.json":          `{"name":"inner","version":"1.0.0"}`,
		"packages/inner/crypto.js":             "module.exports = 1;\n",
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
	})
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "packages", "inner"), filepath.Join(root, "node_modules", "inner")); err != nil {
		t.Fatal(err)
	}

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, d := range result.Dependencies {
		if d.Module == "inner" {
			t.Errorf("workspace member reported as a dependency at %q", d.Dir)
		}
		if d.Version == "" {
			t.Errorf("dependency %q has no version, so it has no coordinate: dir=%q", d.Module, d.Dir)
		}
	}
	if len(result.Dependencies) != 1 {
		t.Errorf("Dependencies = %d, want 1 (node-forge only): %+v", len(result.Dependencies), result.Dependencies)
	}

	if len(result.WorkspaceMembers) != 1 {
		t.Fatalf("WorkspaceMembers = %d, want 1: %+v", len(result.WorkspaceMembers), result.WorkspaceMembers)
	}
	member := result.WorkspaceMembers[0]
	if member.Name != "inner" {
		t.Errorf("member name = %q, want inner", member.Name)
	}
	if _, statErr := os.Stat(filepath.Join(member.Dir, "crypto.js")); statErr != nil {
		t.Errorf("member Dir %q is not the real source: %v", member.Dir, statErr)
	}
}

// Platform packages are optional and gated on os/cpu, so a healthy linux-x64
// tree is missing most of them BY DESIGN. Counting them made the warning fire on
// every real project: `npm install esbuild` alone left 25 of 26 @esbuild/*
// packages absent. A warning that always fires is the same as no warning.
func TestNpmResolver_AbsentOptionalPlatformPackagesAreNotAFailure(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"esbuild":"^0.20.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"esbuild":"^0.20.0"}},
		    "node_modules/esbuild":{"version":"0.20.0","optionalDependencies":{"@esbuild/linux-x64":"0.20.0","@esbuild/darwin-arm64":"0.20.0"}},
		    "node_modules/@esbuild/linux-x64":{"version":"0.20.0","optional":true},
		    "node_modules/@esbuild/darwin-arm64":{"version":"0.20.0","optional":true}
		  }
		}`,
		"node_modules/esbuild/package.json":            `{"name":"esbuild","version":"0.20.0"}`,
		"node_modules/@esbuild/linux-x64/package.json": `{"name":"@esbuild/linux-x64","version":"0.20.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("an absent optional platform package must not fail the scan: %v", err)
	}
	if _, ok := depsByModule(result)["@esbuild/darwin-arm64"]; ok {
		t.Error("the uninstalled darwin package was reported as resolved")
	}
	// The optional edge that DID install is still an edge.
	edges := result.Graph["esbuild"]
	if len(edges) != 1 || edges[0] != "@esbuild/linux-x64" {
		t.Errorf("Graph[esbuild] = %v, want [@esbuild/linux-x64]", edges)
	}
}

// A missing REQUIRED production package is the incomplete install worth failing
// on. Failing only at exactly zero let a tree missing 48 of 50 required packages
// resolve 2 and exit 0.
func TestNpmResolver_AbsentRequiredPackageFailsAndIsNamed(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0","safe-buffer":"^5.2.1"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0"},
		    "node_modules/node-forge":{"version":"1.4.0"},
		    "node_modules/safe-buffer":{"version":"5.2.1"}
		  }
		}`,
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
	})

	_, err := NewNpmResolver().Resolve(context.Background(), root)
	if err == nil {
		t.Fatal("a partially installed tree resolved without error")
	}
	if !strings.Contains(err.Error(), "safe-buffer") {
		t.Errorf("error %q does not name the missing package, so it is not actionable", err)
	}
}

// An aliased install makes the install path the ALIAS and the entry's name the
// real package. The coordinate must be the real package, and the graph edge must
// carry the same name, or the edge joins nothing.
func TestNpmResolver_AliasedInstallNamesTheRealPackageOnBothSides(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"forge-alias":"npm:node-forge@1.4.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"forge-alias":"npm:node-forge@1.4.0"}},
		    "node_modules/forge-alias":{"name":"node-forge","version":"1.4.0"}
		  }
		}`,
		"node_modules/forge-alias/package.json": `{"name":"node-forge","version":"1.4.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := depsByModule(result)["node-forge"]; !ok {
		t.Fatalf("aliased install did not resolve to the real package: %+v", result.Dependencies)
	}
	children := result.Graph["app"]
	if len(children) != 1 || children[0] != "node-forge" {
		t.Fatalf("Graph[app] = %v, want [node-forge]: the edge must name what the Dependency names", children)
	}
	if edges := result.VersionedGraph["app@1.0.0"]; len(edges) != 1 || edges[0].Key() != "node-forge@1.4.0" {
		t.Errorf("VersionedGraph[app@1.0.0] = %v, want [node-forge@1.4.0]", edges)
	}
}

// A peer dependency is a real edge. Without it, a bridge package on a
// user -> crypto path is not on any chain and the chain cannot be built.
func TestNpmResolver_PeerDependencyEdgesArePresent(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"bridge":"1.0.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"bridge":"1.0.0"}},
		    "node_modules/bridge":{"version":"1.0.0","peerDependencies":{"node-forge":"^1.4.0"}},
		    "node_modules/node-forge":{"version":"1.4.0"}
		  }
		}`,
		"node_modules/bridge/package.json":     `{"name":"bridge","version":"1.0.0"}`,
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := result.Graph["bridge"]; len(got) != 1 || got[0] != "node-forge" {
		t.Errorf("Graph[bridge] = %v, want [node-forge] through the peer edge", got)
	}
}

// The graph must hold nodes only for source that is on disk. Walking the
// lockfile instead put nodes in for packages `ls` could not find.
func TestNpmResolver_GraphHoldsNoNodeForAnUninstalledPackage(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"installed":"1.0.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"installed":"1.0.0"}},
		    "node_modules/installed":{"version":"1.0.0","optionalDependencies":{"ghost":"1.0.0"}},
		    "node_modules/ghost":{"version":"1.0.0","optional":true,"dependencies":{"ghost-child":"1.0.0"}},
		    "node_modules/ghost-child":{"version":"1.0.0","optional":true}
		  }
		}`,
		"node_modules/installed/package.json": `{"name":"installed","version":"1.0.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, phantom := range []string{"ghost", "ghost-child"} {
		if _, ok := result.Graph[phantom]; ok {
			t.Errorf("graph has a node for %q, which is not on disk", phantom)
		}
		for parent, children := range result.Graph {
			for _, child := range children {
				if child == phantom {
					t.Errorf("edge %s -> %s points at a package that is not on disk", parent, phantom)
				}
			}
		}
	}
}

// In a workspace, a member is a graph parent like any other. Its dependencies
// are edges the consumer wrote; omitting them left every one of them an orphan
// with no path from the root, which makes reachability pruning vacuous.
func TestNpmResolver_WorkspaceMemberEdgesArePresent(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"ws-root","version":"1.0.0","workspaces":["packages/*"]}`,
		"package-lock.json": `{
		  "name":"ws-root","version":"1.0.0","lockfileVersion":3,
		  "packages":{
		    "":{"name":"ws-root","version":"1.0.0"},
		    "packages/app":{"name":"@ws/app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"}},
		    "node_modules/@ws/app":{"resolved":"packages/app","link":true},
		    "node_modules/node-forge":{"version":"1.4.0"}
		  }
		}`,
		"packages/app/package.json":            `{"name":"@ws/app","version":"1.0.0"}`,
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := result.Graph["@ws/app"]; len(got) != 1 || got[0] != "node-forge" {
		t.Errorf("Graph[@ws/app] = %v, want [node-forge]", got)
	}
	if edges := result.VersionedGraph["@ws/app@1.0.0"]; len(edges) != 1 || edges[0].Key() != "node-forge@1.4.0" {
		t.Errorf("VersionedGraph[@ws/app@1.0.0] = %v, want [node-forge@1.4.0]", edges)
	}
}

// npm 5.0 and 5.1 wrote `"requires": true`. The code claims to support v1, so
// that shape must not abort the whole dependency scan.
func TestNpmResolver_LockfileV1BooleanRequiresIsTolerated(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"1.4.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":1,
		  "dependencies":{"node-forge":{"version":"1.4.0","requires":true}}
		}`,
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("a v1 lockfile with a boolean requires aborted the scan: %v", err)
	}
	if _, ok := depsByModule(result)["node-forge"]; !ok {
		t.Errorf("node-forge missing: %+v", result.Dependencies)
	}
}

// A v2 lockfile carries BOTH shapes. The doc comment claims `packages` wins;
// nothing tested it.
func TestNpmResolver_LockfileV2PrefersThePackagesMap(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"}}`,
		"package-lock.json": `{
		  "name":"app","version":"1.0.0","lockfileVersion":2,
		  "packages":{
		    "":{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"}},
		    "node_modules/node-forge":{"version":"1.4.0"}
		  },
		  "dependencies":{"node-forge":{"version":"0.0.0-stale"}}
		}`,
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
	})

	result, err := NewNpmResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	dep, ok := depsByModule(result)["node-forge"]
	if !ok {
		t.Fatalf("node-forge missing: %+v", result.Dependencies)
	}
	if dep.Version != "1.4.0" {
		t.Errorf("version = %q, want 1.4.0 from the packages map, not the legacy dependencies block", dep.Version)
	}
}

func TestNpmResolver_CanResolve(t *testing.T) {
	t.Parallel()

	resolver := NewNpmResolver()

	t.Run("package-json-and-lockfile-at-root", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for _, name := range []string{"package.json", "package-lock.json"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"name":"use"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if !resolver.CanResolve(dir) {
			t.Fatal("CanResolve() = false, want true with package.json and package-lock.json at the root")
		}
	})

	// Resolve fails without a lockfile, so claiming the target made a Node
	// package with no lockfile fail the whole scan under --scan-dependencies.
	t.Run("package-json-without-lockfile", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"use"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if resolver.CanResolve(dir) {
			t.Fatal("CanResolve() = true, want false for a package.json with no package-lock.json")
		}
		if got := UnresolvableSkipReason(dir, "node"); got != SkipReasonLockfileAbsent {
			t.Fatalf("UnresolvableSkipReason() = %q, want %q", got, SkipReasonLockfileAbsent)
		}
	})

	t.Run("bare-js-source-without-package-json", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "use.js"), []byte("module.exports = 1;\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if resolver.CanResolve(dir) {
			t.Fatal("CanResolve() = true, want false for a Node source tree with no package.json")
		}
	})
}
