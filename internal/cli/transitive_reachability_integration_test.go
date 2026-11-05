// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cli_test

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// appModule stands for the scanned application in transitiveFinding.module
// and in chain module lists: findings and frames with no dependency.
const appModule = ""

// transitiveFinding is the expected verdict of one finding, named by the
// dependency it sits in (appModule for the application), its file's base name
// and its line.
type transitiveFinding struct {
	module, file string
	line         int
	reachability string
	// chain lists, in order, the modules a reachable finding's call chain
	// must pass through, from the application to the finding.
	chain []string
}

// transitiveReachabilityCase names a fixture under
// testdata/projects/transitive_reachability/<fixture>: app/ is the target, it
// depends on liba/, which depends on libb/. Only app/ and libb/ hash.
type transitiveReachabilityCase struct {
	language string
	// fixture is the fixture directory and the subtest name. Empty means
	// the language's own fixture.
	fixture string
	tools   []string
	// needsNetwork marks a case whose toolchain downloads build plugins. It
	// runs only when networkTestsEnv is set to 1.
	needsNetwork bool
	// env prepares the dependencies of fixture/app and returns extra
	// variables for the run.
	env      func(t *testing.T, fixture string) []string
	liba     string
	libb     string
	findings []transitiveFinding
}

// networkTestsEnv opts in to the cases that need the network.
const networkTestsEnv = "CRYPTO_FINDER_NETWORK_TESTS"

// The moat case: app (no crypto in the path) -> liba (no crypto) -> libb
// (crypto). libb's hashing the app reaches through liba must read reachable
// with a chain crossing all three; the hashing behind a liba function the app
// never calls must read unreachable, and so must the app's own dead hashing.
func TestTransitiveReachability(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI test with real scanner and toolchains")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	t.Parallel()

	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	rules := filepath.Join(root, "testdata", "rules", "transitive-reachability.yaml")

	cases := []transitiveReachabilityCase{
		{
			language: "go", tools: []string{"go"},
			env:  func(t *testing.T, _ string) []string { return isolatedHome(t) },
			liba: "example.com/transliba", libb: "example.com/translibb",
			findings: []transitiveFinding{
				{module: appModule, file: "main.go", line: 18, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule}},
				{module: appModule, file: "main.go", line: 22, reachability: graphfrag.ReachabilityUnreachable},
				{module: "example.com/translibb", file: "libb.go", line: 11, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule, "example.com/transliba", "example.com/translibb"}},
				{module: "example.com/translibb", file: "libb.go", line: 17, reachability: graphfrag.ReachabilityUnreachable},
			},
		},
		{
			language: "python", tools: []string{"python3"},
			env:  pythonVenvWithTransitiveChain,
			liba: "transliba", libb: "translibb",
			findings: []transitiveFinding{
				{module: appModule, file: "main.py", line: 7, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule}},
				{module: appModule, file: "main.py", line: 11, reachability: graphfrag.ReachabilityUnreachable},
				{module: "translibb", file: "__init__.py", line: 7, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule, "transliba", "translibb"}},
				{module: "translibb", file: "__init__.py", line: 11, reachability: graphfrag.ReachabilityUnreachable},
			},
		},
		{
			// The npm resolver runs no tool: it reads package-lock.json and
			// the node_modules tree, which the env lays out by hand. So this
			// case needs no node toolchain.
			language: "javascript",
			env:      nodeModulesWithTransitiveChain,
			liba:     "transliba", libb: "translibb",
			findings: []transitiveFinding{
				{module: appModule, file: "index.js", line: 5, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule}},
				{module: appModule, file: "index.js", line: 9, reachability: graphfrag.ReachabilityUnreachable},
				{module: "translibb", file: "index.js", line: 5, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule, "transliba", "translibb"}},
				{module: "translibb", file: "index.js", line: 9, reachability: graphfrag.ReachabilityUnreachable},
			},
		},
		{
			// transhash stands in for a hashing crate: the Rust filter drops a
			// match on a type the scanned source declares itself, so the
			// hashing types live in a crate of their own, as sha2's do.
			language: "rust", tools: []string{"cargo"},
			env:  cargoWithIsolatedHome,
			liba: "transliba", libb: "translibb",
			findings: []transitiveFinding{
				{module: appModule, file: "main.rs", line: 4, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule}},
				{module: appModule, file: "main.rs", line: 9, reachability: graphfrag.ReachabilityUnreachable},
				{module: "translibb", file: "lib.rs", line: 7, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule, "transliba", "translibb"}},
				{module: "translibb", file: "lib.rs", line: 12, reachability: graphfrag.ReachabilityUnreachable},
			},
		},
		{
			// The rust case with packages source cannot spell: trans-liba is
			// trans_liba in a caller, and trans-libb sets [lib] name, so
			// callers write libb_hashing.
			language: "rust", fixture: "rust_dashed", tools: []string{"cargo"},
			env:  cargoWithIsolatedHome,
			liba: "trans-liba", libb: "trans-libb",
			findings: []transitiveFinding{
				{module: appModule, file: "main.rs", line: 4, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule}},
				{module: appModule, file: "main.rs", line: 9, reachability: graphfrag.ReachabilityUnreachable},
				{module: "trans-libb", file: "lib.rs", line: 8, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule, "trans-liba", "trans-libb"}},
				{module: "trans-libb", file: "lib.rs", line: 13, reachability: graphfrag.ReachabilityUnreachable},
			},
		},
		{
			// Maven downloads its plugins even though liba and libb are
			// installed from the fixture, into a local repository of the
			// test's own that the scan reaches through MAVEN_OPTS. Each
			// project has a groupId of its own.
			language: "java", tools: []string{"mvn", "java"}, needsNetwork: true,
			env:  mavenRepositoryWithTransitiveChain,
			liba: "example.transliba:transliba", libb: "example.translibb:translibb",
			findings: []transitiveFinding{
				{module: appModule, file: "Main.java", line: 19, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule}},
				{module: appModule, file: "Main.java", line: 23, reachability: graphfrag.ReachabilityUnreachable},
				{module: "example.translibb:translibb", file: "Hashing.java", line: 13, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule, "example.transliba:transliba", "example.translibb:translibb"}},
				{module: "example.translibb:translibb", file: "Hashing.java", line: 18, reachability: graphfrag.ReachabilityUnreachable},
			},
		},
		{
			// The java case with one groupId for app, liba and libb, as an
			// in-house library has: their packages all sit under it. The
			// groupId names no application code, so liba's unused stays a
			// dependency function and is no chain root.
			language: "java", fixture: "java_shared_groupid", tools: []string{"mvn", "java"}, needsNetwork: true,
			env:  mavenRepositoryWithTransitiveChain,
			liba: "example.shared:transliba", libb: "example.shared:translibb",
			findings: []transitiveFinding{
				{module: appModule, file: "Main.java", line: 19, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule}},
				{module: appModule, file: "Main.java", line: 23, reachability: graphfrag.ReachabilityUnreachable},
				{module: "example.shared:translibb", file: "Hashing.java", line: 13, reachability: graphfrag.ReachabilityReachable, chain: []string{appModule, "example.shared:transliba", "example.shared:translibb"}},
				{module: "example.shared:translibb", file: "Hashing.java", line: 18, reachability: graphfrag.ReachabilityUnreachable},
			},
		},
	}
	for _, tc := range cases {
		fixtureDir := tc.fixture
		switch {
		case fixtureDir != "":
		case tc.language == "javascript":
			fixtureDir = "node"
		default:
			fixtureDir = tc.language
		}
		name := tc.fixture
		if name == "" {
			name = tc.language
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var missing []string
			for _, tool := range tc.tools {
				if _, err := exec.LookPath(tool); err != nil {
					missing = append(missing, tool+" not installed")
				}
			}
			if tc.needsNetwork && os.Getenv(networkTestsEnv) != "1" {
				missing = append(missing, networkTestsEnv+"=1 not set, and this case needs the network")
			}
			if len(missing) > 0 {
				t.Skip(strings.Join(missing, "; "))
			}
			work := t.TempDir()
			fixture := filepath.Join(work, "fixture")
			require.NoError(t, os.CopyFS(fixture, os.DirFS(filepath.Join(root, "testdata", "projects", "transitive_reachability", fixtureDir))))
			env := append(withoutEnv(os.Environ(), "VIRTUAL_ENV"), tc.env(t, fixture)...)

			pass := runReachabilityPass(t, binary, env, rules, tc.language, filepath.Join(fixture, "app"), filepath.Join(work, "out"), "--scan-dependencies")
			got := transitiveVerdicts(&pass)
			for key, v := range got {
				t.Logf("%-40s %-12s dependency=%s chains=%v", key, v.graph.Reachability, describeDependency(v.graph.Dependency), v.chains)
			}

			for _, want := range tc.findings {
				key := transitiveKey(want.module, want.file, want.line)
				t.Run(key, func(t *testing.T) {
					v, ok := got[key]
					require.Truef(t, ok, "no finding at %s; findings: %v", key, keys(got))
					if want.module == appModule {
						require.Equal(t, "direct", v.source, "%s is application code", key)
						require.Nil(t, v.graph.Dependency, "%s is application code", key)
					} else {
						require.Equal(t, "dependency", v.source, "%s sits in a dependency", key)
						require.NotNil(t, v.graph.Dependency, "%s sits in a dependency", key)
						require.Equal(t, want.module, v.graph.Dependency.Module)
						require.Equal(t, graphfrag.DependencyTransitive, v.graph.Dependency.Relationship, "%s is reached through %s", want.module, tc.liba)
						var route []string
						for _, step := range v.graph.Dependency.Path {
							route = append(route, step.Module)
						}
						require.Equal(t, []string{tc.liba, tc.libb}, route, "dependency path to %s", want.module)
					}
					require.Equal(t, want.reachability, v.graph.Reachability, "reachability of %s", key)
					if want.chain != nil {
						require.Truef(t, hasChainThrough(v.chains, want.chain), "no call chain of %s crosses %q in order; chains: %v", key, want.chain, v.chains)
					}
				})
			}
		})
	}
}

// transitiveVerdict is one exported finding graph with what the findings
// report says about the same finding.
type transitiveVerdict struct {
	graph  graphfrag.ExportFindingGraph
	source string
	// chains lists each call chain as the module of every frame, appModule
	// for frames in the application.
	chains [][]string
}

func transitiveVerdicts(pass *reachabilityPass) map[string]transitiveVerdict {
	type located struct {
		file   string
		line   int
		source string
	}
	byID := map[string]located{}
	for _, finding := range pass.report.Findings {
		for i := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[i]
			byID[asset.FindingID] = located{file: path.Base(filepath.ToSlash(finding.FilePath)), line: asset.StartLine, source: asset.Source}
		}
	}
	functions := pass.export.Functions
	out := map[string]transitiveVerdict{}
	for i := range pass.export.FindingGraphs {
		graph := pass.export.FindingGraphs[i]
		loc := byID[graph.FindingID]
		module := appModule
		if graph.Dependency != nil {
			module = graph.Dependency.Module
		}
		v := transitiveVerdict{graph: graph, source: loc.source}
		for _, chain := range graph.CallChainIndexes {
			modules := make([]string, 0, len(chain))
			for _, idx := range chain {
				module := appModule
				if info := functions[idx].DependencyInfo; info != nil {
					module = info.Module
				}
				modules = append(modules, module)
			}
			v.chains = append(v.chains, modules)
		}
		out[transitiveKey(module, loc.file, loc.line)] = v
	}
	return out
}

func transitiveKey(module, file string, line int) string {
	if module == appModule {
		module = "app"
	}
	return fmt.Sprintf("%s/%s:%d", module, file, line)
}

// hasChainThrough reports whether some chain starts in the application, ends
// in want's last module, and visits every module of want in order.
func hasChainThrough(chains [][]string, want []string) bool {
	for _, chain := range chains {
		if len(chain) == 0 || chain[0] != want[0] || chain[len(chain)-1] != want[len(want)-1] {
			continue
		}
		next := 0
		for _, module := range chain {
			if next < len(want) && module == want[next] {
				next++
			}
		}
		if next == len(want) {
			return true
		}
	}
	return false
}

func describeDependency(dep *graphfrag.ExportFindingDependency) string {
	if dep == nil {
		return "-"
	}
	var route []string
	for _, step := range dep.Path {
		route = append(route, step.Module)
	}
	return fmt.Sprintf("%s(%s via %s)", dep.Module, dep.Relationship, strings.Join(route, ">"))
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// pythonVenvWithTransitiveChain installs the fixture's liba and libb into a
// venv outside the target, liba declaring libb as its requirement.
func pythonVenvWithTransitiveChain(t *testing.T, fixture string) []string {
	t.Helper()
	venv, sitePackages := newPythonVenv(t)
	installVenvPackage(t, sitePackages, "translibb", packageSources(t, filepath.Join(fixture, "libb", "translibb")))
	installVenvPackage(t, sitePackages, "transliba", packageSources(t, filepath.Join(fixture, "liba", "transliba")), "translibb")
	return append(isolatedHome(t), "VIRTUAL_ENV="+venv)
}

// nodeModulesWithTransitiveChain lays fixture/liba and fixture/libb out as
// app/node_modules/transliba and app/node_modules/translibb, the hoisted tree
// npm installs for the lockfile the fixture's app/ carries.
func nodeModulesWithTransitiveChain(t *testing.T, fixture string) []string {
	t.Helper()
	for pkg, dir := range map[string]string{"transliba": "liba", "translibb": "libb"} {
		require.NoError(t, os.CopyFS(filepath.Join(fixture, "app", "node_modules", pkg), os.DirFS(filepath.Join(fixture, dir))))
	}
	return isolatedHome(t)
}

// cargoWithIsolatedHome isolates HOME, which also moves CARGO_HOME, and keeps
// the rustup toolchains the cargo proxy needs. Path dependencies need no
// registry, so cargo metadata runs offline.
func cargoWithIsolatedHome(t *testing.T, _ string) []string {
	t.Helper()
	env := isolatedHome(t)
	if os.Getenv("RUSTUP_HOME") == "" {
		if home, err := os.UserHomeDir(); err == nil {
			env = append(env, "RUSTUP_HOME="+filepath.Join(home, ".rustup"))
		}
	}
	return env
}

// mavenRepositoryWithTransitiveChain installs fixture/libb and then
// fixture/liba, each with its sources JAR, into a local repository in a
// temporary directory, and points the scan at it through MAVEN_OPTS. HOME is
// isolated as well, so neither the install nor the scan touches ~/.m2.
func mavenRepositoryWithTransitiveChain(t *testing.T, fixture string) []string {
	t.Helper()
	env := isolatedHome(t)
	repo := t.TempDir()
	for _, lib := range []string{"libb", "liba"} {
		cmd := exec.CommandContext(t.Context(), "mvn", "-q", "-B", "install", "-DskipTests", "-Dmaven.repo.local="+repo)
		cmd.Dir = filepath.Join(fixture, lib)
		cmd.Env = append(withoutEnv(os.Environ(), "MAVEN_OPTS"), env...)
		output, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "mvn install %s:\n%s", lib, output)
	}
	return append(env, "MAVEN_OPTS=-Dmaven.repo.local="+repo)
}

// packageSources reads every file under dir, keyed by its path inside dir.
func packageSources(t *testing.T, dir string) map[string]string {
	t.Helper()
	sources := map[string]string{}
	require.NoError(t, filepath.WalkDir(dir, func(file string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, file)
		if err != nil {
			return err
		}
		sources[rel] = string(content)
		return nil
	}))
	return sources
}
