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

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/scanoss/reach/javaruntime"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
)

// Dependency scans have one pipeline: no flag selects or leaves it, and the
// flags of the old pipeline are gone.
func TestApplicationReachabilityIsTheOnlyDependencyPipeline(t *testing.T) {
	for _, gone := range []string{"dependency-reachability-api", "no-dependency-findings-api", "dep-ecosystem", "dep-workers", "findings-cache", "install-dependencies", "include-dev-dependencies"} {
		if scanCmd.Flags().Lookup(gone) != nil {
			t.Errorf("--%s still exists", gone)
		}
	}
	chains := scanCmd.Flags().Lookup("dependency-reachability-max-chains")
	if chains == nil || chains.DefValue != "1" {
		t.Fatalf("--dependency-reachability-max-chains = %+v, want default 1", chains)
	}
}

// A target without a Java build manifest resolves nothing: no closure, no
// runtime, no type JARs, and the skip names why.
func TestPlanApplicationReachabilitySkipsTargetsWithoutJavaBuild(t *testing.T) {
	python := t.TempDir()
	if err := os.WriteFile(filepath.Join(python, "requirements.txt"), []byte("cryptography==42.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target string
		want         dependencySkip
	}{
		{"python dependencies", python, dependencySkip{reason: depSkipEcosystemNotSupported, ecosystem: "python"}},
		{"no manifest", t.TempDir(), dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemJava}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graphs := newGraphStore(tc.target, "given.jar")
			runtimeAsked := false
			plan, skip, err := planApplicationReachability(context.Background(), graphs, tc.target, ecosystemJava, func() (javaruntime.Config, error) {
				runtimeAsked = true
				return javaruntime.Config{}, nil
			}, nil)
			if err != nil || plan != nil || runtimeAsked || graphs.typeJARList() != "given.jar" {
				t.Fatalf("plan %v, err %v, runtime asked %v, type jars %q", plan, err, runtimeAsked, graphs.typeJARList())
			}
			if skip != tc.want {
				t.Errorf("skip = %+v, want %+v", skip, tc.want)
			}
		})
	}
}

// A Python scan resolves the target's Python closure: no Java runtime, no
// type JARs; a requirement without a pin is carried as unpinned. A Python
// target with no manifest, lock or environment is skipped.
func TestPlanApplicationReachabilityPython(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "requirements.txt"), []byte("cryptography==42.0.0\nrequests>=2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	graphs := newGraphStore(target, "given.jar")
	noRuntime := func() (javaruntime.Config, error) {
		t.Error("a Python scan asked for the Java runtime")
		return javaruntime.Config{}, nil
	}
	plan, skip, err := planApplicationReachability(context.Background(), graphs, target, ecosystemPython, noRuntime, nil)
	if err != nil || plan == nil || skip != (dependencySkip{}) {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	if plan.resolver != nil || plan.closure.Ecosystem != ecosystemPython || graphs.typeJARList() != "given.jar" {
		t.Errorf("resolver %v, ecosystem %q, type jars %q", plan.resolver, plan.closure.Ecosystem, graphs.typeJARList())
	}
	deps := plan.closure.Resolved.Dependencies
	if len(deps) != 1 || deps[0].Module != "cryptography" || deps[0].Version != "42.0.0" {
		t.Errorf("dependencies = %+v, want cryptography 42.0.0", deps)
	}
	if u := plan.closure.Resolved.Unpinned; len(u) != 1 || u[0].Module != "requests" || u[0].Specifier != ">=2.0" {
		t.Errorf("unpinned = %+v, want requests >=2.0", u)
	}

	plan, skip, err = planApplicationReachability(context.Background(), graphs, t.TempDir(), ecosystemPython, noRuntime, nil)
	if err != nil || plan != nil || skip != (dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemPython}) {
		t.Errorf("no manifest: plan %v, skip %+v, err %v", plan, skip, err)
	}
}

// A node scan plans its dependencies from the lock file, never as Java even
// beside a Java build: pinned runtime packages are the closure, dev-only ones
// are left out, and the plan has no Java resolver or type JARs.
func TestPlanApplicationReachabilityNode(t *testing.T) {
	target := t.TempDir()
	lock := `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"@noble/hashes":"^1.3.0"},"devDependencies":{"jest":"^29.0.0"}},
"node_modules/@noble/hashes":{"version":"1.3.2"},
"node_modules/jest":{"version":"29.7.0","dev":true}}}`
	for name, text := range map[string]string{
		"pom.xml":           "<project/>\n",
		"package.json":      `{"name":"app","dependencies":{"@noble/hashes":"^1.3.0"},"devDependencies":{"jest":"^29.0.0"}}`,
		"package-lock.json": lock,
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graphs := newGraphStore(target, "given.jar")
	noRuntime := func() (javaruntime.Config, error) {
		t.Error("a node plan asked for the Java runtime")
		return javaruntime.Config{}, nil
	}
	plan, skip, err := planApplicationReachability(context.Background(), graphs, target, ecosystemNode, noRuntime, nil)
	if err != nil || plan == nil || skip != (dependencySkip{}) {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	if plan.resolver != nil || plan.closure.Ecosystem != ecosystemNode || graphs.typeJARList() != "given.jar" {
		t.Errorf("resolver %v, ecosystem %q, type jars %q", plan.resolver, plan.closure.Ecosystem, graphs.typeJARList())
	}
	deps := plan.closure.Resolved.Dependencies
	if len(deps) != 1 || deps[0].Module != "@noble/hashes" || deps[0].Version != "1.3.2" {
		t.Errorf("dependencies = %+v, want @noble/hashes 1.3.2 only", deps)
	}
}

// A node target with no lock file is skipped as manifest_absent: package.json
// ranges are never resolved.
func TestPlanApplicationReachabilityNodeWithoutLock(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "package.json"), []byte(`{"dependencies":{"left-pad":"^1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	graphs := newGraphStore(target, "given.jar")
	plan, skip, err := planApplicationReachability(context.Background(), graphs, target, ecosystemNode, func() (javaruntime.Config, error) {
		t.Error("a node plan asked for the Java runtime")
		return javaruntime.Config{}, nil
	}, nil)
	if err != nil || plan != nil {
		t.Fatalf("plan %v, err %v", plan, err)
	}
	if want := (dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemNode}); skip != want {
		t.Errorf("skip = %+v, want %+v", skip, want)
	}
}

// An npm 6 lock (lockfileVersion 1), at the root or below it, skips the npm
// dependencies with unsupported_lockfile instead of failing the scan, so the
// other ecosystems of a mixed repository keep their dependency results.
func TestPlanApplicationReachabilityNodeUnsupportedLock(t *testing.T) {
	for name, path := range map[string]string{"at the root": "package-lock.json", "below the root": "examples/demo/package-lock.json"} {
		t.Run(name, func(t *testing.T) {
			target := t.TempDir()
			lock := filepath.Join(target, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(lock), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lock, []byte(`{"lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.3.0"}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			plan, skip, err := planApplicationReachability(context.Background(), newGraphStore(target, ""), target, ecosystemNode, func() (javaruntime.Config, error) {
				t.Error("a node plan asked for the Java runtime")
				return javaruntime.Config{}, nil
			}, nil)
			if err != nil || plan != nil {
				t.Fatalf("plan %v, err %v", plan, err)
			}
			if want := (dependencySkip{reason: dependency.SkipReasonUnsupportedLockfile, ecosystem: ecosystemNode}); skip != want {
				t.Errorf("skip = %+v, want %+v", skip, want)
			}
		})
	}
}

// In a monorepo, an npm 6 lock skips its own root only: the other roots'
// locks still resolve.
func TestPlanApplicationReachabilityNodeUnsupportedLockOneRoot(t *testing.T) {
	target := t.TempDir()
	for path, text := range map[string]string{
		"legacy/package-lock.json": `{"lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.3.0"}}}`,
		"web/package-lock.json":    `{"lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"acme":"^1.0.0"}},"node_modules/acme":{"version":"1.0.0"}}}`,
	} {
		file := filepath.Join(target, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan, skip, err := planApplicationReachability(context.Background(), newGraphStore(target, ""), target, ecosystemNode, nil, nil)
	if err != nil || plan == nil {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	got := make([]string, 0, len(plan.closure.Resolved.Dependencies))
	for _, dep := range plan.closure.Resolved.Dependencies {
		got = append(got, dep.Module+"@"+dep.Version)
	}
	if !slices.Equal(got, []string{"acme@1.0.0"}) {
		t.Errorf("dependencies = %v, want web's acme only", got)
	}
}

// A lock file below the scan root (a monorepo's package) is found.
func TestPlanApplicationReachabilityNodeLockBelowTarget(t *testing.T) {
	target := t.TempDir()
	dir := filepath.Join(target, "services", "api")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"api","dependencies":{"bcryptjs":"^2.4.3"}},"node_modules/bcryptjs":{"version":"2.4.3"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, skip, err := planApplicationReachability(context.Background(), newGraphStore(target, ""), target, ecosystemNode, nil, nil)
	if err != nil || plan == nil || skip != (dependencySkip{}) {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	if deps := plan.closure.Resolved.Dependencies; len(deps) != 1 || deps[0].Module != "bcryptjs" {
		t.Errorf("dependencies = %+v, want bcryptjs", deps)
	}
}

// 1.0.0 removed the flags that had been accepted as no-ops; they are unknown
// flags now, on scan and on annotate.
func TestRemovedNoOpFlagsAreUnknown(t *testing.T) {
	scanFlags := []string{"dep-ecosystem", "dep-workers", "detect-paths-from", "findings-cache", "include-dev-dependencies", "install-dependencies", "interfile", "no-dependency-findings-api", "opengrep-mode", "rule-prefilter", "scanner", "scanner-jobs"}
	for _, name := range scanFlags {
		if scanCmd.Flags().Lookup(name) != nil {
			t.Errorf("scan still has --%s", name)
		}
	}
	for _, name := range []string{"opengrep-mode", "scanner", "scanner-jobs"} {
		if annotateCmd.Flags().Lookup(name) != nil {
			t.Errorf("annotate still has --%s", name)
		}
	}
}

// A Rust scan resolves the target's Cargo.lock with cargo metadata --locked:
// no Java runtime, no type JARs; the dev-only crate is left out and the
// closure holds the production crates with their direct flag.
func TestPlanApplicationReachabilityRust(t *testing.T) {
	target := t.TempDir()
	writeRustProject(t, target)
	graphs := newGraphStore(target, "given.jar")
	plan, skip, err := planApplicationReachability(context.Background(), graphs, target, ecosystemRust, func() (javaruntime.Config, error) {
		t.Error("a rust plan asked for the Java runtime")
		return javaruntime.Config{}, nil
	}, nil)
	if err != nil || plan == nil || skip != (dependencySkip{}) {
		t.Fatalf("plan %v, skip %+v, err %v", plan, skip, err)
	}
	if plan.resolver != nil || plan.closure.Ecosystem != ecosystemRust || graphs.typeJARList() != "given.jar" {
		t.Errorf("resolver %v, ecosystem %q, type jars %q", plan.resolver, plan.closure.Ecosystem, graphs.typeJARList())
	}
	got := make([]string, 0, len(plan.closure.Resolved.Dependencies))
	for _, dep := range plan.closure.Resolved.Dependencies {
		got = append(got, dep.Module+"@"+dep.Version)
		if want := filepath.Join(target, "vendor", dep.Module); dep.Dir != want {
			t.Errorf("%s dir = %q, want %q", dep.Module, dep.Dir, want)
		}
	}
	if want := []string{"acme-pad@1.2.0", "acme-sign@2.0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("dependencies = %v, want %v", got, want)
	}
}

// A Rust target is skipped as manifest_absent, not failed, when it has no
// Cargo.toml or no Cargo.lock: an unlocked closure is never resolved, and
// the scan never writes a lock into the project.
func TestPlanApplicationReachabilityRustSkips(t *testing.T) {
	noLock := t.TempDir()
	writeAnnotateCardsFile(t, filepath.Join(noLock, "Cargo.toml"), "[package]\nname = \"app\"\nversion = \"0.1.0\"\n")
	for name, target := range map[string]string{"no manifest": t.TempDir(), "no lock": noLock} {
		plan, skip, err := planApplicationReachability(context.Background(), newGraphStore(target, ""), target, ecosystemRust, func() (javaruntime.Config, error) {
			return javaruntime.Config{}, nil
		}, nil)
		if err != nil || plan != nil {
			t.Fatalf("%s: plan %v, err %v", name, plan, err)
		}
		if want := (dependencySkip{reason: dependency.SkipReasonManifestAbsent, ecosystem: ecosystemRust}); skip != want {
			t.Errorf("%s: skip = %+v, want %+v", name, skip, want)
		}
	}
	if _, err := os.Stat(filepath.Join(noLock, "Cargo.lock")); err == nil {
		t.Error("the scan wrote a Cargo.lock into the project")
	}
}

// --timeout bounds the whole scan, offline mining included: an offline
// dependency phase that runs out of time fails as a scan timeout naming the
// timeout, and a canceled one as a cancellation; any other failure stays a
// dependency failure.
func TestOfflineReachabilityFailure(t *testing.T) {
	previous := scanTimeout
	scanTimeout = "10m"
	t.Cleanup(func() { scanTimeout = previous })
	for cause, want := range map[error]failure.Code{
		fmt.Errorf("offline mining: %w", context.DeadlineExceeded): failure.CodeScannerTimeout,
		fmt.Errorf("offline mining: %w", context.Canceled):         failure.CodeScannerCancelled,
		errors.New("open cache: permission denied"):                failure.CodeDependencyResolutionFailed,
	} {
		structured, ok := failure.As(offlineReachabilityFailure(cause))
		if !ok || structured.Code != want || structured.Stage != failure.StageDependency {
			t.Errorf("%v: got %+v, want code %s", cause, structured, want)
			continue
		}
		if want == failure.CodeScannerTimeout && (structured.Details["timeout"] != "10m" || !structured.Retryable) {
			t.Errorf("timeout failure %+v: want the timeout in its details, retryable", structured)
		}
	}
}

// The request the API and --offline both answer carries a call into a
// dependency only from a function the project's entry points reach.
func TestApplicationReachabilityRequestLeavesOutDeadCallers(t *testing.T) {
	target := t.TempDir()
	for name, text := range map[string]string{
		"package.json": `{"name":"app","main":"index.js","dependencies":{"liba":"1.0.0"}}`,
		"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"liba":"1.0.0"}},
"node_modules/liba":{"version":"1.0.0"}}}`,
		"index.js": `const liba = require('liba');

function live(data) {
  return liba.fingerprint(data);
}

function dead(data) {
  return liba.fingerprint(data);
}

function main() {
  console.log(live('hello'));
}

main();
`,
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graphs := newGraphStore(target, "")
	noRuntime := func() (javaruntime.Config, error) { return javaruntime.Config{}, nil }
	plan, _, err := planApplicationReachability(context.Background(), graphs, target, ecosystemNode, noRuntime, nil)
	if err != nil || plan == nil {
		t.Fatalf("plan %v, err %v", plan, err)
	}
	project, err := buildStandaloneCallGraphResultForEcosystem(graphs, target, &entities.InterimReport{}, ecosystemNode, javaruntime.Config{}, false, "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	request, unreachable, err := applicationReachabilityRequest(plan.closure, project)
	if err != nil {
		t.Fatal(err)
	}
	var callers []string
	for _, call := range request.CallSites.ExternalCalls {
		if name := project.CallGraph.Functions[call.CallerKey].ID.Name; call.MethodName == "fingerprint" && !slices.Contains(callers, name) {
			callers = append(callers, name)
		}
	}
	if !slices.Equal(callers, []string{"live"}) || unreachable == 0 {
		t.Errorf("callers of the dependency in the request = %v with %d functions left out, want [live] and at least one left out", callers, unreachable)
	}
}
