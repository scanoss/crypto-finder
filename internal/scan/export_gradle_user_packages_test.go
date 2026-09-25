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

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// Issue #372: a Gradle project without `group` exports RootModule as the
// settings.gradle project name. That string is not a Java package prefix, so
// treating it as the only user-code identity drops every chain that actually
// starts in com.acme.earnie.
func TestExportUserPackages_IncludesJavaPackagesFromProjectSources(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	depDir := t.TempDir()
	userFile := filepath.Join(project, "src", "main", "java", "com", "acme", "earnie", "App.java")
	libFile := filepath.Join(depDir, "org", "bouncycastle", "Crypto.java")

	userID := callgraph.FunctionID{Package: "com.acme.earnie", Type: "App", Name: "run#0"}
	libID := callgraph.FunctionID{Package: "org.bouncycastle", Type: "Crypto", Name: "hash#0"}

	result := &engine.DepScanResult{
		RootModule:  "crypto-finder-fixture",
		Ecosystem:   "java",
		ProjectRoot: project,
		Dependencies: []dependency.Dependency{{
			Module:  "org.bouncycastle:bcprov-jdk18on",
			Version: "1.78.1",
			Dir:     depDir,
		}},
		CallGraph: &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{
				userID.String(): {ID: userID, FilePath: userFile, StartLine: 1, EndLine: 9},
				libID.String():  {ID: libID, FilePath: libFile, StartLine: 1, EndLine: 5},
			},
		},
	}

	got := exportUserPackages(result)
	if !got["crypto-finder-fixture"] {
		t.Fatalf("user packages = %#v, want Gradle root module retained", got)
	}
	if !got["com.acme.earnie"] {
		t.Fatalf("user packages = %#v, want Java package from project sources", got)
	}
	if got["org.bouncycastle"] {
		t.Fatalf("user packages = %#v, dependency package must not count as user code", got)
	}
}

func TestExportUserPackages_IgnoresBareFilenamesOutsideTheProject(t *testing.T) {
	t.Parallel()

	userID := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "run#0"}
	libID := callgraph.FunctionID{Package: "dep.lib", Type: "Crypto", Name: "hash#0"}
	result := &engine.DepScanResult{
		RootModule:  "com.acme",
		Ecosystem:   "java",
		ProjectRoot: t.TempDir(),
		Dependencies: []dependency.Dependency{{
			Module: "dep.lib",
			Dir:    t.TempDir(),
		}},
		CallGraph: &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{
				userID.String(): {ID: userID, FilePath: "App.java", StartLine: 1, EndLine: 9},
				libID.String():  {ID: libID, FilePath: "Crypto.java", StartLine: 1, EndLine: 5},
			},
		},
	}

	got := exportUserPackages(result)
	if len(got) != 1 || !got["com.acme"] {
		t.Fatalf("user packages = %#v, want only RootModule when paths are bare names outside the project", got)
	}
}

func TestExportUserPackages_RelativeScanTargetHarvestsJavaPackages(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	userRel := filepath.Join("app", "src", "main", "java", "com", "acme", "earnie", "App.java")
	depRel := filepath.Join("cache", "bcprov")
	libRel := filepath.Join(depRel, "org", "bouncycastle", "Crypto.java")
	if err := os.MkdirAll(filepath.Dir(userRel), 0o755); err != nil {
		t.Fatalf("mkdir user sources: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(libRel), 0o755); err != nil {
		t.Fatalf("mkdir dep sources: %v", err)
	}

	userID := callgraph.FunctionID{Package: "com.acme.earnie", Type: "App", Name: "run#0"}
	libID := callgraph.FunctionID{Package: "org.bouncycastle", Type: "Crypto", Name: "hash#0"}
	result := &engine.DepScanResult{
		RootModule:  "crypto-finder-fixture",
		Ecosystem:   "java",
		ProjectRoot: "app",
		Dependencies: []dependency.Dependency{{
			Module: "org.bouncycastle:bcprov-jdk18on",
			Dir:    depRel,
		}},
		CallGraph: &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{
				userID.String(): {ID: userID, FilePath: userRel, StartLine: 1, EndLine: 9},
				libID.String():  {ID: libID, FilePath: libRel, StartLine: 1, EndLine: 5},
			},
		},
	}

	got := exportUserPackages(result)
	if !got["com.acme.earnie"] {
		t.Fatalf("user packages = %#v, want Java package from a relative scan target", got)
	}
	if got["org.bouncycastle"] {
		t.Fatalf("user packages = %#v, relative dependency dir must not count as user code", got)
	}
}

func TestExportUserPackages_DependencyNestedInsideProjectIsNotUserCode(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	depDir := filepath.Join(project, "vendor", "bcprov")
	userFile := filepath.Join(project, "src", "main", "java", "com", "acme", "App.java")
	libFile := filepath.Join(depDir, "org", "bouncycastle", "Crypto.java")

	userID := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "run#0"}
	libID := callgraph.FunctionID{Package: "org.bouncycastle", Type: "Crypto", Name: "hash#0"}
	result := &engine.DepScanResult{
		RootModule:  "crypto-finder-fixture",
		Ecosystem:   "java",
		ProjectRoot: project,
		Dependencies: []dependency.Dependency{{
			Module: "org.bouncycastle:bcprov-jdk18on",
			Dir:    depDir,
		}},
		CallGraph: &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{
				userID.String(): {ID: userID, FilePath: userFile, StartLine: 1, EndLine: 9},
				libID.String():  {ID: libID, FilePath: libFile, StartLine: 1, EndLine: 5},
			},
		},
	}

	got := exportUserPackages(result)
	if !got["com.acme"] {
		t.Fatalf("user packages = %#v, want project Java package", got)
	}
	if got["org.bouncycastle"] {
		t.Fatalf("user packages = %#v, nested dependency source must not count as user code", got)
	}
}

func TestBuildFindingGraph_GradleProjectNameRootModuleIsReachable(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	depDir := t.TempDir()
	userFile := filepath.Join(project, "src", "main", "java", "com", "acme", "earnie", "App.java")
	libFile := filepath.Join(depDir, "org", "bouncycastle", "Crypto.java")

	userID := callgraph.FunctionID{Package: "com.acme.earnie", Type: "App", Name: "run#0"}
	libID := callgraph.FunctionID{Package: "org.bouncycastle", Type: "Crypto", Name: "hash#0"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			userID.String(): {
				ID: userID, FilePath: userFile, StartLine: 1, EndLine: 9,
				Calls: []callgraph.FunctionCall{{Callee: libID, FilePath: userFile, Line: 4}},
			},
			libID.String(): {ID: libID, FilePath: libFile, StartLine: 1, EndLine: 5},
		},
		Callers: map[string][]string{
			libID.String(): {userID.String()},
		},
	}

	result := &engine.DepScanResult{
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: libFile,
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "f1", StartLine: 3, EndLine: 3,
			}},
		}}},
		CallGraph:   graph,
		RootModule:  "crypto-finder-fixture",
		Ecosystem:   "java",
		ProjectRoot: project,
		Dependencies: []dependency.Dependency{{
			Module:  "org.bouncycastle:bcprov-jdk18on",
			Version: "1.78.1",
			Dir:     depDir,
		}},
	}

	ctx := newExportBuildContext(result)
	fg := buildFindingGraph(ctx, result.Report.Findings[0], result.Report.Findings[0].CryptographicAssets[0])
	if fg.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("Reachability = %q, want %q (Gradle project name must not hide Java user packages)", fg.Reachability, graphfrag.ReachabilityReachable)
	}
	if fg.Reachable == nil || !*fg.Reachable {
		t.Fatalf("Reachable = %v, want true", fg.Reachable)
	}
	if len(fg.CallChains) == 0 || len(fg.CallChains[0]) < 2 {
		t.Fatalf("call chains = %#v, want a traced chain from user code", fg.CallChains)
	}
}

// A scan root with no manifest that names its module (a C tree, a Python
// project built from setup.py) has an empty RootModule. That is not an error:
// its own sources are still the user code, keyed at the scan root, so a
// dependency scan of it classifies reachability instead of answering
// not_applicable for every finding.
func TestExportUserPackages_EmptyRootModuleStillCountsProjectSources(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	depDir := t.TempDir()
	rootID := callgraph.FunctionID{Type: "Benchmark", Name: "run"}
	pkgID := callgraph.FunctionID{Package: "app.services", Name: "sign"}
	libID := callgraph.FunctionID{Package: "Crypto.Cipher", Name: "new"}

	result := &engine.DepScanResult{
		RootModule:  "",
		Ecosystem:   "python",
		ProjectRoot: project,
		Dependencies: []dependency.Dependency{{
			Module:  "pycryptodome",
			Version: "3.23.0",
			Dir:     depDir,
		}},
		CallGraph: &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{
				rootID.String(): {ID: rootID, FilePath: filepath.Join(project, "bench.py"), StartLine: 1, EndLine: 3},
				pkgID.String():  {ID: pkgID, FilePath: filepath.Join(project, "app", "services", "sign.py"), StartLine: 1, EndLine: 3},
				libID.String():  {ID: libID, FilePath: filepath.Join(depDir, "Crypto", "Cipher", "__init__.py"), StartLine: 1, EndLine: 3},
			},
		},
	}

	got := exportUserPackages(result)
	if got == nil {
		t.Fatal("user packages = nil: an empty RootModule must not disable reachability")
	}
	if !got[""] {
		t.Errorf("user packages = %#v, want the scan root's own top-level modules (package %q)", got, "")
	}
	if !got["app.services"] {
		t.Errorf("user packages = %#v, want the project source package app.services", got)
	}
	if got["Crypto.Cipher"] {
		t.Errorf("user packages = %#v, dependency package must not count as user code", got)
	}
}
