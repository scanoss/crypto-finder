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

func TestExportUserPackages_IgnoresRelativePaths(t *testing.T) {
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
		t.Fatalf("user packages = %#v, want only RootModule when paths are relative", got)
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
