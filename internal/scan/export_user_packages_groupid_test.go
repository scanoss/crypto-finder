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

	"github.com/scanoss/static-engine/callgraph"
	"github.com/scanoss/static-engine/dependency"

	"github.com/scanoss/crypto-finder/internal/engine"
)

// sharedGroupIDResult models a Maven reactor under groupId com.acme: the
// application class sits in appPackage, the core and web modules in
// com.acme.core and com.acme.web, and the in-house dependency
// com.acme:crypto-utils, which shares the groupId, in com.acme.crypto.
func sharedGroupIDResult(t *testing.T, appPackage string) *engine.DepScanResult {
	t.Helper()
	project := t.TempDir()
	depDir := t.TempDir()
	functions := map[string]*callgraph.FunctionDecl{}
	declare := func(pkg, file string) {
		id := callgraph.FunctionID{Package: pkg, Type: "T", Name: "run#0"}
		functions[id.String()] = &callgraph.FunctionDecl{ID: id, FilePath: file, StartLine: 1, EndLine: 3}
	}
	declare(appPackage, filepath.Join(project, "app", "src", "main", "java", "Application.java"))
	declare("com.acme.core", filepath.Join(project, "core", "src", "main", "java", "com", "acme", "core", "Service.java"))
	declare("com.acme.web", filepath.Join(project, "web", "src", "main", "java", "com", "acme", "web", "Controller.java"))
	declare("com.acme.crypto", filepath.Join(depDir, "com", "acme", "crypto", "Hashing.java"))
	return &engine.DepScanResult{
		Ecosystem:   "java",
		RootModule:  "com.acme",
		ProjectRoot: project,
		Dependencies: []dependency.Dependency{
			{Module: "com.acme:crypto-utils", Version: "1.0.0", Dir: depDir},
			{Module: "org.bouncycastle:bcprov-jdk18on", Version: "1.78.1"},
		},
		CallGraph: &callgraph.CallGraph{Functions: functions},
	}
}

// A dependency that shares the application's groupId is not application
// code, while the application's own packages and its sibling reactor modules
// still are, on both the resolved run and the project reachability run. The
// application class sits in com.acme, so the dependency is under an
// application package as well as under the groupId.
func TestProjectUserPackages_DependencyUnderTheApplicationGroupIDIsNotUserCode(t *testing.T) {
	t.Parallel()

	result := sharedGroupIDResult(t, "com.acme")
	for name, pkgs := range map[string]map[string]bool{
		"resolved run":         exportUserPackages(result),
		"project reachability": projectUserPackages(result),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for pkg, want := range map[string]bool{
				"com.acme":                 true,
				"com.acme.core":            true,
				"com.acme.web":             true,
				"com.acme.web.handlers":    true,
				"com.acme.crypto":          false,
				"com.acme.crypto.internal": false,
				"org.bouncycastle":         false,
			} {
				if got := callgraph.IsUserPackage(pkg, pkgs, "."); got != want {
					t.Errorf("IsUserPackage(%q) = %v, want %v; user packages %v", pkg, got, want, pkgs)
				}
			}
		})
	}
}

// The groupId is only a stand-in for the project's sources: it does not
// count once a function lies in the project tree, so a dependency package
// under it that no parsed function declares, as one with no sources JAR, is
// not user code either.
func TestProjectUserPackages_GroupIDIsNoUserPackageOnceSourcesAreFound(t *testing.T) {
	t.Parallel()

	result := sharedGroupIDResult(t, "com.acme.app")
	pkgs := projectUserPackages(result)
	if callgraph.IsUserPackage("com.acme.vault", pkgs, ".") {
		t.Fatalf("com.acme.vault is under the groupId but no project file declares it; user packages %v", pkgs)
	}

	result.ProjectRoot = ""
	fallback := projectUserPackages(result)
	if !callgraph.IsUserPackage("com.acme.vault", fallback, ".") {
		t.Fatalf("with no project root the groupId stands in for the sources; user packages %v", fallback)
	}
}
