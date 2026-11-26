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

package dependency

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A packages.lock.json as `dotnet restore --use-lock-file` writes it: the
// requested range and the version it resolved to, per target framework. A
// project reference carries no version.
const nuGetLockFile = `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "BouncyCastle.Cryptography": {
        "type": "Direct",
        "requested": "[2.4.0, )",
        "resolved": "2.4.0",
        "contentHash": "SwXsAV3sMvAU"
      },
      "System.Text.Json": {
        "type": "Transitive",
        "resolved": "8.0.4",
        "contentHash": "bAkhgDlb"
      },
      "Acme.Shared": {
        "type": "Project"
      }
    }
  }
}`

// The libraries of an obj/project.assets.json: `<id>/<version>` keys, and
// only those from a feed are packages.
const nuGetAssetsFile = `{
  "version": 3,
  "libraries": {
    "BouncyCastle.Cryptography/2.4.0": {"type": "package"},
    "Acme.Shared/1.0.0": {"type": "project"}
  }
}`

const packagesConfigFile = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="BouncyCastle" version="1.8.9" targetFramework="net48" />
</packages>`

// write puts one file under dir, making its parents.
func writeCSharpFile(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func resolveCSharp(t *testing.T, dir string) []Dependency {
	t.Helper()
	resolver := NewCSharpResolver()
	if !resolver.CanResolve(dir) {
		t.Fatal("CanResolve = false, want a resolvable project")
	}
	result, err := resolver.Resolve(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return result.Dependencies
}

// The lock file gives each package the version it resolved to; a project
// entry is the solution's own code and is not a package.
func TestCSharpResolverReadsTheLockFile(t *testing.T) {
	dir := t.TempDir()
	writeCSharpFile(t, dir, csharpLockFile, nuGetLockFile)
	deps := resolveCSharp(t, dir)
	if len(deps) != 2 {
		t.Fatalf("dependencies = %+v, want 2", deps)
	}
	if deps[0].Module != "BouncyCastle.Cryptography" || deps[0].Version != "2.4.0" {
		t.Errorf("dependency 0 = %+v", deps[0])
	}
	if deps[1].Module != "System.Text.Json" || deps[1].Version != "8.0.4" {
		t.Errorf("dependency 1 = %+v", deps[1])
	}
}

// Every restore writes the asset file, so a project without a lock still
// resolves.
func TestCSharpResolverReadsTheAssetFile(t *testing.T) {
	dir := t.TempDir()
	writeCSharpFile(t, dir, filepath.Join("obj", csharpAssetsFile), nuGetAssetsFile)
	deps := resolveCSharp(t, dir)
	if len(deps) != 1 || deps[0].Module != "BouncyCastle.Cryptography" || deps[0].Version != "2.4.0" {
		t.Fatalf("dependencies = %+v, want the one package of the assets", deps)
	}
}

// A .NET Framework project writes an exact version per package.
func TestCSharpResolverReadsPackagesConfig(t *testing.T) {
	dir := t.TempDir()
	writeCSharpFile(t, dir, csharpPackagesFile, packagesConfigFile)
	deps := resolveCSharp(t, dir)
	if len(deps) != 1 || deps[0].Module != "BouncyCastle" || deps[0].Version != "1.8.9" {
		t.Fatalf("dependencies = %+v, want the one package of packages.config", deps)
	}
}

// The same package resolved by two files is one dependency.
func TestCSharpResolverMergesTheFilesItReads(t *testing.T) {
	dir := t.TempDir()
	writeCSharpFile(t, dir, csharpLockFile, nuGetLockFile)
	writeCSharpFile(t, dir, filepath.Join("obj", csharpAssetsFile), nuGetAssetsFile)
	deps := resolveCSharp(t, dir)
	if len(deps) != 2 {
		t.Fatalf("dependencies = %+v, want 2", deps)
	}
}

// A project file states a minimum, not a version, so it resolves nothing.
func TestCSharpResolverIgnoresAProjectFile(t *testing.T) {
	dir := t.TempDir()
	writeCSharpFile(t, dir, "app.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup><PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" /></ItemGroup>
</Project>`)
	if NewCSharpResolver().CanResolve(dir) {
		t.Error("a project file alone states ranges: it must not resolve")
	}
}

// A package of the local cache that ships assemblies only has no source
// directory; one that ships source has its own.
func TestCSharpResolverSourceDirectory(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("NUGET_PACKAGES", cache)
	assemblies := filepath.Join(cache, "bouncycastle.cryptography", "2.4.0", "lib", "net6.0")
	writeCSharpFile(t, assemblies, "BouncyCastle.Cryptography.dll", "MZ")
	sources := filepath.Join(cache, "system.text.json", "8.0.4", "contentFiles", "cs")
	writeCSharpFile(t, sources, "Json.cs", "class Json {}")

	dir := t.TempDir()
	writeCSharpFile(t, dir, csharpLockFile, nuGetLockFile)
	deps := resolveCSharp(t, dir)
	if len(deps) != 2 {
		t.Fatalf("dependencies = %+v, want 2", deps)
	}
	if deps[0].Dir != "" {
		t.Errorf("an assembly-only package has no source directory, got %q", deps[0].Dir)
	}
	if deps[1].Dir == "" {
		t.Error("a package that ships source keeps its directory")
	}
}
