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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestScanCommand_IncludeDevDependenciesFlag(t *testing.T) {
	flag := scanCmd.Flags().Lookup("include-dev-dependencies")
	if flag == nil {
		t.Fatal("expected --include-dev-dependencies flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("default = %q, want false", flag.DefValue)
	}
}

// The registry the scan builds hands the flag to the npm resolver.
func TestNewDependencyRegistry_NpmDevDependencies(t *testing.T) {
	root := t.TempDir()
	for path, content := range map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"node-forge":"^1.4.0"},"devDependencies":{"tap":"^16.0.0"}}`,
		"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{
		  "":{"name":"app","version":"1.0.0"},
		  "node_modules/node-forge":{"version":"1.4.0"},
		  "node_modules/tap":{"version":"16.0.0","dev":true}}}`,
		"node_modules/node-forge/package.json": `{"name":"node-forge","version":"1.4.0"}`,
		"node_modules/tap/package.json":        `{"name":"tap","version":"16.0.0"}`,
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		includeDev bool
		want       []string
	}{
		{false, []string{"node-forge"}},
		{true, []string{"node-forge", "tap"}},
	} {
		resolver, err := newDependencyRegistry(tc.includeDev).Get(ecosystemNode)
		if err != nil {
			t.Fatalf("npm resolver: %v", err)
		}
		result, err := resolver.Resolve(context.Background(), root)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		var got []string
		for _, dep := range result.Dependencies {
			got = append(got, dep.Module)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("includeDev=%v modules = %v, want %v", tc.includeDev, got, tc.want)
		}
	}
}
