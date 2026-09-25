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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// A package unpacked into a temporary directory named
// `<sanitized purl>-<version>-<random>` is scanned from that directory.
// Nothing about that name is part of the code, so it must never reach a
// symbol: two scans of the same tree from differently named directories must
// emit identical keys, and a scan root without a manifest that names its
// module has no prefix at all.
func TestStandaloneCallGraph_ScanRootNameNeverNamesASymbol(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		ecosystem  string
		files      map[string]string
		rootModule string
		wantKeys   []string
	}{
		{
			name:      "python without a manifest is rooted at the scan root",
			ecosystem: "python",
			files: map[string]string{
				"bench.py":        "import os\n\nclass Benchmark:\n    def _random_bytes(self, b):\n        return os.urandom(b)\n",
				"pkg/__init__.py": "",
				"pkg/mod.py":      "def helper():\n    return 1\n",
			},
			wantKeys: []string{"(Benchmark)._random_bytes", "pkg.helper"},
		},
		{
			name:      "python src layout is transparent",
			ecosystem: "python",
			files: map[string]string{
				"src/mypkg/__init__.py": "",
				"src/mypkg/core.py":     "def run():\n    return 1\n",
			},
			wantKeys: []string{"mypkg.run"},
		},
		{
			name:      "python lib layout is transparent",
			ecosystem: "python",
			files: map[string]string{
				"lib/Crypto/__init__.py":      "",
				"lib/Crypto/Hash/__init__.py": "",
				"lib/Crypto/Hash/HMAC.py":     "def new(key):\n    return key\n",
			},
			wantKeys: []string{"Crypto.Hash.new"},
		},
		{
			name:      "python lib that is itself a package keeps its name",
			ecosystem: "python",
			files: map[string]string{
				"lib/__init__.py": "",
				"lib/util.py":     "def f():\n    return 1\n",
			},
			wantKeys: []string{"lib.f"},
		},
		{
			name:      "node without package.json is rooted at the scan root",
			ecosystem: "node",
			files: map[string]string{
				"index.js":    "function hash() { return 1; }\n",
				"src/util.js": "function helper() { return 2; }\n",
			},
			wantKeys: []string{"index.hash", "src/util.helper"},
		},
		{
			name:      "node package.json name is the module",
			ecosystem: "node",
			files: map[string]string{
				"package.json": `{"name":"demo-lib","version":"1.0.0"}`,
				"index.js":     "function hash() { return 1; }\n",
			},
			rootModule: "demo-lib",
			wantKeys:   []string{"demo-lib/index.hash"},
		},
		{
			name:      "c is rooted at the scan root",
			ecosystem: "c",
			files: map[string]string{
				"main.c":      "int main(void) { return 0; }\n",
				"crypto/kx.c": "int kx(void) { return 1; }\n",
			},
			wantKeys: []string{"main", "crypto.kx"},
		},
		{
			name:      "cpp is rooted at the scan root",
			ecosystem: "cpp",
			files: map[string]string{
				"src/a.cpp": "void run() {}\n",
			},
			wantKeys: []string{"src.run"},
		},
		{
			name:      "go without go.mod is rooted at the scan root",
			ecosystem: "go",
			files: map[string]string{
				"main.go":  "package main\n\nfunc main() {}\n",
				"pkg/a.go": "package pkg\n\nfunc Run() {}\n",
			},
			wantKeys: []string{"main", "pkg.Run"},
		},
		{
			name:      "rust without Cargo.toml is rooted at the scan root",
			ecosystem: "rust",
			files: map[string]string{
				"src/lib.rs": "pub fn run() {}\n",
			},
			wantKeys: []string{"run"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := t.TempDir()
			minedName := "pkg_pypi_x-1.0-123"
			otherName := "checkout"
			mined := scanRootModuleKeys(t, filepath.Join(base, minedName), tc.ecosystem, tc.files, tc.rootModule)
			other := scanRootModuleKeys(t, filepath.Join(base, otherName), tc.ecosystem, tc.files, tc.rootModule)

			if !reflect.DeepEqual(mined, other) {
				t.Fatalf("symbols differ by scan directory name:\n%s: %v\n%s: %v", minedName, mined, otherName, other)
			}
			for _, key := range mined {
				if strings.Contains(key, minedName) || strings.Contains(key, otherName) {
					t.Errorf("symbol %q carries the scan directory name", key)
				}
			}
			for _, want := range tc.wantKeys {
				if !containsString(mined, want) {
					t.Errorf("missing symbol %q in %v", want, mined)
				}
			}
		})
	}
}

func scanRootModuleKeys(t *testing.T, dir, ecosystem string, files map[string]string, wantRootModule string) []string {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := buildStandaloneCallGraphResultForEcosystem(dir, &entities.InterimReport{}, ecosystem, javaruntime.Config{}, false, "", nil, false)
	if err != nil {
		t.Fatalf("build call graph for %s: %v", ecosystem, err)
	}
	if result.RootModule != wantRootModule {
		t.Errorf("RootModule = %q, want %q", result.RootModule, wantRootModule)
	}
	keys := make([]string, 0, len(result.CallGraph.Functions))
	for key := range result.CallGraph.Functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
