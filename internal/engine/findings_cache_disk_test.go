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

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestDiskFindingsCache_GetPut_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	ctx := context.Background()
	key := "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234"

	report := &entities.InterimReport{
		Version: "1.2",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "0.1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "src/main/java/Crypto.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   12,
						Match:     "Cipher.getInstance(\"AES\")",
						Rules: []entities.RuleInfo{
							{ID: "java.crypto.aes", Message: "AES usage", Severity: "WARNING"},
						},
						Status:   "pending",
						Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "AES"},
					},
				},
			},
		},
	}

	// Put
	if err := cache.Put(ctx, key, report); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Get — should hit
	got, ok, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}

	if got.Version != report.Version {
		t.Errorf("version: got %q, want %q", got.Version, report.Version)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings count: got %d, want 1", len(got.Findings))
	}
	if got.Findings[0].FilePath != report.Findings[0].FilePath {
		t.Errorf("file path: got %q, want %q", got.Findings[0].FilePath, report.Findings[0].FilePath)
	}
	if len(got.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("assets count: got %d, want 1", len(got.Findings[0].CryptographicAssets))
	}
	gotAsset := got.Findings[0].CryptographicAssets[0]
	if gotAsset.Match != "Cipher.getInstance(\"AES\")" {
		t.Errorf("match: got %q, want %q", gotAsset.Match, "Cipher.getInstance(\"AES\")")
	}
}

func TestDiskFindingsCache_Get_Miss(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), "nonexistent@1.0:abc123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss, got hit")
	}
	if got != nil {
		t.Fatal("expected nil report on miss")
	}
}

func TestDiskFindingsCache_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	// Write corrupted JSON
	key := "corrupt@1.0:abc123"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.WriteFile(path, []byte("{invalid json"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Should return miss (not error) and remove the corrupted file
	got, ok, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss for corrupted file")
	}
	if got != nil {
		t.Fatal("expected nil report for corrupted file")
	}

	// Corrupted file should be removed
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected corrupted cache file to be removed")
	}
}

func TestDiskFindingsCache_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "stale@1.0:abc123"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	payload, err := json.Marshal(findingsCacheEnvelope{
		Version: findingsCacheVersion + 1,
		Report:  &entities.InterimReport{Version: "1.2"},
	})
	if err != nil {
		t.Fatalf("Marshal stale envelope: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, ok, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss for version-mismatched file")
	}
	if got != nil {
		t.Fatal("expected nil report for version-mismatched file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected version-mismatched cache file to be removed")
	}
}

func TestNewDiskFindingsCache_UsesConfiguredCacheDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cache, err := NewDiskFindingsCache()
	if err != nil {
		t.Fatalf("NewDiskFindingsCache: %v", err)
	}

	want := filepath.Join(home, ".scanoss", "crypto-finder", "cache", findingsCacheDirName)
	if cache.dir != want {
		t.Fatalf("cache.dir = %q, want %q", cache.dir, want)
	}
	if info, err := os.Stat(cache.dir); err != nil || !info.IsDir() {
		t.Fatalf("expected cache dir to exist, stat err=%v info=%v", err, info)
	}
}

func TestNewDiskFindingsCacheWithDir_ErrorWhenPathIsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cache-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewDiskFindingsCacheWithDir(file); err == nil {
		t.Fatal("expected error when cache dir path is a file")
	}
}

func TestNewDiskFindingsCache_ErrorPaths(t *testing.T) {
	t.Run("cache dir lookup fails", func(t *testing.T) {
		homeFile := filepath.Join(t.TempDir(), "home-file")
		if err := os.WriteFile(homeFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", homeFile)

		if _, err := NewDiskFindingsCache(); err == nil {
			t.Fatal("expected cache dir lookup error")
		}
	})

	t.Run("findings dir create fails", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HOME", homeDir)

		cacheDir := filepath.Join(homeDir, ".scanoss", "crypto-finder", "cache")
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cacheDir, findingsCacheDirName), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := NewDiskFindingsCache(); err == nil {
			t.Fatal("expected findings dir create error")
		}
	})
}

func TestDiskFindingsCache_Get_ReadError(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "read-error@1.0:abc"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := cache.Get(context.Background(), key); err == nil || ok {
		t.Fatalf("expected read error and miss, got ok=%v err=%v", ok, err)
	}
}

func TestDiskFindingsCache_Get_RemoveCorruptedFileFailure(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "remove-error@1.0:abc"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.WriteFile(path, []byte("{invalid json"), 0o640); err != nil {
		t.Fatal(err)
	}

	originalRemove := removeFindingsCacheFile
	removeFindingsCacheFile = func(removePath string) error {
		if removePath == path {
			return errors.New("simulated remove failure")
		}
		return originalRemove(removePath)
	}
	t.Cleanup(func() {
		removeFindingsCacheFile = originalRemove
	})

	if _, _, err := cache.Get(context.Background(), key); err == nil || !strings.Contains(err.Error(), "failed to remove corrupted cache file") {
		t.Fatalf("expected remove failure, got %v", err)
	}
}

func TestDiskFindingsCache_Get_VersionMismatchAndNilReportAreRemoved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "version mismatch",
			payload: `{"version":999,"report":{"version":"1.0","findings":[]}}`,
		},
		{
			name:    "nil report",
			payload: `{"version":1,"report":null}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cache, err := NewDiskFindingsCacheWithDir(dir)
			if err != nil {
				t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
			}

			key := "invalid-envelope@1.0:abc"
			path := filepath.Join(dir, cacheKeyToFilename(key))
			if err := os.WriteFile(path, []byte(tt.payload), 0o640); err != nil {
				t.Fatal(err)
			}

			report, ok, err := cache.Get(context.Background(), key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if ok || report != nil {
				t.Fatalf("expected cache miss for invalid envelope, got ok=%v report=%#v", ok, report)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("expected invalid cache file to be removed, stat err=%v", err)
			}
		})
	}
}

func TestDiskFindingsCache_Put_CreateTempFailure(t *testing.T) {
	cache := &DiskFindingsCache{dir: filepath.Join(t.TempDir(), "missing")}

	err := cache.Put(context.Background(), "key", &entities.InterimReport{Version: "1.0"})
	if err == nil || !strings.Contains(err.Error(), "failed to create temp cache file") {
		t.Fatalf("expected create temp error, got %v", err)
	}
}

func TestDiskFindingsCache_Put_RenameFailureCleansTemp(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskFindingsCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskFindingsCacheWithDir: %v", err)
	}

	key := "rename-error@1.0:abc"
	path := filepath.Join(dir, cacheKeyToFilename(key))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	err = cache.Put(context.Background(), key, &entities.InterimReport{Version: "1.0"})
	if err == nil || !strings.Contains(err.Error(), "failed to rename cache file") {
		t.Fatalf("expected rename error, got %v", err)
	}

	matches, globErr := filepath.Glob(filepath.Join(dir, filepath.Base(path)+".*.tmp"))
	if globErr != nil {
		t.Fatalf("Glob: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("expected temp files to be cleaned up, found %v", matches)
	}
}

func TestCacheKeyToFilename(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{
			key:  "org.bouncycastle:bcprov-jdk18on@1.78:abcd1234",
			want: "org.bouncycastle_bcprov-jdk18on_1.78_abcd1234.json",
		},
		{
			key:  "golang.org/x/crypto@v0.17.0:abcd1234",
			want: "golang.org_x_crypto_v0.17.0_abcd1234.json",
		},
		{
			key:  "github.com/foo/bar@v1.0.0:abcd1234",
			want: "github.com_foo_bar_v1.0.0_abcd1234.json",
		},
		{
			key:  `group:artifact@1.0.0:rules<>:"/\\|?*hash`,
			want: "group_artifact_1.0.0_rules__________hash.json",
		},
	}

	for _, tt := range tests {
		got := cacheKeyToFilename(tt.key)
		if got != tt.want {
			t.Errorf("cacheKeyToFilename(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}
