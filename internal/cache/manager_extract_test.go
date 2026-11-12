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

package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func createTarball(t *testing.T, entries func(tw *tar.Writer)) []byte {
	t.Helper()

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	entries(tarWriter)

	if err := tarWriter.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("Failed to close gzip writer: %v", err)
	}

	return buf.Bytes()
}

func TestManager_extractTarball_SkipsMetadataAndTraversal(t *testing.T) {
	manager := &Manager{}

	tarball := createTarball(t, func(tw *tar.Writer) {
		files := []struct {
			name string
			data []byte
		}{
			{name: "../evil.txt", data: []byte("no")},
			{name: "._metadata", data: []byte("skip")},
			{name: ".DS_Store", data: []byte("skip")},
			{name: "ruleset/example.yml", data: []byte("rules: []\n")},
		}

		for _, file := range files {
			header := &tar.Header{
				Name: file.name,
				Mode: 0o600,
				Size: int64(len(file.data)),
			}
			if err := tw.WriteHeader(header); err != nil {
				t.Fatalf("Failed to write header: %v", err)
			}
			if _, err := tw.Write(file.data); err != nil {
				t.Fatalf("Failed to write data: %v", err)
			}
		}
	})

	outputDir := t.TempDir()
	if err := manager.extractTarball(tarball, outputDir); err != nil {
		t.Fatalf("extractTarball failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outputDir, "evil.txt")); err == nil {
		t.Fatal("Expected traversal file to be skipped")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "._metadata")); err == nil {
		t.Fatal("Expected metadata file to be skipped")
	}
	if _, err := os.Stat(filepath.Join(outputDir, ".DS_Store")); err == nil {
		t.Fatal("Expected DS_Store file to be skipped")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "ruleset", "example.yml")); err != nil {
		t.Fatalf("Expected rules file to exist, got: %v", err)
	}
}

func TestManager_extractTarball_DirectoryAndFileModes(t *testing.T) {
	manager := &Manager{}

	tarball := createTarball(t, func(tw *tar.Writer) {
		if err := tw.WriteHeader(&tar.Header{
			Name:     "rules",
			Mode:     0o755,
			Typeflag: tar.TypeDir,
		}); err != nil {
			t.Fatalf("Failed to write dir header: %v", err)
		}

		data := []byte("rules: []\n")
		if err := tw.WriteHeader(&tar.Header{
			Name: "rules/example.yml",
			Mode: 0o600,
			Size: int64(len(data)),
		}); err != nil {
			t.Fatalf("Failed to write file header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("Failed to write file data: %v", err)
		}
	})

	outputDir := t.TempDir()
	if err := manager.extractTarball(tarball, outputDir); err != nil {
		t.Fatalf("extractTarball failed: %v", err)
	}

	info, err := os.Stat(filepath.Join(outputDir, "rules"))
	if err != nil {
		t.Fatalf("Expected rules directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("Expected rules to be a directory")
	}

	fileInfo, err := os.Stat(filepath.Join(outputDir, "rules", "example.yml"))
	if err != nil {
		t.Fatalf("Expected rules file: %v", err)
	}
	if fileInfo.IsDir() {
		t.Fatal("Expected rules file to be regular file")
	}
}

func TestManager_extractTarball_InvalidGzip(t *testing.T) {
	manager := &Manager{}

	err := manager.extractTarball([]byte("not-gzip"), t.TempDir())
	if err == nil {
		t.Fatal("Expected error for invalid gzip data")
	}
}

func TestManager_tryStaleCache_MetadataError(t *testing.T) {
	tempDir := t.TempDir()
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create ruleset dir: %v", err)
	}
	for name, content := range map[string]string{bundleFileName: "x", leaseFileName: "{}", metadataFileName: "broken"} {
		if err := os.WriteFile(filepath.Join(rulesetPath, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	manager := &Manager{maxStaleCacheAge: 30 * 24 * time.Hour}
	_, err := manager.tryStaleCache(rulesetPath, filepath.Join(rulesetPath, metadataFileName), "dca", "latest")
	if err == nil {
		t.Fatal("Expected error for invalid metadata")
	}
}

func TestManager_tryStaleCache_MissingBundle(t *testing.T) {
	tempDir := t.TempDir()
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create ruleset dir: %v", err)
	}
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	metadata := NewMetadata("dca", "latest", "checksum", 1)
	metadata.DownloadedAt = time.Now().Add(-1 * time.Hour)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to write metadata: %v", err)
	}

	manager := &Manager{maxStaleCacheAge: 30 * 24 * time.Hour}
	_, err := manager.tryStaleCache(rulesetPath, metadataPath, "dca", "latest")
	if err == nil {
		t.Fatal("Expected error for a cache without its bundle")
	}
}

func TestManager_tryStaleCache_UpdatesLastAccessed(t *testing.T) {
	manager := &Manager{apiClient: failingAPIClient(), cacheDir: t.TempDir(), maxStaleCacheAge: 30 * 24 * time.Hour}
	rulesetPath := seedCache(t, manager, time.Hour)
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	metadata, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	metadata.LastAccessed = time.Now().Add(-2 * time.Hour)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to write metadata: %v", err)
	}

	if _, err := manager.tryStaleCache(rulesetPath, metadataPath, "dca", "latest"); err != nil {
		t.Fatalf("Expected stale cache to be used: %v", err)
	}

	loaded, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatalf("Failed to load metadata: %v", err)
	}
	if !loaded.LastAccessed.After(metadata.LastAccessed) {
		t.Fatal("Expected LastAccessed to be updated")
	}
}

// An answer without a signed lease is refused: nothing is cached.
func TestManager_downloadAndCache_RequiresLease(t *testing.T) {
	tarball := createTarball(t, writeOtherRules)
	apiClient := newMockAPIClient(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("scanoss-ruleset-name", "dca")
		w.Header().Set("scanoss-ruleset-version", "v1.40.0")
		w.Header().Set("x-checksum-sha256", CalculateSHA256(tarball))
		w.Header().Set("scanoss-ruleset-created-at", time.Now().Format(time.RFC3339))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarball)
	})
	manager := &Manager{apiClient: apiClient, cacheDir: t.TempDir()}
	targetPath := filepath.Join(manager.cacheDir, "dca", "latest")

	err := manager.downloadAndCache(context.Background(), "dca", "latest", targetPath)
	if err == nil || !strings.Contains(err.Error(), "without a signed lease") {
		t.Fatalf("got %v, want the missing lease error", err)
	}
	if _, statErr := os.Stat(targetPath); !os.IsNotExist(statErr) {
		t.Fatalf("an answer without a lease was cached: %v", statErr)
	}
}

func TestManager_newBytesReader(t *testing.T) {
	reader := newBytesReader([]byte("data"))
	buf := make([]byte, 10)
	if _, err := reader.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("Unexpected read error: %v", err)
	}
}
