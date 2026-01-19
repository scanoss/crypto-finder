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
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
)

func writeRulesetTarball(gzWriter *gzip.Writer) error {
	tarWriter := tar.NewWriter(gzWriter)
	defer func() {
		if err := tarWriter.Close(); err != nil {
			log.Printf("Failed to close tar writer: %v", err)
		}
	}()

	content := []byte("rules: []\n")
	headers := []*tar.Header{
		{
			Name: "semgrep-rules/java/example.yaml",
			Mode: 0o600,
			Size: int64(len(content)),
		},
		{
			Name: "semgrep-rules/python/example.yml",
			Mode: 0o600,
			Size: int64(len(content)),
		},
	}

	for _, header := range headers {
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(content); err != nil {
			return err
		}
	}

	return nil
}

func writeRuleFile(t *testing.T, rulePath string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(rulePath), 0o755); err != nil {
		t.Fatalf("Failed to create rule dir: %v", err)
	}

	if err := os.WriteFile(rulePath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("Failed to write rule file: %v", err)
	}
}

// createMockTarballServer creates an httptest server that returns a minimal valid tarball.
func createMockTarballServer(t *testing.T, statusCode int, includeHeaders bool) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var tarballData []byte

		if statusCode == http.StatusOK {
			var buf bytes.Buffer
			gzWriter := gzip.NewWriter(&buf)
			if err := writeRulesetTarball(gzWriter); err != nil {
				t.Fatalf("Failed to write tarball: %v", err)
			}
			_ = gzWriter.Close()
			tarballData = buf.Bytes()
		}

		if includeHeaders {
			checksum := CalculateSHA256(tarballData)
			w.Header().Set("scanoss-ruleset-name", "dca")
			w.Header().Set("scanoss-ruleset-version", "latest")
			w.Header().Set("x-checksum-sha256", checksum)
			w.Header().Set("scanoss-ruleset-created-at", time.Now().Format(time.RFC3339))
		}

		w.WriteHeader(statusCode)

		if statusCode == http.StatusOK {
			_, _ = w.Write(tarballData)
		}
	}))
}

func TestManager_GetRulesetPath_CacheHit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create valid cache with metadata
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}
	writeRuleFile(t, filepath.Join(rulesetPath, "semgrep-rules", "example.yaml"))

	// Create valid metadata (not expired)
	metadata := NewMetadata("dca", "latest", "checksum123", 86400) // 24h TTL
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Create API client (shouldn't be called)
	server := createMockTarballServer(t, http.StatusInternalServerError, false)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - should use cache, not download
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")
	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}

	// Verify last accessed time was updated
	updatedMetadata, _ := LoadMetadata(metadataPath)
	if updatedMetadata.LastAccessed.Before(metadata.LastAccessed) {
		t.Error("LastAccessed time should have been updated")
	}
}

func TestManager_GetRulesetPath_CacheMiss(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup mock server
	server := createMockTarballServer(t, http.StatusOK, true)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - cache doesn't exist, should download
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")
	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	expectedPath := filepath.Join(tempDir, "dca", "latest")
	if path != expectedPath {
		t.Errorf("Expected path %s, got %s", expectedPath, path)
	}

	// Verify cache was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Cache directory was not created")
	}

	// Verify metadata was created
	metadataPath := filepath.Join(path, metadataFileName)
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		t.Error("Metadata file was not created")
	}

	// Verify manifest was created
	manifestPath := filepath.Join(path, manifestFileName)
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Error("Manifest file was not created")
	}
}

func TestManager_GetRulesetPath_NoCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create existing cache
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}

	oldChecksum := "oldchecksum123"
	metadata := NewMetadata("dca", "latest", oldChecksum, 86400)
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Setup mock server
	server := createMockTarballServer(t, http.StatusOK, true)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   true, // Enable no-cache mode
	}

	// Execute - should bypass cache and download
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")
	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}

	// Verify cache was updated (not using old checksum)
	newMetadata, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatalf("Failed to load updated metadata: %v", err)
	}

	if newMetadata.ChecksumSHA256 == oldChecksum {
		t.Error("Cache was not updated (checksum unchanged)")
	}
}

func TestManager_GetRulesetPath_ExpiredCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create expired cache
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}

	// Create metadata with very short TTL (already expired)
	metadata := NewMetadata("dca", "latest", "checksum123", -1) // Negative TTL = already expired
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Setup mock server
	server := createMockTarballServer(t, http.StatusOK, true)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - cache is expired, should download
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")
	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}

	// Verify cache was refreshed
	newMetadata, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatalf("Failed to load updated metadata: %v", err)
	}

	if newMetadata.DownloadedAt.Before(metadata.DownloadedAt) {
		t.Error("DownloadedAt time should have been updated")
	}
}

func TestManager_GetRulesetPath_DownloadError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup mock server that returns error
	server := createMockTarballServer(t, http.StatusInternalServerError, false)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient:        apiClient,
		cacheDir:         tempDir,
		noCache:          false,
		strictMode:       true, // Enable strict mode to prevent fallback
		maxStaleCacheAge: 30 * 24 * time.Hour,
	}

	// Execute - download should fail
	_, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error but got none")
	}
}

func TestManager_GetRulesetPath_StaleCache_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create expired cache that's within max stale age
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}
	writeRuleFile(t, filepath.Join(rulesetPath, "semgrep-rules", "example.yaml"))

	// Create metadata with expired TTL but within max stale age (5 days old)
	metadata := NewMetadata("dca", "latest", "checksum123", 1)  // 1 second TTL (expired)
	metadata.DownloadedAt = time.Now().Add(-5 * 24 * time.Hour) // 5 days ago
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Setup mock server that returns error (API unreachable)
	server := createMockTarballServer(t, http.StatusInternalServerError, false)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient:        apiClient,
		cacheDir:         tempDir,
		noCache:          false,
		strictMode:       false,               // Fallback enabled
		maxStaleCacheAge: 30 * 24 * time.Hour, // 30 days
	}

	// Execute - API fails, should use stale cache
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")
	// Assert - should succeed with stale cache
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v (expected to use stale cache)", err)
	}

	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}

	// Verify it's actually using the expired cache
	loadedMetadata, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatalf("Failed to load metadata: %v", err)
	}

	if !loadedMetadata.IsExpired() {
		t.Error("Expected cache to be expired")
	}
}

func TestManager_GetRulesetPath_StaleCache_TooOld(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create expired cache that exceeds max stale age
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}
	writeRuleFile(t, filepath.Join(rulesetPath, "semgrep-rules", "example.yaml"))

	// Create metadata that's 40 days old (exceeds 30 day limit)
	metadata := NewMetadata("dca", "latest", "checksum123", 1)   // Expired
	metadata.DownloadedAt = time.Now().Add(-40 * 24 * time.Hour) // 40 days ago
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Setup mock server that returns error
	server := createMockTarballServer(t, http.StatusInternalServerError, false)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient:        apiClient,
		cacheDir:         tempDir,
		noCache:          false,
		strictMode:       false,               // Fallback enabled but cache too old
		maxStaleCacheAge: 30 * 24 * time.Hour, // 30 days
	}

	// Execute - should fail because cache is too stale
	_, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert - should fail
	if err == nil {
		t.Fatal("Expected error but got none (cache should be too stale)")
	}
}

func TestManager_GetRulesetPath_StrictMode_NoFallback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create expired cache that's within max stale age
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}
	writeRuleFile(t, filepath.Join(rulesetPath, "semgrep-rules", "example.yaml"))

	// Create expired metadata that would otherwise be usable
	metadata := NewMetadata("dca", "latest", "checksum123", 1)  // Expired
	metadata.DownloadedAt = time.Now().Add(-5 * 24 * time.Hour) // 5 days ago
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Setup mock server that returns error
	server := createMockTarballServer(t, http.StatusInternalServerError, false)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient:        apiClient,
		cacheDir:         tempDir,
		noCache:          false,
		strictMode:       true, // Strict mode prevents fallback
		maxStaleCacheAge: 30 * 24 * time.Hour,
	}

	// Execute - should fail even though stale cache is available
	_, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert - should fail due to strict mode
	if err == nil {
		t.Fatal("Expected error but got none (strict mode should prevent fallback)")
	}
}

func TestManager_GetRulesetPath_StaleCache_NoCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup mock server that returns error
	server := createMockTarballServer(t, http.StatusInternalServerError, false)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient:        apiClient,
		cacheDir:         tempDir,
		noCache:          false,
		strictMode:       false, // Fallback enabled but no cache exists
		maxStaleCacheAge: 30 * 24 * time.Hour,
	}

	// Execute - no cache exists, should fail
	_, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert - should fail because no cache exists at all
	if err == nil {
		t.Fatal("Expected error but got none (no cache exists)")
	}
}

func TestManager_SetNoCache(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	server := createMockTarballServer(t, http.StatusOK, true)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Test setting noCache to true
	manager.SetNoCache(true)
	if !manager.noCache {
		t.Error("SetNoCache(true) did not set noCache to true")
	}

	// Test setting noCache back to false
	manager.SetNoCache(false)
	if manager.noCache {
		t.Error("SetNoCache(false) did not set noCache to false")
	}
}

func TestManager_isCacheValid(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	server := createMockTarballServer(t, http.StatusOK, true)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	tests := []struct {
		name     string
		setup    func() (rulesetPath, metadataPath string)
		expected bool
	}{
		{
			name: "valid cache with unexpired metadata",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "test1")
				_ = os.MkdirAll(rulesetPath, 0o755)
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				metadata := NewMetadata("test", "1.0", "checksum", 86400)
				_ = metadata.Save(metadataPath)
				return rulesetPath, metadataPath
			},
			expected: true,
		},
		{
			name: "nonexistent ruleset directory",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "nonexistent")
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				return rulesetPath, metadataPath
			},
			expected: false,
		},
		{
			name: "missing metadata file",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "test2")
				_ = os.MkdirAll(rulesetPath, 0o755)
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				return rulesetPath, metadataPath
			},
			expected: false,
		},
		{
			name: "expired cache",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "test3")
				_ = os.MkdirAll(rulesetPath, 0o755)
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				metadata := NewMetadata("test", "1.0", "checksum", -1) // Already expired
				_ = metadata.Save(metadataPath)
				return rulesetPath, metadataPath
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rulesetPath, metadataPath := tt.setup()
			result := manager.isCacheValid(rulesetPath, metadataPath)

			if result != tt.expected {
				t.Errorf("isCacheValid() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestManager_getTTL(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	server := createMockTarballServer(t, http.StatusOK, true)
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	tests := []struct {
		version string
		ttl     time.Duration
	}{
		{"latest", 24 * time.Hour},
		{"v1.0.0", 7 * 24 * time.Hour},
		{"v2.3.1", 7 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := manager.getTTL(tt.version)
			if result != tt.ttl {
				t.Errorf("getTTL(%s) = %v, expected %v", tt.version, result, tt.ttl)
			}
		})
	}
}

func TestManager_isCacheValid_InvalidMetadata(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	manager := &Manager{cacheDir: tempDir}

	rulesetPath := filepath.Join(tempDir, "invalid")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create ruleset dir: %v", err)
	}

	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := os.WriteFile(metadataPath, []byte("broken"), 0o600); err != nil {
		t.Fatalf("Failed to write metadata: %v", err)
	}

	if manager.isCacheValid(rulesetPath, metadataPath) {
		t.Fatal("Expected invalid cache for broken metadata")
	}
}

func TestManager_updateLastAccessed_Error(t *testing.T) {
	t.Parallel()

	manager := &Manager{}
	err := manager.updateLastAccessed("/nonexistent/metadata.json")
	if err == nil {
		t.Fatal("Expected error for missing metadata file")
	}
}

func TestManager_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	tempDir := t.TempDir()

	// Create server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Cancel context before responding
		cancel()
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	apiClient := api.NewClient(server.URL, "test-key")
	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - should fail due to context cancellation
	_, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error due to context cancellation")
	}
}

func Example_cacheWorkflow() {
	// Setup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		if err := writeRulesetTarball(gzWriter); err != nil {
			panic(err)
		}
		_ = gzWriter.Close()
		tarballData := buf.Bytes()

		checksum := CalculateSHA256(tarballData)
		w.Header().Set("scanoss-ruleset-name", "dca")
		w.Header().Set("scanoss-ruleset-version", "latest")
		w.Header().Set("x-checksum-sha256", checksum)
		w.Header().Set("scanoss-ruleset-created-at", time.Now().Format(time.RFC3339))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarballData)
	}))
	defer server.Close()

	// Create client and manager
	apiClient := api.NewClient(server.URL, "test-key")
	tempDir, err := os.MkdirTemp("", "crypto-finder-cache-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		apiClient: apiClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// First call - downloads and caches
	ctx := context.Background()
	path1, _ := manager.GetRulesetPath(ctx, "dca", "latest")
	fmt.Printf("First call downloaded to: %s\n", filepath.Base(filepath.Dir(path1)))

	// Second call - uses cache
	path2, _ := manager.GetRulesetPath(ctx, "dca", "latest")
	fmt.Printf("Second call reused cache: %v\n", path1 == path2)

	// With no-cache - forces re-download
	manager.SetNoCache(true)
	path3, _ := manager.GetRulesetPath(ctx, "dca", "latest")
	fmt.Printf("No-cache call forced download: %s\n", filepath.Base(filepath.Dir(path3)))

	// Output:
	// First call downloaded to: dca
	// Second call reused cache: true
	// No-cache call forced download: dca
}
