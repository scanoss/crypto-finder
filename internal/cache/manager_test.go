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
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newMockAPIClient(handler func(http.ResponseWriter, *http.Request)) *api.Client {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler(recorder, req)
			if err := req.Context().Err(); err != nil {
				return nil, err
			}
			return recorder.Result(), nil
		}),
	}

	return api.NewClientWithHTTPClient("https://api.example.com", testAPIKey, httpClient).WithRetryDelay(time.Millisecond)
}

// failingAPIClient answers every request with a server error.
func failingAPIClient() *api.Client {
	return newMockAPIClient(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
}

// seedCache stores a leased dca ruleset under dca/latest whose TTL elapsed
// age ago (age 0: a fresh cache) and returns its path.
func seedCache(t *testing.T, m *Manager, age time.Duration) string {
	t.Helper()
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(60*24*time.Hour))
	path := m.getRulesetCachePath("dca", "latest")
	if err := m.storeLeased("dca", path, issued.Bundle, issued.LeaseJSON, issued.Lease, int64(time.Hour.Seconds())); err != nil {
		t.Fatal(err)
	}
	if age > 0 {
		metaPath := filepath.Join(path, metadataFileName)
		meta, err := LoadMetadata(metaPath)
		if err != nil {
			t.Fatal(err)
		}
		meta.DownloadedAt = time.Now().Add(-age)
		meta.TTLSeconds = 1
		if err := meta.Save(metaPath); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestManager_GetRulesetPath_CacheHit(t *testing.T) {
	m := &Manager{apiClient: failingAPIClient(), cacheDir: t.TempDir()}
	rulesetPath := seedCache(t, m, 0)
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	before, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatal(err)
	}

	// The API fails, so the fresh cache must be used without it.
	path, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}
	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}
	after, _ := LoadMetadata(metadataPath)
	if after.LastAccessed.Before(before.LastAccessed) {
		t.Error("LastAccessed time should have been updated")
	}
}

func TestManager_GetRulesetPath_NoCache(t *testing.T) {
	m := newLeasedManager(t, "http://127.0.0.1:1")
	rulesetPath := seedCache(t, m, 0)
	// A new signer replaces seedCache's: the server's lease must verify.
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	srv := rulesettest.NewServer(t, rulesettest.Issue(t, signer, "dca", "v1.41.0", testRules, time.Now().Add(30*24*time.Hour)))
	m.apiClient = api.NewClient(srv.URL, testAPIKey).WithRetryDelay(time.Millisecond)
	m.SetNoCache(true)

	path, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}
	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}
	meta, err := LoadMetadata(filepath.Join(path, metadataFileName))
	if err != nil {
		t.Fatal(err)
	}
	if downloads, _ := srv.Counts(); downloads != 1 || meta.Version != "v1.41.0" {
		t.Fatalf("downloads %d, cached version %s; want the fresh cache replaced by v1.41.0", downloads, meta.Version)
	}
}

func TestManager_GetRulesetPath_DownloadError(t *testing.T) {
	t.Parallel()

	m := &Manager{
		apiClient:        failingAPIClient(),
		cacheDir:         t.TempDir(),
		strictMode:       true,
		maxStaleCacheAge: 30 * 24 * time.Hour,
	}
	if _, err := m.GetRulesetPath(context.Background(), "dca", "latest"); err == nil {
		t.Fatal("Expected error but got none")
	}
}

func TestManager_GetRulesetPath_StaleCache(t *testing.T) {
	tests := []struct {
		name    string
		age     time.Duration
		strict  bool
		wantErr bool
	}{
		{"within the max stale age", 5 * 24 * time.Hour, false, false},
		{"older than the max stale age", 40 * 24 * time.Hour, false, true},
		{"strict mode", 5 * 24 * time.Hour, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{
				apiClient:        failingAPIClient(),
				cacheDir:         t.TempDir(),
				strictMode:       tt.strict,
				maxStaleCacheAge: 30 * 24 * time.Hour,
			}
			rulesetPath := seedCache(t, m, tt.age)

			path, err := m.GetRulesetPath(context.Background(), "dca", "latest")
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				return
			}
			if err != nil || path != rulesetPath {
				t.Fatalf("GetRulesetPath() = %q, %v; want the stale cache %s", path, err, rulesetPath)
			}
		})
	}
}

func TestManager_GetRulesetPath_StaleCache_NoCache(t *testing.T) {
	t.Parallel()

	m := &Manager{
		apiClient:        failingAPIClient(),
		cacheDir:         t.TempDir(),
		maxStaleCacheAge: 30 * 24 * time.Hour,
	}
	if _, err := m.GetRulesetPath(context.Background(), "dca", "latest"); err == nil {
		t.Fatal("Expected error but got none (no cache exists)")
	}
}

func TestManager_SetNoCache(t *testing.T) {
	t.Parallel()

	manager := &Manager{apiClient: failingAPIClient(), cacheDir: t.TempDir()}

	manager.SetNoCache(true)
	if !manager.noCache {
		t.Error("SetNoCache(true) did not set noCache to true")
	}
	manager.SetNoCache(false)
	if manager.noCache {
		t.Error("SetNoCache(false) did not set noCache to false")
	}
}

func TestManager_isCacheValid(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(m *Manager) string
		expected bool
	}{
		{
			name:     "fresh cache",
			setup:    func(m *Manager) string { return seedCache(t, m, 0) },
			expected: true,
		},
		{
			name:     "nonexistent ruleset directory",
			setup:    func(m *Manager) string { return m.getRulesetCachePath("dca", "latest") },
			expected: false,
		},
		{
			name: "missing metadata file",
			setup: func(m *Manager) string {
				path := seedCache(t, m, 0)
				_ = os.Remove(filepath.Join(path, metadataFileName))
				return path
			},
			expected: false,
		},
		{
			name: "missing bundle",
			setup: func(m *Manager) string {
				path := seedCache(t, m, 0)
				_ = os.Remove(filepath.Join(path, bundleFileName))
				return path
			},
			expected: false,
		},
		{
			name:     "expired TTL",
			setup:    func(m *Manager) string { return seedCache(t, m, time.Hour) },
			expected: false,
		},
		{
			name: "older plaintext cache",
			setup: func(m *Manager) string {
				path := m.getRulesetCachePath("dca", "latest")
				writeOlderPlaintextCache(t, path)
				return path
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{apiClient: failingAPIClient(), cacheDir: t.TempDir()}
			rulesetPath := tt.setup(m)
			if got := m.isCacheValid(rulesetPath, filepath.Join(rulesetPath, metadataFileName)); got != tt.expected {
				t.Errorf("isCacheValid() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestManager_getTTL(t *testing.T) {
	t.Parallel()

	manager := &Manager{cacheDir: t.TempDir()}

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
	for name, content := range map[string]string{bundleFileName: "x", leaseFileName: "{}", metadataFileName: "broken"} {
		if err := os.WriteFile(filepath.Join(rulesetPath, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if manager.isCacheValid(rulesetPath, filepath.Join(rulesetPath, metadataFileName)) {
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
	apiClient := newMockAPIClient(func(w http.ResponseWriter, _ *http.Request) {
		cancel()
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	manager := &Manager{apiClient: apiClient, cacheDir: t.TempDir()}

	if _, err := manager.GetRulesetPath(ctx, "dca", "latest"); err == nil {
		t.Fatal("Expected error due to context cancellation")
	}
}
