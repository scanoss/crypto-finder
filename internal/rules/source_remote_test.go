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

package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newRemoteRuleSourceTestClient(
	t *testing.T,
	statusCode int,
	includeHeaders bool,
) *api.Client {
	t.Helper()

	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()

			var tarballData []byte
			if statusCode == http.StatusOK {
				var buf bytes.Buffer
				gzWriter := gzip.NewWriter(&buf)
				tarWriter := tar.NewWriter(gzWriter)
				content := []byte("rules: []\n")
				if err := tarWriter.WriteHeader(&tar.Header{
					Name: "semgrep-rules/example.yaml",
					Mode: 0o600,
					Size: int64(len(content)),
				}); err != nil {
					t.Fatalf("write tar header: %v", err)
				}
				if _, err := tarWriter.Write(content); err != nil {
					t.Fatalf("write tar content: %v", err)
				}
				if err := tarWriter.Close(); err != nil {
					t.Fatalf("close tar writer: %v", err)
				}
				if err := gzWriter.Close(); err != nil {
					t.Fatalf("close gzip writer: %v", err)
				}
				tarballData = buf.Bytes()
			}

			if includeHeaders {
				recorder.Header().Set("scanoss-ruleset-name", "dca")
				recorder.Header().Set("scanoss-ruleset-version", "latest")
				recorder.Header().Set("x-checksum-sha256", cache.CalculateSHA256(tarballData))
				recorder.Header().Set("scanoss-ruleset-created-at", time.Now().UTC().Format(time.RFC3339))
			}

			recorder.WriteHeader(statusCode)
			if len(tarballData) > 0 {
				if _, err := recorder.Write(tarballData); err != nil {
					t.Fatalf("write response body: %v", err)
				}
			}

			return recorder.Result(), req.Context().Err()
		}),
	}

	return api.NewClientWithHTTPClient("https://api.example.com", "test-key", httpClient)
}

func TestNewRemoteRuleSource(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cacheManager, err := cache.NewManager(nil)
	if err != nil {
		t.Fatalf("Failed to create cache manager: %v", err)
	}

	source := NewRemoteRuleSource(ctx, "dca", "latest", cacheManager)

	if source == nil {
		t.Fatal("NewRemoteRuleSource() returned nil")
	}

	if source.rulesetName != "dca" {
		t.Errorf("Expected rulesetName 'dca', got '%s'", source.rulesetName)
	}

	if source.version != "latest" {
		t.Errorf("Expected version 'latest', got '%s'", source.version)
	}

	if source.cacheManager == nil {
		t.Error("cacheManager should not be nil")
	}
}

func TestRemoteRuleSource_Name(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rulesetName  string
		version      string
		wantContains []string
	}{
		{
			name:         "dca latest",
			rulesetName:  "dca",
			version:      "latest",
			wantContains: []string{"remote", "dca", "latest"},
		},
		{
			name:         "custom ruleset with version",
			rulesetName:  "custom-rules",
			version:      "v1.2.3",
			wantContains: []string{"remote", "custom-rules", "v1.2.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cacheManager, err := cache.NewManager(nil)
			if err != nil {
				t.Fatalf("Failed to create cache manager: %v", err)
			}
			source := NewRemoteRuleSource(ctx, tt.rulesetName, tt.version, cacheManager)

			name := source.Name()

			if name == "" {
				t.Fatal("Name() should not return empty string")
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(name, want) {
					t.Errorf("Name() = %q should contain %q", name, want)
				}
			}
		})
	}
}

func TestRemoteRuleSource_Load(t *testing.T) {
	t.Run("uses cache manager and returns cached ruleset path", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())

		ctx := context.Background()
		cacheManager, err := cache.NewManager(newRemoteRuleSourceTestClient(t, http.StatusOK, true))
		if err != nil {
			t.Fatalf("Failed to create cache manager: %v", err)
		}

		source := NewRemoteRuleSource(ctx, "dca", "latest", cacheManager)
		paths, err := source.Load()
		if err != nil {
			t.Fatalf("Load() failed: %v", err)
		}

		if len(paths) != 1 {
			t.Fatalf("len(paths) = %d, want 1", len(paths))
		}
		if _, err := os.Stat(filepath.Join(paths[0], "semgrep-rules", "example.yaml")); err != nil {
			t.Fatalf("expected extracted rule file, got stat error: %v", err)
		}
	})

	t.Run("wraps cache retrieval failures", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())

		ctx := context.Background()
		cacheManager, err := cache.NewManager(newRemoteRuleSourceTestClient(t, http.StatusInternalServerError, false))
		if err != nil {
			t.Fatalf("Failed to create cache manager: %v", err)
		}

		source := NewRemoteRuleSource(ctx, "dca", "latest", cacheManager)
		_, err = source.Load()
		if err == nil {
			t.Fatal("expected Load() to fail")
		}
		if !strings.Contains(err.Error(), "failed to get ruleset 'dca@latest'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
