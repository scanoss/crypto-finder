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

package apiclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	client := NewClient("https://api.example.com", "test-key")

	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	if client.baseURL != "https://api.example.com" {
		t.Errorf("Expected baseURL 'https://api.example.com', got '%s'", client.baseURL)
	}

	if client.apiKey != "test-key" {
		t.Errorf("Expected apiKey 'test-key', got '%s'", client.apiKey)
	}

	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

func TestClient_DownloadRuleset_Success(t *testing.T) {
	t.Parallel()

	// Create minimal valid tarball
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	emptyTar := make([]byte, 1024)
	_, _ = gzWriter.Write(emptyTar)
	_ = gzWriter.Close()
	tarballData := buf.Bytes()

	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("x-api-key") != "test-key" {
			t.Error("Missing or incorrect API key header")
		}

		if r.Header.Get("user-agent") != "scanoss-crypto-finder" {
			t.Error("Missing or incorrect User-Agent header")
		}

		// Return response with headers
		w.Header().Set("scanoss-ruleset-name", "dca")
		w.Header().Set("scanoss-ruleset-version", "v1.0.0")
		w.Header().Set("x-checksum-sha256", "abc123")
		w.Header().Set("scanoss-ruleset-created-at", "2024-01-01T00:00:00Z")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarballData)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx := context.Background()

	// Execute
	data, manifest, err := client.DownloadRuleset(ctx, "dca", "v1.0.0")
	// Assert
	if err != nil {
		t.Fatalf("DownloadRuleset() failed: %v", err)
	}

	if data == nil {
		t.Fatal("Expected non-nil data")
	}

	if len(data) == 0 {
		t.Error("Expected non-empty data")
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	if manifest.Name != "dca" {
		t.Errorf("Expected manifest.Name 'dca', got '%s'", manifest.Name)
	}

	if manifest.Version != "v1.0.0" {
		t.Errorf("Expected manifest.Version 'v1.0.0', got '%s'", manifest.Version)
	}

	if manifest.ChecksumSHA256 != "abc123" {
		t.Errorf("Expected manifest.ChecksumSHA256 'abc123', got '%s'", manifest.ChecksumSHA256)
	}
}

func TestClient_DownloadRuleset_404NotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("ruleset not found"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx := context.Background()

	// Execute
	_, _, err := client.DownloadRuleset(ctx, "nonexistent", "v1.0.0")

	// Assert
	if err == nil {
		t.Fatal("Expected error for 404 response")
	}

	// Check that error wraps ErrNotFound
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestClient_DownloadRuleset_401Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid API key"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "invalid-key")
	ctx := context.Background()

	// Execute
	_, _, err := client.DownloadRuleset(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error for 401 response")
	}

	// Check that error wraps ErrUnauthorized
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized, got: %v", err)
	}
}

func TestClient_DownloadRuleset_403Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("access denied"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx := context.Background()

	// Execute
	_, _, err := client.DownloadRuleset(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error for 403 response")
	}

	// Check that error wraps ErrForbidden
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("Expected ErrForbidden, got: %v", err)
	}
}

func TestClient_DownloadRuleset_500ServerError(t *testing.T) {
	t.Parallel()

	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx := context.Background()

	// Execute
	_, _, err := client.DownloadRuleset(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error for 500 response")
	}

	// Should retry (default is 3 attempts, so total 4 requests)
	if attemptCount <= 1 {
		t.Errorf("Expected multiple retry attempts, got %d", attemptCount)
	}
}

func TestClient_DownloadRuleset_RetrySuccess(t *testing.T) {
	t.Parallel()

	attemptCount := 0

	// Create minimal valid tarball
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	emptyTar := make([]byte, 1024)
	_, _ = gzWriter.Write(emptyTar)
	_ = gzWriter.Close()
	tarballData := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attemptCount++

		// Fail first 2 attempts, succeed on 3rd
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Success on 3rd attempt
		w.Header().Set("scanoss-ruleset-name", "dca")
		w.Header().Set("scanoss-ruleset-version", "latest")
		w.Header().Set("x-checksum-sha256", "abc123")
		w.Header().Set("scanoss-ruleset-created-at", time.Now().Format(time.RFC3339))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarballData)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx := context.Background()

	// Execute
	data, manifest, err := client.DownloadRuleset(ctx, "dca", "latest")
	// Assert
	if err != nil {
		t.Fatalf("DownloadRuleset() failed: %v", err)
	}

	if data == nil {
		t.Fatal("Expected non-nil data")
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	if attemptCount != 3 {
		t.Errorf("Expected 3 attempts (2 failures + 1 success), got %d", attemptCount)
	}
}

func TestClient_DownloadRuleset_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Cancel context before responding
		cancel()
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")

	// Execute
	_, _, err := client.DownloadRuleset(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error due to context cancellation")
	}
}

func TestClient_DownloadRuleset_MissingHeaders(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	emptyTar := make([]byte, 1024)
	_, _ = gzWriter.Write(emptyTar)
	_ = gzWriter.Close()
	tarballData := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return 200 but without required headers
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarballData)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx := context.Background()

	// Execute
	_, _, err := client.DownloadRuleset(ctx, "dca", "latest")

	// Assert - should fail due to missing headers
	if err == nil {
		t.Fatal("Expected error for missing headers")
	}
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         error
		isRetryable bool
	}{
		{
			name:        "nil error",
			err:         nil,
			isRetryable: false,
		},
		{
			name:        "unauthorized error (401)",
			err:         ErrUnauthorized,
			isRetryable: false,
		},
		{
			name:        "forbidden error (403)",
			err:         ErrForbidden,
			isRetryable: false,
		},
		{
			name:        "not found error (404)",
			err:         ErrNotFound,
			isRetryable: false,
		},
		{
			name:        "invalid checksum error",
			err:         ErrInvalidChecksum,
			isRetryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			if result != tt.isRetryable {
				t.Errorf("IsRetryable(%v) = %v, expected %v", tt.err, result, tt.isRetryable)
			}
		})
	}
}

func TestManifest_TimezoneParsing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		emptyTar := make([]byte, 1024)
		_, _ = gzWriter.Write(emptyTar)
		_ = gzWriter.Close()

		w.Header().Set("scanoss-ruleset-name", "dca")
		w.Header().Set("scanoss-ruleset-version", "v1.0.0")
		w.Header().Set("x-checksum-sha256", "abc123")
		w.Header().Set("scanoss-ruleset-created-at", "2024-12-25T10:30:00Z")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key")
	ctx := context.Background()

	// Execute
	_, manifest, err := client.DownloadRuleset(ctx, "dca", "v1.0.0")
	// Assert
	if err != nil {
		t.Fatalf("DownloadRuleset() failed: %v", err)
	}

	expectedTime := time.Date(2024, 12, 25, 10, 30, 0, 0, time.UTC)
	if !manifest.CreatedAt.Equal(expectedTime) {
		t.Errorf("Expected CreatedAt %v, got %v", expectedTime, manifest.CreatedAt)
	}
}
