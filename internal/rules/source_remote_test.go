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
	"context"
	"net/http"
	"net/http/httptest"
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

// newFailingTestClient returns an API client whose every request fails
// with a server error. A successful Load is covered by
// TestRemoteRuleSource_LeasedRulesetLivesOnlyForTheRun.
func newFailingTestClient() *api.Client {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			recorder.WriteHeader(http.StatusInternalServerError)
			return recorder.Result(), req.Context().Err()
		}),
	}

	return api.NewClientWithHTTPClient("https://api.example.com", "test-key", httpClient).WithRetryDelay(time.Millisecond)
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
	t.Run("wraps cache retrieval failures", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())

		ctx := context.Background()
		cacheManager, err := cache.NewManager(newFailingTestClient())
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
