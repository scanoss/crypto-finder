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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

// An API answer that this client must be upgraded is final: a cached
// ruleset whose TTL elapsed is not used as a stale fallback, leased or not,
// and nothing is retried.
func TestGetRulesetPath_UpgradeRequiredSkipsStaleCache(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour))

	for _, status := range []int{http.StatusGone, http.StatusUpgradeRequired} {
		for _, leased := range []bool{false, true} {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("Upgrade crypto-finder."))
			}))
			m := newLeasedManager(t, srv.URL)
			path := m.getRulesetCachePath("dca", "latest")
			if leased {
				if err := m.storeLeased("dca", path, issued.Bundle, issued.LeaseJSON, issued.Lease, 1); err != nil {
					t.Fatal(err)
				}
			} else {
				writeRuleFile(t, filepath.Join(path, "semgrep-rules", "example.yaml"))
				if err := NewMetadata("dca", "v1.39.0", "checksum", 1).Save(filepath.Join(path, metadataFileName)); err != nil {
					t.Fatal(err)
				}
			}
			metaPath := filepath.Join(path, metadataFileName)
			meta, err := LoadMetadata(metaPath)
			if err != nil {
				t.Fatal(err)
			}
			meta.DownloadedAt = time.Now().Add(-2 * time.Hour) // TTL elapsed, well within the stale age
			if err := meta.Save(metaPath); err != nil {
				t.Fatal(err)
			}

			_, err = m.GetRulesetPath(context.Background(), "dca", "latest")
			var upgrade *api.UpgradeRequiredError
			if !errors.As(err, &upgrade) || upgrade.Message != "Upgrade crypto-finder." {
				t.Fatalf("status %d leased=%v: got %v, want the upgrade-required error", status, leased, err)
			}
			// One v3 download, not retried and not asked on v2; a leased
			// cache asks for the current release first.
			want := 1
			if leased {
				want = 2
			}
			if requests != want {
				t.Fatalf("status %d leased=%v: %d requests, want %d", status, leased, requests, want)
			}
			if _, statErr := os.Stat(path); statErr != nil {
				t.Fatalf("status %d leased=%v: the cached copy was removed: %v", status, leased, statErr)
			}
			srv.Close()
		}
	}

	// A server error still falls back to the same stale cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m := newLeasedManager(t, srv.URL)
	m.apiClient = api.NewClient(srv.URL, testAPIKey).WithRetryDelay(time.Millisecond)
	path := m.getRulesetCachePath("dca", "latest")
	writeRuleFile(t, filepath.Join(path, "semgrep-rules", "example.yaml"))
	meta := NewMetadata("dca", "v1.39.0", "checksum", 1)
	meta.DownloadedAt = time.Now().Add(-2 * time.Hour)
	if err := meta.Save(filepath.Join(path, metadataFileName)); err != nil {
		t.Fatal(err)
	}
	if got, err := m.GetRulesetPath(context.Background(), "dca", "latest"); err != nil || got != path {
		t.Fatalf("503: got %q, %v; want the stale cache", got, err)
	}
}
