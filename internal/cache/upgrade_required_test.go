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
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
)

// An API answer that this client must be upgraded is final: a cached
// ruleset whose TTL elapsed is not used as a stale fallback, and nothing is
// retried.
func TestGetRulesetPath_UpgradeRequiredSkipsStaleCache(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusUpgradeRequired} {
		requests := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests++
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(status)
			_, _ = w.Write([]byte("Upgrade crypto-finder."))
		}))
		m := newLeasedManager(t, srv.URL)
		path := seedCache(t, m, 2*time.Hour) // TTL elapsed, well within the stale age

		_, err := m.GetRulesetPath(context.Background(), "dca", "latest")
		var upgrade *api.UpgradeRequiredError
		if !errors.As(err, &upgrade) || upgrade.Message != "Upgrade crypto-finder." {
			t.Fatalf("status %d: got %v, want the upgrade-required error", status, err)
		}
		// The release check, then one download, not retried.
		if requests != 2 {
			t.Fatalf("status %d: %d requests, want 2", status, requests)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("status %d: the cached copy was removed: %v", status, statErr)
		}
		srv.Close()
	}

	// A server error still falls back to the same stale cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m := newLeasedManager(t, srv.URL)
	path := seedCache(t, m, 2*time.Hour)
	if got, err := m.GetRulesetPath(context.Background(), "dca", "latest"); err != nil || got != path {
		t.Fatalf("503: got %q, %v; want the stale cache", got, err)
	}
}
