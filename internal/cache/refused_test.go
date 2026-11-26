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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
)

// refusingServer answers every request under path prefix refused with
// status and every other request with 503.
func refusingServer(t *testing.T, refused string, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if strings.Contains(r.URL.Path, refused) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(status)
			_, _ = w.Write([]byte("key revoked"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

// A key the API refuses (401 or 403) on the release check or on the
// download never scans with the cached ruleset, however fresh the stale
// copy is: the refusal is returned and the cache is not opened.
func TestGetRulesetPath_RefusedKeySkipsStaleCache(t *testing.T) {
	cases := []struct {
		name     string
		refused  string // path part the server refuses
		noCache  bool
		requests int32 // the refusal ends the run: no download after it, no retry
	}{
		{name: "release check", refused: "/rulesets/", requests: 1},
		{name: "download after a failed release check", refused: "/download", requests: 2},
		{name: "download with --no-cache", refused: "/download", noCache: true, requests: 1},
	}
	for _, tc := range cases {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			t.Run(tc.name+"/"+http.StatusText(status), func(t *testing.T) {
				srv, requests := refusingServer(t, tc.refused, status)
				m := newLeasedManager(t, srv.URL)
				m.SetNoCache(tc.noCache)
				seedCache(t, m, 2*time.Hour) // TTL elapsed, well within the stale age and the lease

				got, err := m.GetRulesetPath(context.Background(), "dca", "latest")
				if err == nil {
					t.Fatalf("got %q, want the refusal, not the stale cache", got)
				}
				var refused *api.RefusedError
				if !errors.As(err, &refused) || refused.StatusCode != status {
					t.Fatalf("got %v, want a refused-key error with HTTP %d", err, status)
				}
				if n := requests.Load(); n != tc.requests {
					t.Fatalf("%d requests, want %d", n, tc.requests)
				}
			})
		}
	}
}

// A server error and an unreachable API keep the stale fallback until the
// lease expires.
func TestGetRulesetPath_ServerErrorUsesStaleCache(t *testing.T) {
	srv, requests := refusingServer(t, "/never", http.StatusUnauthorized)
	m := newLeasedManager(t, srv.URL)
	path := seedCache(t, m, 2*time.Hour)
	got, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil || got != path {
		t.Fatalf("503: got %q, %v; want the stale cache", got, err)
	}
	if requests.Load() == 0 {
		t.Fatal("no request reached the API")
	}

	unreachable := newLeasedManager(t, "http://127.0.0.1:1")
	path = seedCache(t, unreachable, 2*time.Hour)
	got, err = unreachable.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil || got != path {
		t.Fatalf("unreachable: got %q, %v; want the stale cache", got, err)
	}
}
