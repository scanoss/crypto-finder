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
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestServerMessage(t *testing.T) {
	t.Parallel()

	jsonHeader := http.Header{"Content-Type": {"application/json"}}
	textHeader := http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	htmlHeader := http.Header{"Content-Type": {"text/html"}}
	cases := []struct {
		name   string
		header http.Header
		body   string
		want   string
	}{
		{"scanoss.api error body", jsonHeader, `{"status":"error","error":{"code":"CLIENT_UPGRADE_REQUIRED","message":"crypto-finder 0.40 is no longer supported. Upgrade: https://example.com"},"timestamp":"2026-11-11T00:00:00Z"}`, "crypto-finder 0.40 is no longer supported. Upgrade: https://example.com (CLIENT_UPGRADE_REQUIRED)"},
		{"error as a string", jsonHeader, `{"error":"Endpoint access denied"}`, "Endpoint access denied"},
		{"top-level message", jsonHeader, `{"message":"key expired"}`, "key expired"},
		{"plain text", textHeader, "Upgrade crypto-finder.\r\n\r\nSee the release notes.\n", "Upgrade crypto-finder.\nSee the release notes."},
		{"no content type", http.Header{}, "please upgrade", "please upgrade"},
		{"html page", htmlHeader, "<html><body>Gone</body></html>", ""},
		{"unreadable json", jsonHeader, `{"error":`, ""},
		{"escape sequences and bidi controls", textHeader, "\x1b[31mred\x1b[0m\tand\u202eevil\x07", "[31mred[0m andevil"},
		{"empty", textHeader, "  \n ", ""},
	}
	for _, tc := range cases {
		if got := serverMessage(tc.header, []byte(tc.body)); got != tc.want {
			t.Errorf("%s: serverMessage() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSanitizeServerMessage_Caps(t *testing.T) {
	t.Parallel()

	long := sanitizeServerMessage(strings.Repeat("x", 5000))
	if n := len([]rune(long)); n != maxServerMessageRunes+1 || !strings.HasSuffix(long, serverMessageTruncated) {
		t.Fatalf("long message: %d runes, suffix %q", n, long[len(long)-3:])
	}
	many := sanitizeServerMessage(strings.Repeat("line\n", 50))
	if lines := strings.Split(many, "\n"); len(lines) != maxServerMessageLines || !strings.HasSuffix(many, serverMessageTruncated) {
		t.Fatalf("many lines: %d lines", len(lines))
	}
}

func TestClient_DownloadRuleset_UpgradeRequiredIsFinal(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		status int
		v3     bool // answer on v3; otherwise v3 is 404 and v2 answers
		body   string
		want   string
	}{
		{"v3 410 json", http.StatusGone, true, `{"status":"error","error":{"code":"CLIENT_GONE","message":"This crypto-finder is too old. Upgrade it."}}`, "This crypto-finder is too old. Upgrade it. (CLIENT_GONE)"},
		{"v3 426 text", http.StatusUpgradeRequired, true, "Upgrade crypto-finder to 0.60 or later.", "Upgrade crypto-finder to 0.60 or later."},
		{"v2 410 after v3 404", http.StatusGone, false, "Upgrade crypto-finder.", "Upgrade crypto-finder."},
		{"v2 426 without a body", http.StatusUpgradeRequired, false, "", defaultUpgradeMessage},
	} {
		var paths []string
		client := newTestClient(t, "test-key", func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			if !tc.v3 && strings.HasPrefix(r.URL.Path, "/v3/") {
				http.NotFound(w, r)
				return
			}
			if strings.HasPrefix(tc.body, "{") {
				w.Header().Set("Content-Type", "application/json")
			} else {
				w.Header().Set("Content-Type", "text/plain")
			}
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		})

		_, _, err := client.DownloadRuleset(context.Background(), "dca", "latest")
		var upgrade *UpgradeRequiredError
		if !errors.As(err, &upgrade) || !errors.Is(err, ErrUpgradeRequired) {
			t.Fatalf("%s: got %v, want an upgrade-required error", tc.name, err)
		}
		if upgrade.StatusCode != tc.status || upgrade.Message != tc.want {
			t.Fatalf("%s: got %d %q, want %d %q", tc.name, upgrade.StatusCode, upgrade.Message, tc.status, tc.want)
		}
		wantRequests := 1
		if !tc.v3 {
			wantRequests = 2
		}
		if len(paths) != wantRequests {
			t.Fatalf("%s: requests %v, want %d (no retry, no other endpoint)", tc.name, paths, wantRequests)
		}
	}
}

func TestClient_GetRelease_UpgradeRequired(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, "test-key", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	})
	if _, err := client.GetRelease(context.Background(), "dca", "latest"); !errors.Is(err, ErrUpgradeRequired) {
		t.Fatalf("got %v, want an upgrade-required error", err)
	}
}

func TestClient_DownloadRuleset_RefusedKeyReadsWell(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		client := newTestClient(t, "test-key", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"status":"error","error":{"code":"RULESET_KEY_REQUIRED","message":"this ruleset needs an API key"}}`))
		})
		_, _, err := client.DownloadRuleset(context.Background(), "dca", "latest")
		var refused *RefusedError
		if !errors.As(err, &refused) || refused.StatusCode != status || refused.Message != "this ruleset needs an API key (RULESET_KEY_REQUIRED)" {
			t.Fatalf("status %d: got %v", status, err)
		}
		if strings.Contains(err.Error(), "{") || strings.Contains(err.Error(), "retries") {
			t.Fatalf("status %d: error reads %q", status, err)
		}
	}
}
