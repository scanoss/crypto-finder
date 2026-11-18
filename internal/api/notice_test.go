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
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
)

// collectNotices installs a notice handler for the test and returns what it
// received so far.
func collectNotices(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	SetNoticeHandler(func(text string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, text)
	})
	t.Cleanup(func() { SetNoticeHandler(nil) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

func noticeServer(t *testing.T, status int, notice string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if notice != "" {
			w.Header().Set("SCANOSS-Notice", notice)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(readyComponentResponse))
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "test-key")
}

func TestNoticeReachesHandlerOnEveryRequest(t *testing.T) {
	notices := collectNotices(t)
	client := noticeServer(t, http.StatusOK, "crypto-finder 0.54 stops working on 2026-12-15")

	for range 3 {
		if _, _, err := client.ComponentFindings(t.Context(), "pkg:npm/a", "1.0.0"); err != nil {
			t.Fatalf("ComponentFindings: %v", err)
		}
	}
	_, _ = client.GetRelease(t.Context(), "dca", "latest") // only the header matters here

	got := notices()
	if len(got) != 4 {
		t.Fatalf("handler calls = %d, want 4 (one per response): %q", len(got), got)
	}
	for _, text := range got {
		if text != "crypto-finder 0.54 stops working on 2026-12-15" {
			t.Errorf("notice = %q", text)
		}
	}
}

func TestNoticeOnErrorAnswer(t *testing.T) {
	notices := collectNotices(t)
	client := noticeServer(t, http.StatusGone, "update crypto-finder")

	if _, err := client.GetRelease(t.Context(), "dca", "latest"); err == nil {
		t.Fatal("GetRelease on 410 returned no error")
	}
	if got := notices(); !slices.Equal(got, []string{"update crypto-finder"}) {
		t.Errorf("notices = %q", got)
	}
}

func TestNoticeIsSanitized(t *testing.T) {
	notices := collectNotices(t)
	client := noticeServer(t, http.StatusOK, "\u202eupdate\u200b now")

	if _, _, err := client.ComponentFindings(t.Context(), "pkg:npm/a", "1.0.0"); err != nil {
		t.Fatalf("ComponentFindings: %v", err)
	}
	if got := notices(); !slices.Equal(got, []string{"update now"}) {
		t.Errorf("notices = %q, want the format characters dropped", got)
	}
}

func TestNoNoticeWithoutHeaderOrHandler(t *testing.T) {
	notices := collectNotices(t)
	client := noticeServer(t, http.StatusOK, "")
	if _, _, err := client.ComponentFindings(t.Context(), "pkg:npm/a", "1.0.0"); err != nil {
		t.Fatalf("ComponentFindings: %v", err)
	}
	if got := notices(); len(got) != 0 {
		t.Errorf("notices without the header = %q", got)
	}

	SetNoticeHandler(nil)
	client = noticeServer(t, http.StatusOK, "ignored")
	if _, _, err := client.ComponentFindings(t.Context(), "pkg:npm/a", "1.0.0"); err != nil {
		t.Fatalf("ComponentFindings without a handler: %v", err)
	}
}

func TestNoticeKeepsCustomTransport(t *testing.T) {
	notices := collectNotices(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("SCANOSS-Notice", "hello")
		_, _ = w.Write([]byte(readyComponentResponse))
	}))
	t.Cleanup(server.Close)
	var used bool
	custom := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return http.DefaultTransport.RoundTrip(r)
	})}

	client := NewClientWithHTTPClient(server.URL, "test-key", custom)
	if _, _, err := client.ComponentFindings(t.Context(), "pkg:npm/a", "1.0.0"); err != nil {
		t.Fatalf("ComponentFindings: %v", err)
	}
	if !used {
		t.Error("the caller's transport was not used")
	}
	if len(notices()) != 1 {
		t.Errorf("notices = %q", notices())
	}
}

func TestNoticeIgnoresXPrefixedHeader(t *testing.T) {
	notices := collectNotices(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-SCANOSS-Notice", "old name")
		_, _ = w.Write([]byte(readyComponentResponse))
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "test-key")
	if _, _, err := client.ComponentFindings(t.Context(), "pkg:npm/a", "1.0.0"); err != nil {
		t.Fatalf("ComponentFindings: %v", err)
	}
	if got := notices(); len(got) != 0 {
		t.Errorf("notices from X-SCANOSS-Notice = %q, want none", got)
	}
}
