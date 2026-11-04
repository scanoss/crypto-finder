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
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
)

func setRulesetHeaders(w http.ResponseWriter) {
	w.Header().Set("scanoss-ruleset-name", "dca")
	w.Header().Set("scanoss-ruleset-version", "v1.40.0")
	w.Header().Set("x-checksum-sha256", "abc123")
	w.Header().Set("scanoss-ruleset-created-at", "2026-11-04T10:00:00Z")
}

func TestClient_DownloadRuleset_V3ReturnsLease(t *testing.T) {
	t.Parallel()

	var paths []string
	client := newTestClient(t, "test-key", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		setRulesetHeaders(w)
		w.Header().Set("SCANOSS-Ruleset-Lease", base64.StdEncoding.EncodeToString([]byte(`{"format":"x"}`)))
		_, _ = w.Write([]byte("bundle"))
	})

	data, manifest, err := client.DownloadRuleset(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "bundle" || string(manifest.Lease) != `{"format":"x"}` {
		t.Fatalf("data %q lease %q", data, manifest.Lease)
	}
	if len(paths) != 1 || paths[0] != "/v3/rulesets/dca/latest/download" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestClient_DownloadRuleset_FallsBackToV2OnNotFound(t *testing.T) {
	t.Parallel()

	var paths []string
	client := newTestClient(t, "test-key", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/v3/rulesets/dca/latest/download" {
			http.NotFound(w, r)
			return
		}
		setRulesetHeaders(w)
		_, _ = w.Write([]byte("legacy"))
	})

	data, manifest, err := client.DownloadRuleset(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "legacy" || manifest.Lease != nil {
		t.Fatalf("data %q lease %q", data, manifest.Lease)
	}
	if len(paths) != 2 || paths[1] != "/v2/cryptography/rulesets/dca/latest/download" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestClient_DownloadRuleset_V3RefusalIsNotRetriedOnV2(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusBadRequest} {
		var paths []string
		client := newTestClient(t, "test-key", func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			if r.URL.Path == "/v3/rulesets/dca/latest/download" {
				w.WriteHeader(status)
				return
			}
			setRulesetHeaders(w)
			_, _ = w.Write([]byte("legacy"))
		})

		if _, _, err := client.DownloadRuleset(context.Background(), "dca", "latest"); err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if len(paths) != 1 {
			t.Fatalf("status %d: paths = %v", status, paths)
		}
	}
}

func TestClient_DownloadRuleset_InvalidLeaseHeader(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, "test-key", func(w http.ResponseWriter, _ *http.Request) {
		setRulesetHeaders(w)
		w.Header().Set("SCANOSS-Ruleset-Lease", "%%%")
		_, _ = w.Write([]byte("bundle"))
	})
	if _, _, err := client.DownloadRuleset(context.Background(), "dca", "latest"); err == nil {
		t.Fatal("expected an error for a lease header that is not base64")
	}
}

func TestClient_GetRelease(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, "test-key", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/rulesets/dca/latest" || r.Header.Get("x-api-key") != "test-key" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"format":"scanoss-ruleset-release/1","name":"dca","version":"v1.40.0","payload_sha256":"ff"}`))
	})
	release, err := client.GetRelease(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "v1.40.0" || release.PayloadSHA != "ff" {
		t.Fatalf("release = %+v", release)
	}
	if _, err := client.GetRelease(context.Background(), "dca", "v9.9.9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing release: got %v", err)
	}
}
