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

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestScanCommand_NoDependencyFindingsAPIFlag(t *testing.T) {
	flag := scanCmd.Flags().Lookup("no-dependency-findings-api")
	if flag == nil {
		t.Fatal("expected --no-dependency-findings-api flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("default = %q, want false", flag.DefValue)
	}
}

func TestNewDependencyFindingsSource_OnlyWithAPIKeyAndNotDisabled(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v3/cryptography/reachability/component" || r.Header.Get("x-api-key") != "key" {
			t.Errorf("request %s with key %q", r.URL.Path, r.Header.Get("x-api-key"))
		}
		_, _ = w.Write([]byte(`{"info_code":"READY","data":[{"version":"1.0","findings":[]}]}`))
	}))
	t.Cleanup(server.Close)

	if source := newDependencyFindingsSource(server.URL, "", false); source != nil {
		t.Error("a source without an API key")
	}
	if source := newDependencyFindingsSource(server.URL, "key", true); source != nil {
		t.Error("a source with --no-dependency-findings-api")
	}
	source := newDependencyFindingsSource(server.URL, "key", false)
	if source == nil {
		t.Fatal("no source with an API key")
	}
	if _, found, err := source.Findings(context.Background(), "pkg:maven/a/b", "1.0"); err != nil || !found {
		t.Fatalf("Findings: found %v, err %v", found, err)
	}
	if requests.Load() != 1 {
		t.Errorf("API received %d requests, want 1", requests.Load())
	}
}
