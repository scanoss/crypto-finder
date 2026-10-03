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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

const readyComponentResponse = `{
  "rules_version": "rules-2026.10",
  "info_code": "READY",
  "status": {"status": "SUCCESS", "message": "Reachability computed"},
  "data": [{
    "purl": "pkg:maven/commons-codec/commons-codec",
    "version": "1.17.0",
    "requirement": "1.17.0",
    "finding_count": 1,
    "schemas": {"findings": "1.6", "callgraph": "6.14"},
    "findings": [{
      "file_path": "org/apache/commons/codec/digest/B64.java",
      "language": "java",
      "cryptographic_assets": [{
        "finding_id": "dcd8626d",
        "match": "return getRandomSalt(num, new SecureRandom());",
        "source": "direct",
        "start_line": 79,
        "end_line": 79,
        "metadata": {"assetType": "algorithm", "algorithmPrimitive": "drbg"},
        "rules": [{"id": "jca.algorithm.drbg.securerandom"}]
      }]
    }]
  }]
}`

func serveComponent(t *testing.T, status int, body string, seen func(*http.Request, []byte)) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if seen != nil {
			seen(r, payload)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "test-key")
}

func TestComponentFindings_SendsPurlAndRequirementOnly(t *testing.T) {
	called := false
	client := serveComponent(t, http.StatusOK, readyComponentResponse, func(r *http.Request, body []byte) {
		called = true
		if r.Method != http.MethodPost || r.URL.Path != "/v3/cryptography/reachability/component" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("x-api-key = %q", got)
		}
		var fields map[string]any
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatalf("request body is not JSON: %v", err)
		}
		want := map[string]any{"purl": "pkg:maven/commons-codec/commons-codec", "requirement": "1.17.0"}
		if !reflect.DeepEqual(fields, want) {
			t.Errorf("request body = %v, want %v", fields, want)
		}
	})

	if _, _, err := client.ComponentFindings(context.Background(), "pkg:maven/commons-codec/commons-codec", "1.17.0"); err != nil {
		t.Fatalf("ComponentFindings: %v", err)
	}
	if !called {
		t.Fatal("no request reached the API")
	}
}

func TestComponentFindings_ReadyDecodesFindings(t *testing.T) {
	client := serveComponent(t, http.StatusOK, readyComponentResponse, nil)

	got, found, err := client.ComponentFindings(context.Background(), "pkg:maven/commons-codec/commons-codec", "1.17.0")
	if err != nil || !found {
		t.Fatalf("ComponentFindings = found %v, err %v", found, err)
	}
	if got.RulesVersion != "rules-2026.10" || got.Version != "1.17.0" {
		t.Errorf("rules version %q, served version %q", got.RulesVersion, got.Version)
	}
	if len(got.Findings) != 1 || len(got.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("findings = %+v", got.Findings)
	}
	finding := got.Findings[0]
	asset := finding.CryptographicAssets[0]
	if finding.FilePath != "org/apache/commons/codec/digest/B64.java" || finding.Language != "java" {
		t.Errorf("finding = %q %q", finding.FilePath, finding.Language)
	}
	if asset.StartLine != 79 || asset.EndLine != 79 || asset.Match != "return getRandomSalt(num, new SecureRandom());" {
		t.Errorf("asset location = %+v", asset)
	}
	if len(asset.Rules) != 1 || asset.Rules[0].ID != "jca.algorithm.drbg.securerandom" {
		t.Errorf("rules = %+v", asset.Rules)
	}
	if asset.Metadata["assetType"] != "algorithm" || asset.Metadata["algorithmPrimitive"] != "drbg" {
		t.Errorf("metadata = %v", asset.Metadata)
	}
}

func TestComponentFindings_ServesClosestPatch(t *testing.T) {
	body := `{"info_code":"READY","rules_version":"r1","data":[{"purl":"pkg:maven/org.bouncycastle/bcprov-jdk18on",` +
		`"version":"1.78.1","actual_mined_version":"1.78","findings":[],"finding_count":0}]}`
	client := serveComponent(t, http.StatusOK, body, nil)

	got, found, err := client.ComponentFindings(context.Background(), "pkg:maven/org.bouncycastle/bcprov-jdk18on", "1.78.1")
	if err != nil || !found {
		t.Fatalf("ComponentFindings = found %v, err %v", found, err)
	}
	if got.Version != "1.78" || len(got.Findings) != 0 {
		t.Errorf("served version %q, findings %d; want the mined patch and no findings", got.Version, len(got.Findings))
	}
}

func TestComponentFindings_NotReadyIsNotFound(t *testing.T) {
	for _, body := range []string{
		`{"info_code":"COMPONENT_NOT_FOUND","status":{"status":"SUCCESS"}}`,
		`{"info_code":"VERSION_NOT_FOUND"}`,
		`{"info_code":"NO_INFO"}`,
		`{"info_code":"READY","data":[]}`,
	} {
		client := serveComponent(t, http.StatusOK, body, nil)
		got, found, err := client.ComponentFindings(context.Background(), "pkg:maven/a/b", "1.0")
		if err != nil || found || got != nil {
			t.Errorf("%s: got %+v, found %v, err %v; want not found", body, got, found, err)
		}
	}
}

func TestComponentFindings_AccessErrors(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusUnauthorized: ErrUnauthorized,
		http.StatusForbidden:    ErrForbidden,
		http.StatusBadGateway:   ErrServerError,
	} {
		client := serveComponent(t, status, `{"error":"Endpoint access denied"}`, nil)
		_, found, err := client.ComponentFindings(context.Background(), "pkg:maven/a/b", "1.0")
		if found || !errors.Is(err, want) {
			t.Errorf("HTTP %d: found %v, err %v; want %v", status, found, err, want)
		}
	}
}

func TestComponentFindings_MalformedBodyIsAnError(t *testing.T) {
	client := serveComponent(t, http.StatusOK, `{"info_code":"READY","data":[{"findings":"x"}]}`, nil)
	if _, found, err := client.ComponentFindings(context.Background(), "pkg:maven/a/b", "1.0"); found || err == nil {
		t.Errorf("found %v, err %v; want a decode error", found, err)
	}
}
