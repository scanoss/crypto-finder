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
	"net/http"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

const readyApplicationResponse = `{
  "schema_version": "1",
  "rules_version": "v1.48.0",
  "info_code": "READY",
  "info_message": "1 of 1 dependencies have reachability data",
  "summary": {"reachable": 1, "unknown": 1, "unreachable": 0},
  "dependencies": [{
    "purl": "pkg:maven/commons-codec/commons-codec",
    "version": "1.17.0",
    "direct": true,
    "info_code": "READY",
    "summary": {"reachable": 1, "unknown": 1, "unreachable": 0},
    "finding_count": 2,
    "findings": [{
      "file_path": "commons-codec:commons-codec@1.17.0/org/apache/commons/codec/digest/DigestUtils.java",
      "language": "java",
      "dependency_info": {"module": "commons-codec:commons-codec", "version": "1.17.0", "purl": "pkg:maven/commons-codec/commons-codec@1.17.0"},
      "cryptographic_assets": [{
        "finding_id": "1a2b3c4d",
        "match": "MessageDigest.getInstance(algorithm)",
        "source": "indirect",
        "start_line": 216,
        "end_line": 216,
        "metadata": {"assetType": "algorithm", "algorithmName": "MD5"},
        "rules": [{"id": "jca.algorithm.hash.md5"}],
        "reachability": "reachable",
        "analysis": {"call_chains": "complete", "route_evidence": "direct"},
        "call_chains": [[{"function_key": "app.(Main).run#0"}]]
      }, {
        "finding_id": "5e6f7a8b",
        "match": "MessageDigest.getInstance(\"SHA-1\")",
        "source": "indirect",
        "start_line": 300,
        "end_line": 300,
        "metadata": {"assetType": "algorithm", "algorithmName": "SHA-1"},
        "rules": [{"id": "jca.algorithm.hash.sha1"}],
        "reachability": "unknown",
        "reachability_reason": "ambiguous_dispatch"
      }]
    }]
  }]
}`

func TestApplicationReachability_SendsOneRequest(t *testing.T) {
	requests := 0
	client := serveComponent(t, http.StatusOK, readyApplicationResponse, func(r *http.Request, body []byte) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/v3/cryptography/reachability/application" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("x-api-key = %q", got)
		}
		var fields struct {
			SchemaVersion       string                  `json:"schema_version"`
			Dependencies        []ApplicationDependency `json:"dependencies"`
			CallSites           map[string]any          `json:"call_sites"`
			IncludeCallChains   bool                    `json:"include_call_chains"`
			MaxChainsPerFinding int                     `json:"max_chains_per_finding"`
		}
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatalf("request body is not JSON: %v", err)
		}
		if fields.SchemaVersion != "1" || len(fields.Dependencies) != 2 || !fields.Dependencies[0].Direct ||
			fields.Dependencies[0].Requires[0] != "pkg:maven/b/b" {
			t.Errorf("request = %+v", fields)
		}
		if fields.CallSites["schema_version"] != graphfrag.SchemaVersion || !fields.IncludeCallChains || fields.MaxChainsPerFinding != 1 {
			t.Errorf("call sites %v, chains %v/%d", fields.CallSites["schema_version"], fields.IncludeCallChains, fields.MaxChainsPerFinding)
		}
	})

	request := &ApplicationReachabilityRequest{
		SchemaVersion: ApplicationReachabilitySchemaVersion,
		Dependencies: []ApplicationDependency{
			{Purl: "pkg:maven/a/a", Version: "1.0", Direct: true, Requires: []string{"pkg:maven/b/b"}},
			{Purl: "pkg:maven/b/b", Version: "2.0"},
		},
		CallSites:           &graphfrag.GraphFragmentExport{SchemaVersion: graphfrag.SchemaVersion},
		IncludeCallChains:   true,
		MaxChainsPerFinding: 1,
	}
	answer, err := client.ApplicationReachability(context.Background(), request)
	if err != nil {
		t.Fatalf("ApplicationReachability: %v", err)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1", requests)
	}
	if answer.RequestBytes == 0 || answer.ResponseBytes != len(readyApplicationResponse) {
		t.Errorf("sizes = %d up, %d down", answer.RequestBytes, answer.ResponseBytes)
	}
}

// The asset type has its own UnmarshalJSON; the verdict beside it must
// survive decoding, as must the asset itself.
func TestApplicationReachability_DecodesVerdictsBesideAssets(t *testing.T) {
	client := serveComponent(t, http.StatusOK, readyApplicationResponse, nil)

	answer, err := client.ApplicationReachability(context.Background(), &ApplicationReachabilityRequest{SchemaVersion: "1"})
	if err != nil {
		t.Fatalf("ApplicationReachability: %v", err)
	}
	if answer.InfoCode != "READY" || len(answer.Dependencies) != 1 || answer.Summary.Reachable != 1 {
		t.Fatalf("answer = %+v", answer)
	}
	assets := answer.Dependencies[0].Findings[0].CryptographicAssets
	if len(assets) != 2 {
		t.Fatalf("assets = %d", len(assets))
	}
	reached, unknown := assets[0], assets[1]
	if reached.Reachability != "reachable" || len(reached.CallChains) == 0 || len(reached.Analysis) == 0 {
		t.Errorf("reachable asset verdict = %q, chains %s, analysis %s", reached.Reachability, reached.CallChains, reached.Analysis)
	}
	if unknown.Reachability != "unknown" || unknown.ReachabilityReason != "ambiguous_dispatch" {
		t.Errorf("unknown asset verdict = %q (%q)", unknown.Reachability, unknown.ReachabilityReason)
	}
	if reached.Asset.StartLine != 216 || reached.Asset.Match != "MessageDigest.getInstance(algorithm)" ||
		len(reached.Asset.Rules) != 1 || reached.Asset.Metadata["algorithmName"] != "MD5" {
		t.Errorf("asset = %+v", reached.Asset)
	}
}

func TestApplicationReachability_NonOKIsAnError(t *testing.T) {
	client := serveComponent(t, http.StatusUnauthorized, `{"error":"no"}`, nil)
	if _, err := client.ApplicationReachability(context.Background(), &ApplicationReachabilityRequest{SchemaVersion: "1"}); err == nil {
		t.Fatal("ApplicationReachability on 401: no error")
	}
}
