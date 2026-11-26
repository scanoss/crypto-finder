// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	api "github.com/scanoss/crypto-finder/internal/api"
)

// fallbackAPIStub is a SCANOSS API that holds reachability data for
// acme-seal only, with no finding in it: every other dependency it answers
// NO_INFO.
func fallbackAPIStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/cryptography/reachability/application" {
			http.NotFound(w, r)
			return
		}
		var request api.ApplicationReachabilityRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		answer := api.ApplicationReachability{SchemaVersion: "1", InfoCode: "READY"}
		for _, d := range request.Dependencies {
			dep := api.ApplicationDependencyAnswer{Purl: d.Purl, Version: d.Version, Direct: d.Direct, InfoCode: "NO_INFO", Findings: []api.ApplicationFinding{}}
			if d.Purl == "pkg:npm/acme-seal" {
				dep.InfoCode = "READY"
			}
			answer.Dependencies = append(answer.Dependencies, dep)
		}
		_ = json.NewEncoder(w).Encode(answer)
	}))
}

// An online scan answers offline, from the installed package, the
// dependency the API holds no data for (acme-sign: its finding, reachable,
// as --offline serves it), keeps the API's answer for acme-seal, and lists
// the one installed nowhere (@acme/missing) without data, with why the
// fallback could not answer it. --no-offline-fallback serves the API's
// answer as it is.
func TestScanNodeProjectOnlineWithOfflineFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	ruleset := nodeDependencyRuleset(t, dir)
	project := filepath.Join(dir, "project")
	writeAnnotateCardsFile(t, filepath.Join(project, "package.json"),
		`{"name":"app","main":"index.js","dependencies":{"acme-sign":"^2.0.0","acme-seal":"^3.0.0","@acme/missing":"^1.0.0"}}`)
	writeAnnotateCardsFile(t, filepath.Join(project, "package-lock.json"), `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"acme-sign":"^2.0.0","acme-seal":"^3.0.0","@acme/missing":"^1.0.0"}},
"node_modules/acme-sign":{"version":"2.0.1"},
"node_modules/acme-seal":{"version":"3.0.0"},
"node_modules/@acme/missing":{"version":"1.0.0"}}}`)
	writeAnnotateCardsFile(t, filepath.Join(project, "index.js"), `const signer = require("acme-sign");
const sealer = require("acme-seal");

function viaDependency(x) {
  return signer.sign(x);
}

function viaSeal(x) {
  return sealer.seal(x);
}

viaDependency("x");
viaSeal("y");
`)
	for _, pkg := range []struct{ name, version, fn string }{{"acme-sign", "2.0.1", "sign"}, {"acme-seal", "3.0.0", "seal"}} {
		writeAnnotateCardsFile(t, filepath.Join(project, "node_modules", pkg.name, "package.json"), `{"name":"`+pkg.name+`","version":"`+pkg.version+`","main":"index.js"}`)
		writeAnnotateCardsFile(t, filepath.Join(project, "node_modules", pkg.name, "index.js"), `const h = require("acme-hash");

exports.`+pkg.fn+` = function (x) {
  return h.digest(x);
};
`)
	}
	server := fallbackAPIStub(t)
	defer server.Close()

	scan := func(name string, extra ...string) (map[string]string, map[string]any, string) {
		out := filepath.Join(dir, name)
		args := make([]string, 0, 32)
		args = append(args,
			"scan", "--no-remote-rules", "--rules-dir", ruleset, "--languages", "javascript", "--progress",
			"--scan-dependencies", "--api-url", server.URL, "--api-key", "test", "--allow-http",
			"--offline-cache-dir", filepath.Join(dir, "cache"),
			"--output", out+".json", "--export-callgraph", out+".callgraph.json",
		)
		args = append(args, extra...)
		cmd := exec.CommandContext(t.Context(), binary, append(args, project)...)
		cmd.Env = progressTestEnv(dir)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("scan %s: %v\n%s", name, err, stderr.String())
		}
		var report struct {
			Findings []struct {
				FilePath            string `json:"file_path"`
				CryptographicAssets []struct {
					FindingID      string `json:"finding_id"`
					Source         string `json:"source"`
					DependencyInfo *struct {
						Module, Version string
					} `json:"dependency_info"`
				} `json:"cryptographic_assets"`
			} `json:"findings"`
		}
		readPythonScanJSON(t, out+".json", &report)
		var callgraph struct {
			FindingGraphs []struct {
				FindingID    string `json:"finding_id"`
				Reachability string `json:"reachability"`
			} `json:"finding_graphs"`
		}
		readPythonScanJSON(t, out+".callgraph.json", &callgraph)
		verdicts := map[string]string{}
		for _, g := range callgraph.FindingGraphs {
			verdicts[g.FindingID] = g.Reachability
		}
		got := map[string]string{}
		for _, f := range report.Findings {
			for _, a := range f.CryptographicAssets {
				if a.DependencyInfo != nil {
					got[a.Source+" "+f.FilePath+" "+a.DependencyInfo.Module+"@"+a.DependencyInfo.Version] = verdicts[a.FindingID]
				}
			}
		}
		var details map[string]any
		for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
			var event map[string]any
			if json.Unmarshal([]byte(line), &event) == nil && event["phase"] == "dependencies" && event["status"] == "completed" {
				details, _ = event["details"].(map[string]any)
			}
		}
		return got, details, stderr.String()
	}

	got, details, stderr := scan("fallback")
	if want := map[string]string{"dependency index.js acme-sign@2.0.1": "reachable"}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings with the fallback\n got %v\nwant %v\nstderr:\n%s", got, want, stderr)
	}
	answered := []any{map[string]any{"purl": "pkg:npm/acme-sign", "version": "2.0.1"}}
	if !reflect.DeepEqual(details["deps_answered_offline_list"], answered) || details["deps_answered_offline"] != 1.0 || details["deps_answered_online"] != 1.0 {
		t.Errorf("answered: offline %v %v, online %v", details["deps_answered_offline_list"], details["deps_answered_offline"], details["deps_answered_online"])
	}
	skipped, _ := details["deps_skipped_list"].([]any)
	if len(skipped) != 1 {
		t.Fatalf("deps_skipped_list = %v, want @acme/missing only", details["deps_skipped_list"])
	}
	missing := skipped[0].(map[string]any)
	if missing["module"] != "@acme/missing" || missing["reason"] != "no_reachability_data" || missing["offline_fallback"] == nil {
		t.Errorf("@acme/missing = %v, want no_reachability_data with the fallback's reason", missing)
	}

	// The fallback's answer for acme-sign is the one --offline gives.
	offline, _, stderr := scan("offline", "--offline")
	if offline["dependency index.js acme-sign@2.0.1"] != got["dependency index.js acme-sign@2.0.1"] {
		t.Errorf("acme-sign: fallback %v, --offline %v\nstderr:\n%s", got, offline, stderr)
	}

	got, details, stderr = scan("no-fallback", "--no-offline-fallback")
	if len(got) != 0 {
		t.Errorf("findings without the fallback = %v, want none\nstderr:\n%s", got, stderr)
	}
	if _, ok := details["deps_answered_offline"]; ok {
		t.Errorf("details without the fallback carry deps_answered_offline: %v", details)
	}
	if skipped, _ := details["deps_skipped_list"].([]any); len(skipped) != 2 {
		t.Errorf("deps_skipped_list without the fallback = %v, want acme-sign and @acme/missing", details["deps_skipped_list"])
	}
}
