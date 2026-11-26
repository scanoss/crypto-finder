// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gf "github.com/scanoss/reach/graphfrag"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/engine"
	pr "github.com/scanoss/crypto-finder/pkg/appreach"
)

const (
	fallbackPurlA = "pkg:maven/org.example/a"
	fallbackPurlB = "pkg:maven/org.example/b"
	fallbackPurlC = "pkg:maven/org.example/c"
)

// apiAnswer is an online answer: a READY, b and c without data.
func apiAnswer() *api.ApplicationReachability {
	return &api.ApplicationReachability{
		SchemaVersion: "1",
		InfoCode:      "READY",
		InfoMessage:   "1 of 3 dependencies have reachability data",
		Summary:       api.ApplicationReachabilitySummary{Reachable: 1},
		Dependencies: []api.ApplicationDependencyAnswer{
			{Purl: fallbackPurlA, Version: "1.0", Direct: true, InfoCode: "READY", Summary: api.ApplicationReachabilitySummary{Reachable: 1}, Findings: []api.ApplicationFinding{{FilePath: "a@1.0/A.java"}}},
			{Purl: fallbackPurlB, Version: "2.0", InfoCode: "NO_INFO", Findings: []api.ApplicationFinding{}},
			{Purl: fallbackPurlC, Version: "3.0", InfoCode: "NO_INFO", Findings: []api.ApplicationFinding{}},
		},
	}
}

// localAnswer is what the offline path answers for the whole request: a
// served without data (the API answered it, so it was not mined), b mined,
// c failed to mine.
func localAnswer() *api.ApplicationReachability {
	return &api.ApplicationReachability{
		SchemaVersion: "1",
		InfoCode:      "READY",
		Dependencies: []api.ApplicationDependencyAnswer{
			{Purl: fallbackPurlA, Version: "1.0", Direct: true, InfoCode: "NO_INFO"},
			{Purl: fallbackPurlB, Version: "2.0", InfoCode: "READY", RulesVersion: "local", Summary: api.ApplicationReachabilitySummary{Unreachable: 1}, Findings: []api.ApplicationFinding{{FilePath: "b@2.0/B.java"}}},
			{Purl: fallbackPurlC, Version: "3.0", InfoCode: "NO_INFO", InfoMessage: "offline: mining org.example:c@3.0 failed: boom"},
		},
	}
}

// The dependencies the API answered without data, and only those, are
// answered locally, and their local answers replace the API's in place.
func TestOfflineFallbackMergesTheLocalAnswers(t *testing.T) {
	answer := apiAnswer()
	var asked []string
	report := fillWithoutDataOffline(context.Background(), answer, func(_ context.Context, purls []string) (*api.ApplicationReachability, error) {
		asked = purls
		return localAnswer(), nil
	})

	if want := []string{fallbackPurlB, fallbackPurlC}; !slices.Equal(asked, want) {
		t.Fatalf("asked the offline path for %v, want %v", asked, want)
	}
	want := apiAnswer()
	want.Dependencies[1] = localAnswer().Dependencies[1]
	if !reflect.DeepEqual(answer.Dependencies, want.Dependencies) {
		t.Fatalf("merged dependencies:\n got %+v\nwant %+v", answer.Dependencies, want.Dependencies)
	}
	if want := []dependencyAnsweredOffline{{PURL: fallbackPurlB, Version: "2.0"}}; !reflect.DeepEqual(report.answered, want) {
		t.Fatalf("answered offline = %+v, want %+v", report.answered, want)
	}
	if got := report.failed[fallbackKey(fallbackPurlC, "3.0")]; !strings.Contains(got, "boom") {
		t.Fatalf("failure of c = %q, want the offline message", got)
	}
	if _, ok := report.failed[fallbackKey(fallbackPurlB, "2.0")]; ok {
		t.Fatal("b is reported failed although the offline path answered it")
	}
}

// An answer with data for every dependency runs nothing locally.
func TestOfflineFallbackSkipsACompleteAnswer(t *testing.T) {
	answer := apiAnswer()
	answer.Dependencies = answer.Dependencies[:1]
	report := fillWithoutDataOffline(context.Background(), answer, func(context.Context, []string) (*api.ApplicationReachability, error) {
		t.Fatal("the offline path ran for a complete answer")
		return nil, nil
	})
	if report.ran || len(report.answered) != 0 || len(report.failed) != 0 {
		t.Fatalf("report = %+v, want empty", report)
	}
}

// A failed or timed-out offline path leaves the API's answer as it was and
// names every dependency it was asked for as failed, with why.
func TestOfflineFallbackFailureKeepsTheAPIAnswer(t *testing.T) {
	for name, cause := range map[string]error{
		"failure": errors.New("offline mining: cache unwritable"),
		"timeout": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			answer := apiAnswer()
			report := fillWithoutDataOffline(context.Background(), answer, func(context.Context, []string) (*api.ApplicationReachability, error) {
				return nil, cause
			})
			if !reflect.DeepEqual(answer, apiAnswer()) {
				t.Fatalf("answer changed after a failed fallback: %+v", answer)
			}
			if len(report.answered) != 0 || len(report.failed) != 2 {
				t.Fatalf("report = %+v, want b and c failed", report)
			}
			for _, key := range []string{fallbackKey(fallbackPurlB, "2.0"), fallbackKey(fallbackPurlC, "3.0")} {
				if report.failed[key] == "" {
					t.Fatalf("no failure recorded for %s: %+v", key, report.failed)
				}
			}
			if name == "timeout" && !strings.Contains(report.failed[fallbackKey(fallbackPurlB, "2.0")], "--timeout") {
				t.Fatalf("timeout failure does not name --timeout: %q", report.failed[fallbackKey(fallbackPurlB, "2.0")])
			}
		})
	}
}

// A fallback that mines until the deadline must stop short of the scan's own
// deadline: the scan still has to send the next plans' requests and write its
// report, so the scan's context is alive when the fallback gives up.
func TestOfflineFallbackLeavesTheScanTimeToFinish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	answer := apiAnswer()
	report := fillWithoutDataOffline(ctx, answer, func(fctx context.Context, _ []string) (*api.ApplicationReachability, error) {
		<-fctx.Done()
		return nil, fctx.Err()
	})
	if err := ctx.Err(); err != nil {
		t.Fatalf("the scan's context ended with the fallback: %v", err)
	}
	if len(report.failed) != 2 || !strings.Contains(report.failed[fallbackKey(fallbackPurlB, "2.0")], "--timeout") {
		t.Fatalf("report = %+v, want b and c failed on the deadline", report.failed)
	}
}

// Without the fallback (--no-offline-fallback) the online answer is the
// API's body as decoded, untouched; with it, the dependencies without data
// are filled in.
func TestOnlineReachabilityFallbackSwitch(t *testing.T) {
	body, err := json.Marshal(apiAnswer())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client := api.NewClientWithHTTPClient(server.URL, "key", server.Client(), api.WithAllowHTTP(true))
	request := &api.ApplicationReachabilityRequest{SchemaVersion: "1"}

	off, report, err := onlineReachability(context.Background(), client, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(off)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("answer without the fallback differs from the API's:\n got %s\nwant %s", got, body)
	}
	if report != nil {
		t.Fatalf("report without the fallback = %+v, want nil", report)
	}

	on, report, err := onlineReachability(context.Background(), client, request, func(context.Context, []string) (*api.ApplicationReachability, error) {
		return localAnswer(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if on.Dependencies[1].InfoCode != "READY" || report == nil || len(report.answered) != 1 {
		t.Fatalf("fallback did not fill b: %+v, report %+v", on.Dependencies[1], report)
	}
}

// The fallback mines the dependencies without data and every dependency
// that leads to one in the resolved tree, so a route from the project
// through an API-answered dependency into one mined locally is in the stitch.
func TestFallbackMineKeysAddsAncestors(t *testing.T) {
	// project -> a -> b -> c, project -> d
	req := pr.Request{
		SchemaVersion: pr.RequestSchemaVersion,
		CallSites:     &gf.GraphFragmentExport{SchemaVersion: pr.SchemaVersion},
		Dependencies: []pr.Dependency{
			{Purl: fallbackPurlA, Version: "1.0", Direct: true, Requires: []string{fallbackPurlB}},
			{Purl: fallbackPurlB, Version: "2.0", Requires: []string{fallbackPurlC}},
			{Purl: fallbackPurlC, Version: "3.0"},
			{Purl: "pkg:maven/org.example/d", Version: "4.0", Direct: true},
		},
	}
	plan, rejected := pr.NewPlan(req, pr.DefaultLimits)
	if rejected != nil {
		t.Fatalf("plan rejected: %+v", rejected)
	}
	got := fallbackMineKeys(plan, []string{fallbackPurlB})
	want := []pr.ComponentKey{{Purl: fallbackPurlA, Version: "1.0"}, {Purl: fallbackPurlB, Version: "2.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mine keys = %+v, want %+v", got, want)
	}
}

// The phase details say which dependencies the fallback answered and why
// it could not answer the others; the API-answered count is the rest.
func TestOfflineFallbackDetails(t *testing.T) {
	outcome := engine.ApplicationReachabilityOutcome{
		Dependencies: 3,
		DependenciesWithout: []engine.DependencyWithout{
			{Module: "org.example:c", Version: "3.0", PURL: fallbackPurlC, Reason: engine.DependencyWithoutReachabilityData, InfoCode: "NO_INFO"},
		},
	}
	report := &offlineFallbackReport{
		ran:      true,
		answered: []dependencyAnsweredOffline{{PURL: fallbackPurlB, Version: "2.0"}},
		failed:   map[string]string{fallbackKey(fallbackPurlC, "3.0"): "offline: boom"},
	}
	markOfflineFallbackFailures(&outcome, report)
	details := dependencyPhaseDetails("java", outcome)
	addOfflineFallbackDetails(details, report)

	if details["deps_answered_online"] != 1 || details["deps_answered_offline"] != 1 {
		t.Fatalf("answered online %v, offline %v; want 1 and 1", details["deps_answered_online"], details["deps_answered_offline"])
	}
	if got := details["deps_answered_offline_list"]; !reflect.DeepEqual(got, report.answered) {
		t.Fatalf("answered offline list = %+v", got)
	}
	without := details["deps_skipped_list"].([]engine.DependencyWithout)
	if without[0].OfflineFallback != "offline: boom" {
		t.Fatalf("c's fallback failure not reported: %+v", without[0])
	}

	merged := mergeDependencyPhaseDetails(details, func() map[string]any {
		d := dependencyPhaseDetails("python", engine.ApplicationReachabilityOutcome{Dependencies: 1})
		addOfflineFallbackDetails(d, &offlineFallbackReport{ran: true, answered: []dependencyAnsweredOffline{{PURL: "pkg:pypi/x", Version: "1"}}})
		return d
	}())
	if merged["deps_answered_offline"] != 2 || len(merged["deps_answered_offline_list"].([]dependencyAnsweredOffline)) != 2 {
		t.Fatalf("merged details = %+v", merged)
	}
}
