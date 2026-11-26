// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/perf"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/utils"
	pr "github.com/scanoss/crypto-finder/pkg/appreach"
)

// The offline fallback: an online dependency scan answers locally, with the
// offline path (scan_offline.go), the dependencies the SCANOSS API holds no
// reachability data for, and serves those answers as if the API had given
// them. The local answer comes from one stitch over the whole request, in
// which the dependencies without data and every dependency that leads to
// one in the resolved tree are mined; the others are served without a graph
// and spliced out, as the API splices a dependency it has no data for. Only
// the dependencies without data take the local answer: the API's answer
// stands for every other.

var scanNoOfflineFallback bool

func init() {
	scanCmd.Flags().BoolVar(&scanNoOfflineFallback, "no-offline-fallback", false,
		"With --scan-dependencies (online): do not mine locally the dependencies the SCANOSS API holds no reachability data for; their findings are left out, as the API answered")
}

// offlineAnswerer answers locally the request's dependencies pinned under
// purls, as offlineReachability does.
type offlineAnswerer func(ctx context.Context, purls []string) (*api.ApplicationReachability, error)

// dependencyAnsweredOffline names a dependency the offline fallback
// answered, in the dependencies phase details.
type dependencyAnsweredOffline struct {
	PURL    string `json:"purl"`
	Version string `json:"version"`
}

// offlineFallbackReport is what the fallback did: whether it ran, the
// dependencies it answered, and why it could not answer the others, keyed by
// fallbackKey.
type offlineFallbackReport struct {
	ran      bool
	answered []dependencyAnsweredOffline
	failed   map[string]string
}

// fallbackKey keys a dependency by its canonical versionless purl and its
// version, so the API's answer and the local one meet on the same key.
func fallbackKey(purl, version string) string {
	if p, err := pr.ParsePurl(purl); err == nil {
		p.Version = ""
		purl = p.String()
	}
	return purl + "@" + version
}

// onlineReachability asks the API for the request's reachability and, when
// local is set, answers locally the dependencies it holds no data for. With
// local nil the answer is the API's, untouched, and the report nil.
func onlineReachability(ctx context.Context, client *api.Client, request *api.ApplicationReachabilityRequest, local offlineAnswerer) (*api.ApplicationReachability, *offlineFallbackReport, error) {
	requestSpan := perf.Start("dependencies.reachability_request")
	answer, err := client.ApplicationReachability(ctx, request)
	requestSpan.End()
	if err != nil {
		return nil, nil, failure.WrapUnknown(err, failure.CodeDependencyResolutionFailed, failure.StageDependency, "application reachability request failed")
	}
	if local == nil {
		return answer, nil, nil
	}
	return answer, fillWithoutDataOffline(ctx, answer, local), nil
}

// fillWithoutDataOffline answers with local the dependencies answer holds
// without data and puts each local answer that has data in place of the
// API's. A dependency the local path cannot answer either keeps the API's
// answer, and the report says why; a failed local path fails no scan.
func fillWithoutDataOffline(ctx context.Context, answer *api.ApplicationReachability, local offlineAnswerer) *offlineFallbackReport {
	report := &offlineFallbackReport{failed: map[string]string{}}
	var purls []string
	without := map[string]int{}
	for i, dep := range answer.Dependencies {
		if dep.InfoCode == "READY" {
			continue
		}
		purls = append(purls, dep.Purl)
		without[fallbackKey(dep.Purl, dep.Version)] = i
	}
	if len(purls) == 0 {
		return report
	}
	report.ran = true
	log.Info().Int("dependencies", len(purls)).Msg("The SCANOSS API holds no reachability data for some dependencies; answering them offline")
	span := perf.Start("dependencies.offline_fallback")
	localAnswer, err := local(ctx, purls)
	span.End()
	if err != nil {
		why := fmt.Sprintf("offline fallback failed: %v", err)
		if errors.Is(err, context.DeadlineExceeded) {
			why = fmt.Sprintf("offline fallback stopped: the scan's --timeout (%s) ran out while mining: %v", scanTimeout, err)
		}
		for key := range without {
			report.failed[key] = why
		}
	} else {
		report.answered = takeLocalAnswers(answer, localAnswer, without, report.failed)
	}
	for _, dep := range answer.Dependencies {
		if why, ok := report.failed[fallbackKey(dep.Purl, dep.Version)]; ok {
			log.Warn().Str("dependency", dep.Purl+"@"+dep.Version).Str("reason", why).Msg("Offline fallback: the dependency stays without reachability data")
		}
	}
	return report
}

// takeLocalAnswers puts in answer, in place of the API's, each local answer
// with data for a dependency of without (keyed by fallbackKey, valued by its
// index in answer), and returns those dependencies. Each other dependency of
// without goes into failed, with the local answer's message.
func takeLocalAnswers(answer, localAnswer *api.ApplicationReachability, without map[string]int, failed map[string]string) []dependencyAnsweredOffline {
	answered := make([]dependencyAnsweredOffline, 0, len(without))
	for key := range without {
		failed[key] = "offline fallback: no local data for this dependency"
	}
	for _, dep := range localAnswer.Dependencies {
		key := fallbackKey(dep.Purl, dep.Version)
		i, ok := without[key]
		switch {
		case !ok:
			continue
		case dep.InfoCode != "READY":
			if dep.InfoMessage != "" {
				failed[key] = dep.InfoMessage
			}
			continue
		}
		delete(failed, key)
		apiDep := answer.Dependencies[i]
		dep.Purl, dep.Direct = apiDep.Purl, apiDep.Direct
		answer.Dependencies[i] = dep
		answered = append(answered, dependencyAnsweredOffline{PURL: dep.Purl, Version: dep.Version})
	}
	return answered
}

// fallbackMineKeys are the plan's dependencies the fallback mines, in plan
// order: those pinned under purls and every dependency that leads to one of
// them in the request's dependency edges. A route from the project into a
// dependency without data through one the API answered then runs through a
// mined graph.
func fallbackMineKeys(plan *pr.Plan, purls []string) []pr.ComponentKey {
	edges, _ := plan.RequestEdges()
	parents := map[pr.ComponentKey][]pr.ComponentKey{}
	for parent, children := range edges {
		for _, child := range children {
			parents[child] = append(parents[child], parent)
		}
	}
	mine := map[pr.ComponentKey]bool{}
	var stack []pr.ComponentKey
	for _, purl := range purls {
		if key, ok := plan.Pins.Key(purl); ok && !mine[key] {
			mine[key] = true
			stack = append(stack, key)
		}
	}
	for len(stack) > 0 {
		key := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, parent := range parents[key] {
			if !mine[parent] {
				mine[parent] = true
				stack = append(stack, parent)
			}
		}
	}
	return slices.DeleteFunc(slices.Clone(plan.Keys), func(k pr.ComponentKey) bool { return !mine[k] })
}

// markOfflineFallbackFailures names, on each dependency without data, why
// the offline fallback could not answer it either.
func markOfflineFallbackFailures(outcome *engine.ApplicationReachabilityOutcome, report *offlineFallbackReport) {
	if report == nil {
		return
	}
	for i := range outcome.DependenciesWithout {
		w := &outcome.DependenciesWithout[i]
		if w.Reason != engine.DependencyWithoutReachabilityData {
			continue
		}
		if why, ok := report.failed[fallbackKey(w.PURL, w.Version)]; ok {
			w.OfflineFallback = why
		}
	}
}

// addOfflineFallbackDetails adds to the dependencies phase details which
// dependencies the API answered and which the offline fallback did. The
// keys are added whenever the fallback is on, so a consumer reads them on
// every online scan that allows it.
func addOfflineFallbackDetails(details map[string]any, report *offlineFallbackReport) {
	if report == nil {
		return
	}
	answered := report.answered
	if answered == nil {
		answered = []dependencyAnsweredOffline{}
	}
	scanned := utils.AsOr[int](details["deps_scanned"])
	details["deps_answered_online"] = scanned - len(answered)
	details["deps_answered_offline"] = len(answered)
	details["deps_answered_offline_list"] = answered
}

// newOnlineClient is the API client of the one application reachability
// request.
func newOnlineClient(url, key string, allowHTTP bool) *api.Client {
	return api.NewClientWithHTTPClient(url, key, &http.Client{Timeout: applicationReachabilityTimeout}, api.WithAllowHTTP(allowHTTP))
}
