// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	gf "github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/pkg/conditioned"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite pkg/appreach/testdata/golden")

// goldenCase is one project request over the commons-codec fixture whose
// whole response is pinned byte for byte, so moving the stitch core cannot
// change what the API and the offline client serve.
type goldenCase struct {
	name     string
	req      func(t *testing.T) Request
	loaded   func(t *testing.T) map[ComponentKey]Component
	recorded map[ComponentKey][]string
}

var goldenMissing = ComponentKey{Purl: "pkg:maven/com.example/not-mined", Version: "1.0"}

func goldenRequest(chains bool, maxChains int, deps ...Dependency) func(t *testing.T) Request {
	return func(t *testing.T) Request {
		return Request{SchemaVersion: RequestSchemaVersion, Dependencies: deps, CallSites: codecCallSites(t), IncludeCallChains: chains, MaxChainsPerFinding: maxChains}
	}
}

func goldenLoaded(withReport bool) func(t *testing.T) map[ComponentKey]Component {
	return func(t *testing.T) map[ComponentKey]Component {
		return map[ComponentKey]Component{
			codecKey:      codecComponent(t, withReport),
			goldenMissing: {Code: InfoNoInfo, Message: "not mined"},
		}
	}
}

func goldenCases() []goldenCase {
	codecDirect := Dependency{Purl: codecKey.Purl, Version: codecKey.Version, Direct: true}
	codecIndirect := Dependency{Purl: codecKey.Purl, Version: codecKey.Version}
	missingDirect := Dependency{Purl: goldenMissing.Purl, Version: goldenMissing.Version, Direct: true}
	missing := Dependency{Purl: goldenMissing.Purl, Version: goldenMissing.Version}
	return []goldenCase{
		{name: "verdicts", req: goldenRequest(false, 0, codecDirect, missing), loaded: goldenLoaded(true)},
		{name: "chains-all", req: goldenRequest(true, 0, codecDirect, missing), loaded: goldenLoaded(true)},
		{name: "chains-two", req: goldenRequest(true, 2, codecDirect, missing), loaded: goldenLoaded(true)},
		{name: "annotation-only", req: goldenRequest(true, 1, codecDirect, missing), loaded: goldenLoaded(false)},
		{
			// commons-codec hangs only from a dependency without a graph.
			name:     "via-missing-graph",
			req:      goldenRequest(false, 0, missingDirect, codecIndirect),
			loaded:   goldenLoaded(true),
			recorded: map[ComponentKey][]string{goldenMissing: {codecKey.Purl}},
		},
		{
			name: "conditioned",
			req: func(t *testing.T) Request {
				req := goldenRequest(true, 1, codecDirect)(t)
				req.ConditionedRules = []conditioned.Rule{{
					ID: "invented-mac", Symbols: []string{"javax.crypto.Mac.getInstance"},
					Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "$alg", "parameterCondition": `param[0]~=^(?P<alg>Hmac.*)$`},
				}}
				return req
			},
			loaded: goldenLoaded(true),
		},
	}
}

func TestRunGolden(t *testing.T) {
	for _, c := range goldenCases() {
		t.Run(c.name, func(t *testing.T) {
			plan, rejected := NewPlan(c.req(t), DefaultLimits)
			if rejected != nil {
				t.Fatalf("rejected: %s", rejected.InfoMessage)
			}
			edges, fromRequest := plan.RequestEdges()
			if !fromRequest {
				edges = plan.EdgesFrom(c.recorded)
			}
			resp, stats, err := plan.Run(context.Background(), c.loaded(t), edges, RunOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(struct {
				Response         Response `json:"response"`
				WithGraph        int      `json:"with_graph"`
				ConditionedAdded int      `json:"conditioned_added"`
			}{resp, stats.WithGraph, stats.ConditionedAdded}, "", " ")
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, c.name, got)
		})
	}
}

// TestNewPlanRejectionsGolden pins every rejection envelope.
func TestNewPlanRejectionsGolden(t *testing.T) {
	sites := codecCallSites(t)
	dep := Dependency{Purl: "pkg:maven/g/a", Version: "1", Direct: true}
	reqs := []Request{
		{SchemaVersion: "2", Dependencies: []Dependency{dep}, CallSites: sites},
		{SchemaVersion: "1", CallSites: sites},
		{SchemaVersion: "1", Dependencies: []Dependency{{Purl: "pkg:maven/a", Version: "1", Direct: true}}, CallSites: sites},
		{SchemaVersion: "1", Dependencies: []Dependency{{Purl: "pkg:maven/g/a", Direct: true}}, CallSites: sites},
		{SchemaVersion: "1", Dependencies: []Dependency{dep, {Purl: "pkg:maven/g/a@2"}}, CallSites: sites},
		{SchemaVersion: "1", Dependencies: []Dependency{{Purl: "pkg:pypi/a", Version: "1.0"}, {Purl: "pkg:pypi/A", Version: "1.0.0", Direct: true}, {Purl: "pkg:pypi/a", Version: "1.1"}}, CallSites: sites},
		{SchemaVersion: "1", Dependencies: []Dependency{{Purl: "pkg:maven/g/a", Version: "1"}}, CallSites: sites},
		{SchemaVersion: "1", Dependencies: []Dependency{dep}},
		{SchemaVersion: "1", Dependencies: []Dependency{dep}, CallSites: &gf.GraphFragmentExport{SchemaVersion: "graph-fragment-99.0"}},
		{SchemaVersion: "1", Dependencies: []Dependency{dep}, CallSites: sites, MaxChainsPerFinding: MaxChainsHigh + 1},
		{SchemaVersion: "1", Dependencies: []Dependency{dep}, CallSites: sites, MaxChainsPerFinding: -1},
		{SchemaVersion: "1", Dependencies: []Dependency{dep}, CallSites: sites, ConditionedRules: []conditioned.Rule{{ID: "bad", Metadata: map[string]string{"parameterCondition": "param[0]=="}}}},
	}
	out := make([]*Response, 0, len(reqs)+2)
	for _, req := range reqs {
		_, rejected := NewPlan(req, DefaultLimits)
		out = append(out, rejected)
	}
	_, rejected := NewPlan(Request{SchemaVersion: "1", Dependencies: []Dependency{dep, {Purl: "pkg:maven/g/b", Version: "1"}}, CallSites: sites}, Limits{MaxDependencies: 1, MaxCallSites: 1})
	out = append(out, rejected)
	_, rejected = NewPlan(Request{SchemaVersion: "1", Dependencies: []Dependency{dep}, CallSites: sites}, Limits{MaxDependencies: 1, MaxCallSites: 1})
	out = append(out, rejected)
	got, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "rejections", got)
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".json.gz")
	if *updateGolden {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if _, err := zw.Write(got); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := readGzipFixture(t, filepath.Join("golden", name+".json.gz"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: response differs from testdata/golden/%s.json.gz (run with -update-golden only for an intended change)", name, name)
	}
}
