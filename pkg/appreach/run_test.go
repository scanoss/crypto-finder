// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	gf "github.com/scanoss/reach/graphfrag"
)

// The fixture is real miner data, the same the API's endpoint tests
// read: commons-codec 1.17.0 as the cards miner stored it (structural graph,
// crypto annotation, findings report) and the call sites
// client-encryption-java 1.8.7 makes into it.
var codecKey = ComponentKey{Purl: "pkg:maven/commons-codec/commons-codec", Version: "1.17.0"}

// codecReachable are the commons-codec findings the project reaches, by their
// stored finding ids (verified against the labeled benchmark case and its
// neighbors).
var codecReachable = []string{
	"12c58084", "40019d42", "41049e89", "42337331", "5b42943f", "65df9163",
	"7e16fea9", "7f5f8c1a", "84f415ad", "9692402e", "cbdb495d", "fe6e4412",
}

func readGzipFixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// codecComponent loads commons-codec as a caller does: the structural graph,
// the annotation's crypto sections and, when withReport, the findings report.
func codecComponent(t *testing.T, withReport bool) Component {
	t.Helper()
	frag, err := DecodeProducerGraph(codecKey, readGzipFixture(t, "commons-codec-1.17.0.graph.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	var ann struct {
		CryptoOperations  []gf.CryptoOperation  `json:"crypto_operations"`
		SupportingCalls   []gf.SupportingCall   `json:"supporting_calls"`
		CryptoEntryPoints []gf.CryptoEntryPoint `json:"crypto_entry_points"`
	}
	if err := json.Unmarshal(readGzipFixture(t, "commons-codec-1.17.0.annotation.json.gz"), &ann); err != nil {
		t.Fatal(err)
	}
	frag.CryptoOperations, frag.SupportingCalls, frag.CryptoEntryPoints, frag.RulesVersion = ann.CryptoOperations, ann.SupportingCalls, ann.CryptoEntryPoints, "rules-b"
	comp := Component{Fragment: frag}
	if withReport {
		stored, err := DecodeStoredReport(readGzipFixture(t, "commons-codec-1.17.0.findings.json.gz"), "")
		if err != nil {
			t.Fatal(err)
		}
		comp.Stored = &stored
	}
	return comp
}

func codecCallSites(t *testing.T) *gf.GraphFragmentExport {
	t.Helper()
	var doc gf.GraphFragmentExport
	if err := json.Unmarshal(readGzipFixture(t, "client-encryption-java.call-sites.json.gz"), &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

func verdictsWith(d *DependencyDTO, want string) []string {
	var out []string
	for id, v := range verdictsByID(d) {
		if v == want {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func TestRunOnMinedData(t *testing.T) {
	missing := ComponentKey{Purl: "pkg:maven/com.example/not-mined", Version: "1.0"}
	plan, rejected := NewPlan(Request{
		SchemaVersion: RequestSchemaVersion,
		Dependencies: []Dependency{
			{Purl: codecKey.Purl, Version: codecKey.Version, Direct: true},
			{Purl: missing.Purl, Version: missing.Version},
		},
		CallSites: codecCallSites(t),
	}, DefaultLimits)
	if rejected != nil {
		t.Fatalf("rejected: %s", rejected.InfoMessage)
	}
	loaded := map[ComponentKey]Component{
		codecKey: codecComponent(t, true),
		missing:  {Code: InfoNoInfo, Message: "not mined"},
	}
	stitched := false
	resp, stats, err := plan.Run(context.Background(), loaded, nil, RunOptions{AfterStitch: func() { stitched = true }})
	if err != nil {
		t.Fatal(err)
	}
	if !stitched || stats.WithGraph != 1 {
		t.Errorf("AfterStitch ran %v, %d components with a graph, want true and 1", stitched, stats.WithGraph)
	}
	if resp.InfoCode != InfoReady || resp.RulesVersion != "rules-b" || resp.InfoMessage != "1 of 2 dependencies have reachability data" {
		t.Fatalf("envelope %s %q rules %q", resp.InfoCode, resp.InfoMessage, resp.RulesVersion)
	}
	if want := (Summary{Reachable: 12, Unreachable: 60}); resp.Summary != want {
		t.Errorf("summary %+v, want %+v", resp.Summary, want)
	}
	codec, gone := resp.Dependencies[0], resp.Dependencies[1]
	if got := verdictsWith(codec, "reachable:"); !reflect.DeepEqual(got, codecReachable) {
		t.Errorf("reachable findings %v, want %v", got, codecReachable)
	}
	if codec.FindingCount != 72 || !codec.Direct {
		t.Errorf("commons-codec block findings=%d direct=%v", codec.FindingCount, codec.Direct)
	}
	for _, f := range codec.Findings {
		if !strings.HasPrefix(f.FilePath, "commons-codec:commons-codec@1.17.0/") {
			t.Errorf("finding file %q: want the dependency's prefixed path", f.FilePath)
		}
	}
	if gone.InfoCode != InfoNoInfo || gone.InfoMessage != "not mined" || len(gone.Findings) != 0 {
		t.Errorf("unmined block %+v", gone)
	}
}

// A canceled context fails the run at the stitch, with the context's error.
func TestRunCancelled(t *testing.T) {
	plan, _ := NewPlan(Request{
		SchemaVersion: RequestSchemaVersion,
		Dependencies:  []Dependency{{Purl: codecKey.Purl, Version: codecKey.Version, Direct: true}},
		CallSites:     codecCallSites(t),
	}, DefaultLimits)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := plan.Run(ctx, map[ComponentKey]Component{codecKey: codecComponent(t, true)}, nil, RunOptions{})
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Stage != "stitch" || !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want a stitch RunError wrapping context.Canceled", err)
	}
}

func TestNewPlanRejects(t *testing.T) {
	sites := &gf.GraphFragmentExport{SchemaVersion: SchemaVersion}
	dep := Dependency{Purl: "pkg:maven/g/a", Version: "1", Direct: true}
	cases := map[string]struct {
		req  Request
		code InfoCode
		msg  string
	}{
		"schema":       {Request{SchemaVersion: "2", Dependencies: []Dependency{dep}, CallSites: sites}, InfoInvalidRequest, "schema_version"},
		"empty":        {Request{SchemaVersion: "1", CallSites: sites}, InfoInvalidRequest, "must not be empty"},
		"bad purl":     {Request{SchemaVersion: "1", Dependencies: []Dependency{{Purl: "pkg:maven/a", Version: "1", Direct: true}}, CallSites: sites}, InfoInvalidRequest, "invalid purl"},
		"no version":   {Request{SchemaVersion: "1", Dependencies: []Dependency{{Purl: "pkg:maven/g/a", Direct: true}}, CallSites: sites}, InfoInvalidRequest, "version is required"},
		"conflict":     {Request{SchemaVersion: "1", Dependencies: []Dependency{dep, {Purl: "pkg:maven/g/a@2"}}, CallSites: sites}, InfoInvalidRequest, "conflicting versions"},
		"no direct":    {Request{SchemaVersion: "1", Dependencies: []Dependency{{Purl: "pkg:maven/g/a", Version: "1"}}, CallSites: sites}, InfoInvalidRequest, "at least one must be direct"},
		"no sites":     {Request{SchemaVersion: "1", Dependencies: []Dependency{dep}}, InfoInvalidRequest, "call_sites: required"},
		"sites schema": {Request{SchemaVersion: "1", Dependencies: []Dependency{dep}, CallSites: &gf.GraphFragmentExport{SchemaVersion: "graph-fragment-99.0"}}, InfoUnsupportedSchema, "call_sites"},
		"chains":       {Request{SchemaVersion: "1", Dependencies: []Dependency{dep}, CallSites: sites, MaxChainsPerFinding: MaxChainsHigh + 1}, InfoInvalidRequest, "max_chains_per_finding"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			plan, rejected := NewPlan(c.req, DefaultLimits)
			if plan != nil || rejected == nil || rejected.InfoCode != c.code || !strings.Contains(rejected.InfoMessage, c.msg) {
				t.Fatalf("plan %v rejected %+v, want %s containing %q", plan, rejected, c.code, c.msg)
			}
		})
	}
	tooMany := Request{SchemaVersion: "1", Dependencies: []Dependency{dep, {Purl: "pkg:maven/g/b", Version: "1"}}, CallSites: sites}
	if _, rejected := NewPlan(tooMany, Limits{MaxDependencies: 1, MaxCallSites: 1}); rejected == nil || !strings.Contains(rejected.InfoMessage, "at most 1") {
		t.Fatalf("over the dependency limit: %+v", rejected)
	}
}

// The request's requires edges win; without them the caller's recorded edges
// are kept only between pinned components, whatever version they name.
func TestPlanEdges(t *testing.T) {
	a, b, c := ComponentKey{Purl: "pkg:maven/g/a", Version: "1"}, ComponentKey{Purl: "pkg:maven/g/b", Version: "2"}, ComponentKey{Purl: "pkg:maven/g/c", Version: "3"}
	req := Request{SchemaVersion: "1", CallSites: &gf.GraphFragmentExport{SchemaVersion: SchemaVersion}, Dependencies: []Dependency{
		{Purl: a.Purl, Version: a.Version, Direct: true, Requires: []string{b.Purl, "pkg:maven/g/unpinned", a.Purl}},
		{Purl: b.Purl, Version: b.Version},
		{Purl: c.Purl, Version: c.Version},
	}}
	plan, rejected := NewPlan(req, DefaultLimits)
	if rejected != nil {
		t.Fatal(rejected.InfoMessage)
	}
	edges, fromRequest := plan.RequestEdges()
	if !fromRequest || !reflect.DeepEqual(edges, map[ComponentKey][]ComponentKey{a: {b}}) {
		t.Errorf("request edges %v (%v), want a -> b", edges, fromRequest)
	}
	got := plan.EdgesFrom(map[ComponentKey][]string{b: {"pkg:maven/g/c@9", "pkg:maven/g/x", b.Purl}})
	if !reflect.DeepEqual(got, map[ComponentKey][]ComponentKey{b: {c}}) {
		t.Errorf("recorded edges %v, want b -> c", got)
	}
	req.Dependencies[0].Requires = nil
	plan, _ = NewPlan(req, DefaultLimits)
	if _, fromRequest := plan.RequestEdges(); fromRequest {
		t.Error("no requires: edges must come from the caller")
	}
}
