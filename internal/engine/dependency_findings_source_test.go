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

package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

type fakeFindingsSource struct {
	report *entities.InterimReport
	found  bool
	err    error
	calls  atomic.Int32
	purl   string
	ver    string
}

func (f *fakeFindingsSource) Findings(_ context.Context, purl, version string) (*entities.InterimReport, bool, error) {
	f.calls.Add(1)
	f.purl, f.ver = purl, version
	return f.report, f.found, f.err
}

func sourceReport(paths ...string) *entities.InterimReport {
	report := &entities.InterimReport{Version: "1.0"}
	for _, path := range paths {
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: path,
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 3, EndLine: 3, Match: "sha256.Sum256(b)",
				Rules:    []entities.RuleInfo{{ID: "go.crypto.sha256"}},
				Metadata: map[string]string{"assetType": "algorithm"},
			}},
		})
	}
	return report
}

// sourceScanner builds a dependency scanner whose detection counts its runs.
func sourceScanner(t *testing.T, cache FindingsCache, source DependencyFindingsSource) (*DependencyScanner, *atomic.Int32) {
	t.Helper()
	var scans atomic.Int32
	registry := scanner.NewRegistry()
	registry.Register("test-scanner", &mockScanner{scanFunc: func(_ context.Context, _ string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
		scans.Add(1)
		return &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{}}, nil
	}})
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{"/rules/go.yaml"}, nil }}), registry)
	ds := NewDependencyScanner(orch, &fakeResolver{ecosystem: "go"}, nil, cache, WithDependencyFindingsSource(source))
	return ds, &scans
}

func sourceScanOptions() DepScanOptions {
	return DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}}
}

func TestDependencyScanner_FindingsSourceAnswersCacheMiss(t *testing.T) {
	source := &fakeFindingsSource{report: sourceReport("a.go"), found: true}
	ds, scans := sourceScanner(t, &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}}, source)
	dep := dependency.Dependency{Module: "example.com/a", Version: "v1.0.0", Dir: t.TempDir()}

	res := ds.scanSingleDep(context.Background(), dep, "example.com/a@v1.0.0", []string{"/rules/go.yaml"}, sourceScanOptions())

	if res.err != nil || res.status != depScanStatusScanned {
		t.Fatalf("result = %v, %v", res.status, res.err)
	}
	if scans.Load() != 0 {
		t.Errorf("detection ran %d times for a dependency the source answered", scans.Load())
	}
	if source.purl != "pkg:golang/example.com/a" || source.ver != "v1.0.0" {
		t.Errorf("source asked for %q at %q", source.purl, source.ver)
	}
	if res.report == nil || !reflect.DeepEqual(res.report.Findings, source.report.Findings) {
		t.Errorf("report = %+v, want the source's findings", res.report)
	}
}

func TestDependencyScanner_FindingsSourceMissOrErrorScansLive(t *testing.T) {
	for name, source := range map[string]*fakeFindingsSource{
		"miss":  {},
		"error": {err: errors.New("api unavailable")},
	} {
		t.Run(name, func(t *testing.T) {
			ds, scans := sourceScanner(t, &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}}, source)
			dep := dependency.Dependency{Module: "example.com/a", Version: "v1.0.0", Dir: t.TempDir()}

			res := ds.scanSingleDep(context.Background(), dep, "example.com/a@v1.0.0", []string{"/rules/go.yaml"}, sourceScanOptions())

			if res.err != nil || source.calls.Load() != 1 || scans.Load() != 1 {
				t.Errorf("err %v, source calls %d, scans %d; want one source call then one live scan", res.err, source.calls.Load(), scans.Load())
			}
		})
	}
}

func TestDependencyScanner_FindingsSourceRunsWithoutLocalCache(t *testing.T) {
	source := &fakeFindingsSource{report: sourceReport("a.go"), found: true}
	ds, scans := sourceScanner(t, nil, source)
	dep := dependency.Dependency{Module: "example.com/a", Version: "v1.0.0", Dir: t.TempDir()}

	res := ds.scanSingleDep(context.Background(), dep, "example.com/a@v1.0.0", []string{"/rules/go.yaml"}, sourceScanOptions())

	if res.err != nil || scans.Load() != 0 || source.calls.Load() != 1 {
		t.Errorf("err %v, scans %d, source calls %d; the source must answer with no local cache", res.err, scans.Load(), source.calls.Load())
	}
}

func TestDependencyScanner_LocalCacheHitSkipsFindingsSource(t *testing.T) {
	source := &fakeFindingsSource{}
	cache := &storingFindingsCache{entries: map[string]*entities.InterimReport{}}
	ds, scans := sourceScanner(t, cache, source)
	dep := dependency.Dependency{Module: "example.com/a", Version: "v1.0.0", Dir: t.TempDir()}

	for range 2 {
		if res := ds.scanSingleDep(context.Background(), dep, "example.com/a@v1.0.0", []string{"/rules/go.yaml"}, sourceScanOptions()); res.err != nil {
			t.Fatal(res.err)
		}
	}

	if source.calls.Load() != 1 || scans.Load() != 1 {
		t.Errorf("source calls %d, scans %d; the second scan must be a local cache hit", source.calls.Load(), scans.Load())
	}
}

func TestDependencyScanner_FindingsSourceKeepsDependencyFiles(t *testing.T) {
	dir := t.TempDir()
	source := &fakeFindingsSource{report: sourceReport("a.go", "other/b.go"), found: true}
	ds, _ := sourceScanner(t, nil, source)
	dep := dependency.Dependency{Module: "example.com/a", Version: "v1.0.0", Dir: dir, Files: []string{filepath.Join(dir, "a.go")}}

	res := ds.scanSingleDep(context.Background(), dep, "example.com/a@v1.0.0", []string{"/rules/go.yaml"}, sourceScanOptions())

	if res.report == nil || len(res.report.Findings) != 1 || res.report.Findings[0].FilePath != "a.go" {
		t.Errorf("report = %+v, want only the dependency's own file", res.report)
	}
}

type fakeComponentAPI struct {
	answer *apiclient.ComponentFindings
	found  bool
	err    error
	calls  int
}

func (f *fakeComponentAPI) ComponentFindings(context.Context, string, string) (*apiclient.ComponentFindings, bool, error) {
	f.calls++
	return f.answer, f.found, f.err
}

func TestAPIFindingsSource_ReturnsPublishedFindings(t *testing.T) {
	findings := sourceReport("a.go").Findings
	api := &fakeComponentAPI{answer: &apiclient.ComponentFindings{Version: "1.2.3", RulesVersion: "r7", Findings: findings}, found: true}

	report, found, err := NewAPIFindingsSource(api).Findings(context.Background(), "pkg:maven/a/b", "1.2.4")

	if err != nil || !found {
		t.Fatalf("found %v, err %v", found, err)
	}
	if !reflect.DeepEqual(report.Findings, findings) || report.Rules.Version != "r7" {
		t.Errorf("report = %+v", report)
	}
}

func TestAPIFindingsSource_AccessDeniedStopsAsking(t *testing.T) {
	for _, denied := range []error{apiclient.ErrUnauthorized, apiclient.ErrForbidden} {
		api := &fakeComponentAPI{err: fmt.Errorf("%w: not permitted", denied)}
		source := NewAPIFindingsSource(api)

		for range 3 {
			if _, found, err := source.Findings(context.Background(), "pkg:maven/a/b", "1.0"); found || err != nil {
				t.Errorf("%v: found %v, err %v; access denied must read as no findings", denied, found, err)
			}
		}
		if api.calls != 1 {
			t.Errorf("%v: API asked %d times, want once", denied, api.calls)
		}
	}
}

func TestAPIFindingsSource_OtherErrorsKeepAsking(t *testing.T) {
	api := &fakeComponentAPI{err: apiclient.ErrServerError}
	source := NewAPIFindingsSource(api)

	for range 2 {
		if _, found, err := source.Findings(context.Background(), "pkg:maven/a/b", "1.0"); found || !errors.Is(err, apiclient.ErrServerError) {
			t.Errorf("found %v, err %v", found, err)
		}
	}
	if api.calls != 2 {
		t.Errorf("API asked %d times, want 2", api.calls)
	}
}

// A Go dependency's detection is scoped to its imported files, but the
// source publishes findings for the whole package.
func TestDependencyScanner_FindingsSourceKeepsDependencyFilesUnderScopedDetection(t *testing.T) {
	dir := t.TempDir()
	registry := scanner.NewRegistry()
	registry.Register("test-scanner", &scopedMockScanner{})
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{"/rules/go.yaml"}, nil }}), registry)
	source := &fakeFindingsSource{report: sourceReport("a.go", "other/b.go"), found: true}
	ds := NewDependencyScanner(orch, &fakeResolver{ecosystem: "go"}, nil, nil, WithDependencyFindingsSource(source))
	dep := dependency.Dependency{Module: "example.com/a", Version: "v1.0.0", Dir: dir, Files: []string{filepath.Join(dir, "a.go")}}

	res := ds.scanSingleDep(context.Background(), dep, "example.com/a@v1.0.0", []string{"/rules/go.yaml"}, sourceScanOptions())

	if res.report == nil || len(res.report.Findings) != 1 || res.report.Findings[0].FilePath != "a.go" {
		t.Errorf("report = %+v, want only the dependency's own file", res.report)
	}
}
