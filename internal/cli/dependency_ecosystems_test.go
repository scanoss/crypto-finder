// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/xeipuuv/gojsonschema"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/language"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/skip"
)

// ambientPythonResolver stands in for PipResolver on a host with python3 on
// PATH: it reads no manifest and can always resolve.
type ambientPythonResolver struct{}

func (ambientPythonResolver) Resolve(context.Context, string) (*dependency.ResolveResult, error) {
	return &dependency.ResolveResult{}, nil
}
func (ambientPythonResolver) Ecosystem() string      { return ecosystemPython }
func (ambientPythonResolver) CanResolve(string) bool { return true }

func testDependencyRegistry() *dependency.Registry {
	registry := dependency.NewRegistry()
	registry.Register("go", dependency.NewGoResolver())
	registry.Register(ecosystemJava, dependency.NewJavaResolver())
	registry.Register(ecosystemPython, ambientPythonResolver{})
	registry.Register("rust", dependency.NewCargoResolver())
	registry.Register(ecosystemNode, dependency.NewNpmResolver())
	return registry
}

// writeSources writes n files named <prefix><i><ext> holding body.
func writeSources(t *testing.T, dir, prefix, ext, body string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		writeFile(t, filepath.Join(dir, prefix+strconv.Itoa(i)+ext), body)
	}
}

func detectedHints(t *testing.T, dir string) []string {
	t.Helper()
	hints, err := language.NewEnryDetector(skip.NewGitIgnoreMatcher(nil)).Detect(dir)
	if err != nil {
		t.Fatalf("detect languages: %v", err)
	}
	return hints
}

func TestPlanAutoDependencyEcosystems(t *testing.T) {
	const pyBody = "import flask\n\ndef handler():\n    return 'ok'\n"
	const jsBody = "function onClick() {\n  return document.title;\n}\n"
	const lockfile = `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"}}}`

	cases := []struct {
		name          string
		setup         func(t *testing.T, dir string)
		wantPrimary   string
		wantFallback  string
		wantResolved  []string
		wantSkipped   []dependencyEcosystemSkip
		wantHintFirst string
	}{
		{
			// The reported Flask application: browser JavaScript outnumbers
			// the Python, and only Python has a manifest.
			name: "requirements.txt with more JavaScript than Python and no package.json",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
				writeSources(t, dir, "app", ".py", pyBody, 11)
				writeSources(t, filepath.Join(dir, "static"), "ui", ".js", jsBody, 16)
			},
			wantHintFirst: "javascript",
			wantPrimary:   ecosystemPython,
			wantFallback:  ecosystemNode,
			wantResolved:  []string{ecosystemPython},
			wantSkipped:   []dependencyEcosystemSkip{{Ecosystem: ecosystemNode, Reason: dependency.SkipReasonManifestAbsent}},
		},
		{
			// A tie orders the hints alphabetically, so JavaScript leads.
			name: "as many JavaScript as Python files with requirements.txt",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
				writeSources(t, dir, "app", ".py", pyBody, 5)
				writeSources(t, dir, "ui", ".js", jsBody, 5)
			},
			wantHintFirst: "javascript",
			wantPrimary:   ecosystemPython,
			wantFallback:  ecosystemNode,
			wantResolved:  []string{ecosystemPython},
			wantSkipped:   []dependencyEcosystemSkip{{Ecosystem: ecosystemNode, Reason: dependency.SkipReasonManifestAbsent}},
		},
		{
			name: "package.json without a lockfile beside requirements.txt",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
				writeFile(t, filepath.Join(dir, "package.json"), `{"name":"app"}`)
				writeSources(t, dir, "app", ".py", pyBody, 2)
				writeSources(t, dir, "ui", ".js", jsBody, 6)
			},
			wantHintFirst: "javascript",
			wantPrimary:   ecosystemPython,
			wantFallback:  ecosystemNode,
			wantResolved:  []string{ecosystemPython},
			wantSkipped:   []dependencyEcosystemSkip{{Ecosystem: ecosystemNode, Reason: dependency.SkipReasonLockfileAbsent}},
		},
		{
			name: "package.json and lockfile beside requirements.txt resolve both, dominant first",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
				writeFile(t, filepath.Join(dir, "package.json"), `{"name":"app"}`)
				writeFile(t, filepath.Join(dir, "package-lock.json"), lockfile)
				writeSources(t, dir, "app", ".py", pyBody, 2)
				writeSources(t, dir, "ui", ".js", jsBody, 6)
			},
			wantHintFirst: "javascript",
			wantPrimary:   ecosystemNode,
			wantFallback:  ecosystemNode,
			wantResolved:  []string{ecosystemNode, ecosystemPython},
		},
		{
			// Python reads an interpreter, not a manifest, so a lone script
			// in a Node package without a lockfile does not pull in the
			// interpreter's packages.
			name: "Python script without a Python manifest is not resolved beside another ecosystem",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "package.json"), `{"name":"app"}`)
				writeSources(t, dir, "tool", ".py", pyBody, 1)
				writeSources(t, dir, "ui", ".js", jsBody, 4)
			},
			wantHintFirst: "javascript",
			wantPrimary:   ecosystemNode,
			wantFallback:  ecosystemNode,
			wantSkipped: []dependencyEcosystemSkip{
				{Ecosystem: ecosystemNode, Reason: dependency.SkipReasonLockfileAbsent},
				{Ecosystem: ecosystemPython, Reason: dependency.SkipReasonManifestAbsent},
			},
		},
		{
			// Nothing qualifies: the dominant language stays the pick, so the
			// phase skips exactly as it did.
			name: "JavaScript only without a manifest keeps the previous pick",
			setup: func(t *testing.T, dir string) {
				writeSources(t, dir, "ui", ".js", jsBody, 3)
			},
			wantHintFirst: "javascript",
			wantPrimary:   ecosystemNode,
			wantFallback:  ecosystemNode,
			wantSkipped:   []dependencyEcosystemSkip{{Ecosystem: ecosystemNode, Reason: dependency.SkipReasonManifestAbsent}},
		},
		{
			// The fallback Python resolves from the interpreter as before.
			name: "Python only without a manifest resolves from the interpreter as before",
			setup: func(t *testing.T, dir string) {
				writeSources(t, dir, "app", ".py", pyBody, 3)
			},
			wantHintFirst: ecosystemPython,
			wantPrimary:   ecosystemPython,
			wantFallback:  ecosystemPython,
			wantResolved:  []string{ecosystemPython},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			hints := detectedHints(t, dir)
			if len(hints) == 0 || hints[0] != tc.wantHintFirst {
				t.Fatalf("detected hints = %v, want %q first", hints, tc.wantHintFirst)
			}
			plan := planAutoDependencyEcosystems(dir, hints, false, testDependencyRegistry(), nil)
			if got := plan.primary(); got != tc.wantPrimary {
				t.Errorf("primary = %q, want %q (plan %+v)", got, tc.wantPrimary, plan)
			}
			if plan.fallback != tc.wantFallback {
				t.Errorf("fallback = %q, want %q", plan.fallback, tc.wantFallback)
			}
			if !reflect.DeepEqual(plan.resolvable, tc.wantResolved) {
				t.Errorf("resolvable = %v, want %v", plan.resolvable, tc.wantResolved)
			}
			if !reflect.DeepEqual(plan.skipped, tc.wantSkipped) {
				t.Errorf("skipped = %+v, want %+v", plan.skipped, tc.wantSkipped)
			}
		})
	}
}

func TestPlanAutoDependencyEcosystemsNothingDetected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "notes.txt"), "nothing to scan\n")
	plan := planAutoDependencyEcosystems(dir, nil, false, testDependencyRegistry(), nil)
	if plan.primary() != "" || len(plan.resolvable) != 0 || len(plan.skipped) != 0 {
		t.Fatalf("plan = %+v, want no ecosystem at all (ecosystem_unknown)", plan)
	}
}

// The manifest ecosystems follow the dominant language, in DetectEcosystem's
// precedence, whatever order the files were written in.
func TestPlanAutoDependencyEcosystemsManifestPrecedence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"app"}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"}}}`)
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.22\n")
	plan := planAutoDependencyEcosystems(dir, nil, false, testDependencyRegistry(), nil)
	want := []string{"go", ecosystemPython, ecosystemNode}
	if !reflect.DeepEqual(plan.resolvable, want) {
		t.Fatalf("resolvable = %v, want %v", plan.resolvable, want)
	}
	if got := scanutil.DetectEcosystem(dir); got != "go" {
		t.Fatalf("DetectEcosystem = %q, want go", got)
	}
}

func TestDependencySkipDetailsNamesEcosystem(t *testing.T) {
	cases := []struct {
		reason, ecosystem string
		want              map[string]any
	}{
		{dependency.SkipReasonManifestAbsent, ecosystemNode, map[string]any{"reason": "manifest_absent", "ecosystem": "node"}},
		{dependency.SkipReasonLockfileAbsent, ecosystemNode, map[string]any{"reason": "lockfile_absent", "ecosystem": "node"}},
		{depSkipResolverUnavailable, "cpp", map[string]any{"reason": "resolver_unavailable", "ecosystem": "cpp"}},
		{depSkipEcosystemUnknown, "", map[string]any{"reason": "ecosystem_unknown"}},
		{depSkipNotRequested, "", map[string]any{"reason": "not_requested"}},
	}
	for _, tc := range cases {
		got := dependencySkipDetails(tc.reason, tc.ecosystem)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("dependencySkipDetails(%q, %q) = %v, want %v", tc.reason, tc.ecosystem, got, tc.want)
		}
	}
}

// The skipped dependencies event names the ecosystem it skipped and still
// validates against the published progress schema.
func TestDependencySkipEventCarriesEcosystem(t *testing.T) {
	var out bytes.Buffer
	writer := scanutil.NewProgressWriter(&out)
	reason := dependency.SkipReasonManifestAbsent
	if err := writer.SkipWithDetails("dependencies", "scan", reason, dependencySkipDetails(reason, ecosystemNode)); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatalf("decode %q: %v", out.String(), err)
	}
	details, _ := event["details"].(map[string]any)
	if details["reason"] != "manifest_absent" || details["ecosystem"] != "node" {
		t.Fatalf("details = %#v, want reason manifest_absent and ecosystem node", details)
	}
	validateProgressEvent(t, out.String())
}

func validateProgressEvent(t *testing.T, line string) {
	t.Helper()
	schema, err := filepath.Abs(filepath.Join("..", "..", "schemas", "scan-progress-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := gojsonschema.Validate(gojsonschema.NewReferenceLoader("file://"+schema), gojsonschema.NewStringLoader(line))
	if err != nil {
		t.Fatalf("validate progress event: %v", err)
	}
	if !result.Valid() {
		t.Fatalf("progress event %s violates the published schema: %v", line, result.Errors())
	}
}

func TestDependencyEcosystemOutcomeJoinsResolvedEcosystems(t *testing.T) {
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}
	firstReport := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "app.js"}}}
	finalReport := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "app.js"}, {FilePath: "dep.py"}}}
	node := &engine.DepScanResult{Ecosystem: ecosystemNode, CallGraph: graph, Report: firstReport}
	python := &engine.DepScanResult{
		Ecosystem: ecosystemPython, CallGraph: graph, Report: finalReport,
		Dependencies: []dependency.Dependency{{Module: "cryptography", Version: "42.0.0"}},
	}
	// Rust resolved no dependencies, so it built no graph.
	rust := &engine.DepScanResult{Ecosystem: "rust", Report: finalReport}
	outcome := dependencyEcosystemOutcome{
		resolved: []*engine.DepScanResult{node, python, rust},
		skipped: []dependencyEcosystemSkip{
			{Ecosystem: "go", Reason: depSkipParserUnavailable},
			{Ecosystem: "cpp", Reason: depSkipResolverUnavailable},
		},
	}

	primary := outcome.primaryWithAdditional()
	if primary != node || primary.Report != finalReport {
		t.Fatalf("primary = %+v, want node carrying the final report", primary)
	}
	if len(primary.AdditionalEcosystems) != 1 || primary.AdditionalEcosystems[0] != python || len(python.Dependencies) != 1 {
		t.Fatalf("additional ecosystems = %v, want python with its dependencies only", primary.AdditionalEcosystems)
	}

	details := outcome.progressDetails()
	if got := details["ecosystems"]; !reflect.DeepEqual(got, []string{ecosystemNode, ecosystemPython, "rust"}) {
		t.Errorf("ecosystems = %v, want resolution order, primary first", got)
	}
	wantSkipped := []dependencyEcosystemSkip{{Ecosystem: "cpp", Reason: depSkipResolverUnavailable}, {Ecosystem: "go", Reason: depSkipParserUnavailable}}
	if got := details["ecosystems_skipped"]; !reflect.DeepEqual(got, wantSkipped) {
		t.Errorf("ecosystems_skipped = %v, want %v", got, wantSkipped)
	}
	for _, key := range []string{"deps_scanned", "deps_skipped", "deps_failed", "deps_incomplete", "deps_with_findings", "total_dep_findings", "deps_skipped_list"} {
		if _, ok := details[key]; !ok {
			t.Errorf("details lack %s: %v", key, details)
		}
	}
	line, err := json.Marshal(map[string]any{
		"event": "scan_progress", "schema_version": "1", "phase": "dependencies", "status": "completed",
		"parent_phase": "scan", "duration_ms": 1, "details": details,
	})
	if err != nil {
		t.Fatal(err)
	}
	validateProgressEvent(t, string(line))
}

// An explicit --dep-ecosystem resolves that ecosystem alone.
func TestDependencyEcosystemOutcomeExplicitEcosystem(t *testing.T) {
	java := &engine.DepScanResult{Ecosystem: ecosystemJava}
	details := dependencyEcosystemOutcome{resolved: []*engine.DepScanResult{java}}.progressDetails()
	if got := details["ecosystems"]; !reflect.DeepEqual(got, []string{ecosystemJava}) {
		t.Errorf("ecosystems = %v, want [java]", got)
	}
	skipped, ok := details["ecosystems_skipped"].([]dependencyEcosystemSkip)
	if !ok || skipped == nil || len(skipped) != 0 {
		t.Errorf("ecosystems_skipped = %#v, want an empty list", details["ecosystems_skipped"])
	}
	encoded, err := json.Marshal(details["ecosystems_skipped"])
	if err != nil || string(encoded) != "[]" {
		t.Errorf("ecosystems_skipped encodes as %s, want []", encoded)
	}
}

// ecosystems_skipped reports only what the target carried and the phase left
// unresolved, never a language hint with nothing to resolve.
func TestAutoDependencyEcosystemsReportedSkips(t *testing.T) {
	plan := autoDependencyEcosystems{
		manifests: []string{ecosystemPython, ecosystemNode},
		skipped: []dependencyEcosystemSkip{
			{Ecosystem: ecosystemNode, Reason: dependency.SkipReasonLockfileAbsent},
			{Ecosystem: ecosystemPython, Reason: dependency.SkipReasonManifestAbsent},
			{Ecosystem: "go", Reason: dependency.SkipReasonManifestAbsent},
			{Ecosystem: ecosystemCPP, Reason: depSkipResolverUnavailable},
			{Ecosystem: "rust", Reason: depSkipParserUnavailable},
		},
	}
	want := []dependencyEcosystemSkip{
		{Ecosystem: ecosystemNode, Reason: dependency.SkipReasonLockfileAbsent},
		// A requirements.txt with no interpreter to read is a real gap.
		{Ecosystem: ecosystemPython, Reason: dependency.SkipReasonManifestAbsent},
		{Ecosystem: "rust", Reason: depSkipParserUnavailable},
	}
	if got := plan.reportedSkips(); !reflect.DeepEqual(got, want) {
		t.Errorf("reportedSkips = %+v, want %+v", got, want)
	}
}

// The reported case: a Flask application whose browser JavaScript outnumbers
// its Python, with no package.json, resolves Python and reports no skipped
// Node ecosystem, because it had no Node dependencies to resolve.
func TestAutoDependencyEcosystemsFlaskWithBrowserJavaScriptReportsNoSkip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
	writeSources(t, dir, "app", ".py", "import os\n", 3)
	writeSources(t, dir, "ui", ".js", "console.log(1)\n", 6)
	plan := planAutoDependencyEcosystems(dir, detectedHints(t, dir), false, testDependencyRegistry(), nil)
	if plan.primary() != ecosystemPython {
		t.Fatalf("primary = %q, want python (plan %+v)", plan.primary(), plan)
	}
	if got := plan.reportedSkips(); len(got) != 0 {
		t.Errorf("reportedSkips = %+v, want none", got)
	}
}

// An explicit --languages bounds dependency resolution: a manifest of another
// language's ecosystem at the root adds no candidate.
func TestPlanAutoDependencyEcosystemsExplicitLanguagesBoundTheEcosystems(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"app"}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"}}}`)
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.22\n")

	plan := planAutoDependencyEcosystems(dir, []string{"go"}, true, testDependencyRegistry(), nil)
	if !reflect.DeepEqual(plan.resolvable, []string{"go"}) {
		t.Errorf("explicit --languages go: resolvable = %v, want [go] only", plan.resolvable)
	}
	if len(plan.reportedSkips()) != 0 {
		t.Errorf("explicit --languages go: reportedSkips = %+v, want none for languages not requested", plan.reportedSkips())
	}

	plan = planAutoDependencyEcosystems(dir, []string{"go", "javascript"}, true, testDependencyRegistry(), nil)
	if !reflect.DeepEqual(plan.resolvable, []string{"go", ecosystemNode}) {
		t.Errorf("explicit --languages go,javascript: resolvable = %v, want [go node]", plan.resolvable)
	}

	// Detected hints still take every manifest ecosystem.
	plan = planAutoDependencyEcosystems(dir, []string{"go"}, false, testDependencyRegistry(), nil)
	if !slices.Contains(plan.resolvable, ecosystemPython) || !slices.Contains(plan.resolvable, ecosystemNode) {
		t.Errorf("detected hints: resolvable = %v, want go, node and python", plan.resolvable)
	}
}

// The rule graph passes run on the primary graph and on every additional
// ecosystem auto mode resolved, and still on the additional ones when the
// primary resolved no dependencies and built no graph.
func TestRuleGraphPassResultsCoverEveryResolvedGraph(t *testing.T) {
	graph := &callgraph.CallGraph{}
	python := &engine.DepScanResult{Ecosystem: ecosystemPython, CallGraph: graph}
	sourceOnly := &engine.DepScanResult{Ecosystem: "rust"}

	primary := &engine.DepScanResult{Ecosystem: ecosystemNode, CallGraph: graph, AdditionalEcosystems: []*engine.DepScanResult{python, sourceOnly, nil}}
	if got := ruleGraphPassResults(primary); !reflect.DeepEqual(got, []*engine.DepScanResult{primary, python}) {
		t.Errorf("ruleGraphPassResults = %v, want the primary then python", got)
	}

	noGraph := &engine.DepScanResult{Ecosystem: ecosystemNode, AdditionalEcosystems: []*engine.DepScanResult{python}}
	if got := ruleGraphPassResults(noGraph); !reflect.DeepEqual(got, []*engine.DepScanResult{python}) {
		t.Errorf("ruleGraphPassResults = %v, want python alone when the primary built no graph", got)
	}
	if got := ruleGraphPassResults(nil); got != nil {
		t.Errorf("ruleGraphPassResults(nil) = %v, want nil", got)
	}
}

// A secondary ecosystem auto mode added for its manifest cannot fail the scan:
// a failure becomes resolution_failed and the others still resolve. Only
// cancellation stops it.
func TestDependencyEcosystemOutcomeResolveSecondaryKeepsResultsOnFailure(t *testing.T) {
	primaryReport := &entities.InterimReport{}
	primary := &engine.DepScanResult{Ecosystem: ecosystemNode, Report: primaryReport}
	pythonReport := &entities.InterimReport{}
	python := &engine.DepScanResult{Ecosystem: ecosystemPython, Report: pythonReport}
	resolverFor := func(ecosystem string) (dependency.Resolver, error) {
		if ecosystem == ecosystemCPP {
			return nil, errors.New("no resolver")
		}
		return nil, nil
	}
	var inputs []*entities.InterimReport
	scan := func(ecosystem string, _ dependency.Resolver, input *entities.InterimReport) (*engine.DepScanResult, string, error) {
		inputs = append(inputs, input)
		switch ecosystem {
		case ecosystemJava:
			return nil, "", errors.New("failed to list Maven dependencies: mvn: not found")
		case "rust":
			return nil, depSkipParserUnavailable, nil
		default:
			return python, "", nil
		}
	}

	outcome := dependencyEcosystemOutcome{resolved: []*engine.DepScanResult{primary}}
	err := outcome.resolveSecondary(context.Background(), []string{ecosystemJava, ecosystemCPP, "rust", ecosystemPython}, resolverFor, scan)
	if err != nil {
		t.Fatalf("resolveSecondary = %v, want the scan to continue past a failed secondary ecosystem", err)
	}
	if !reflect.DeepEqual(outcome.resolved, []*engine.DepScanResult{primary, python}) {
		t.Errorf("resolved = %v, want the primary then python", outcome.resolved)
	}
	wantSkipped := []dependencyEcosystemSkip{
		{Ecosystem: ecosystemJava, Reason: depSkipResolutionFailed},
		{Ecosystem: ecosystemCPP, Reason: depSkipResolverUnavailable},
		{Ecosystem: "rust", Reason: depSkipParserUnavailable},
	}
	if !reflect.DeepEqual(outcome.skipped, wantSkipped) {
		t.Errorf("skipped = %+v, want %+v", outcome.skipped, wantSkipped)
	}
	for i, input := range inputs {
		if input != primaryReport {
			t.Errorf("scan %d got report %p, want the primary's %p: a failed or skipped ecosystem returns no report to build on", i, input, primaryReport)
		}
	}

	canceled := dependencyEcosystemOutcome{resolved: []*engine.DepScanResult{primary}}
	cancelScan := func(string, dependency.Resolver, *entities.InterimReport) (*engine.DepScanResult, string, error) {
		return nil, "", context.Canceled
	}
	if err := canceled.resolveSecondary(context.Background(), []string{ecosystemPython}, resolverFor, cancelScan); !errors.Is(err, context.Canceled) {
		t.Errorf("resolveSecondary on cancellation = %v, want context.Canceled", err)
	}
}

// A child killed by Ctrl-C, SIGTERM or --timeout returns its exit error, not
// the context's: the scan context decides, so the scan stops, and a done
// context stops it before the next ecosystem starts.
func TestDependencyEcosystemOutcomeResolveSecondaryStopsWhenTheScanContextIsDone(t *testing.T) {
	primary := &engine.DepScanResult{Ecosystem: ecosystemNode, Report: &entities.InterimReport{}}
	resolverFor := func(string) (dependency.Resolver, error) { return nil, nil }
	killed := errors.New("failed to list Maven dependencies: signal: killed")

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	scans := 0
	scan := func(string, dependency.Resolver, *entities.InterimReport) (*engine.DepScanResult, string, error) {
		scans++
		return nil, "", killed
	}
	outcome := dependencyEcosystemOutcome{resolved: []*engine.DepScanResult{primary}}
	err := outcome.resolveSecondary(ctx, []string{ecosystemJava}, resolverFor, scan)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("resolveSecondary after the deadline = %v, want context.DeadlineExceeded before any ecosystem runs", err)
	}
	if typed, ok := failure.As(err); !ok || typed.Code != failure.CodeScannerTimeout || typed.Stage != failure.StageDependency {
		t.Errorf("resolveSecondary after the deadline = %#v, want scanner_timeout at the dependency stage", err)
	}
	if scans != 0 {
		t.Errorf("scans = %d, want none once the scan context is done", scans)
	}

	// The context ends while the toolchain runs: its exit error stops the scan.
	running, stop := context.WithCancel(context.Background())
	killDuringScan := func(string, dependency.Resolver, *entities.InterimReport) (*engine.DepScanResult, string, error) {
		stop()
		return nil, "", killed
	}
	outcome = dependencyEcosystemOutcome{resolved: []*engine.DepScanResult{primary}}
	err = outcome.resolveSecondary(running, []string{ecosystemJava, ecosystemPython}, resolverFor, killDuringScan)
	if !errors.Is(err, killed) || !errors.Is(err, context.Canceled) || !isScanCanceled(err) {
		t.Errorf("resolveSecondary when the scan is interrupted mid-ecosystem = %v, want a cancellation carrying the toolchain's error", err)
	}
	if typed, ok := failure.As(err); !ok || typed.Code != failure.CodeScannerCancelled || typed.Stage != failure.StageDependency {
		t.Errorf("resolveSecondary when the scan is interrupted = %#v, want scanner_canceled at the dependency stage", err)
	}
	if len(outcome.skipped) != 0 {
		t.Errorf("skipped = %+v, want an interrupted ecosystem not reported as resolution_failed", outcome.skipped)
	}
}
