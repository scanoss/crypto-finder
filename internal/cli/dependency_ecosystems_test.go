// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	"github.com/scanoss/crypto-finder/internal/dependency"
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
			plan := planAutoDependencyEcosystems(dir, hints, testDependencyRegistry(), nil)
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
	plan := planAutoDependencyEcosystems(dir, nil, testDependencyRegistry(), nil)
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
	plan := planAutoDependencyEcosystems(dir, nil, testDependencyRegistry(), nil)
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
