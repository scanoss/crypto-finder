// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/pkg/appreach"
)

// hasherLibrary is a Java dependency with one interface, two implementations
// that each hold a crypto finding (on the line of their sum's body), and
// factories: standard builds one class on every return; mixed also returns a
// `new` the return tracer cannot read, so what it builds is unknown.
var hasherLibrary = map[string]string{
	"org/acme/liba/Hasher.java": `package org.acme.liba;

public interface Hasher {
    byte[] sum(byte[] data);
}
`,
	"org/acme/liba/Standard.java": `package org.acme.liba;

public final class Standard implements Hasher {
    public byte[] sum(byte[] data) {
        return Digests.standard(data);
    }
}
`,
	"org/acme/liba/Plain.java": `package org.acme.liba;

public final class Plain implements Hasher {
    public byte[] sum(byte[] data) {
        return Digests.plain(data);
    }
}
`,
	"org/acme/liba/Hashers.java": `package org.acme.liba;

public final class Hashers {
    public static Hasher standard() {
        return new Standard();
    }

    public static Hasher mixed(boolean fast) {
        if (fast) {
            return new org.acme.liba.Box<String>();
        }
        return new Standard();
    }
}
`,
}

const (
	hasherStandardFinding = "org/acme/liba/Standard.java"
	hasherPlainFinding    = "org/acme/liba/Plain.java"
	hasherFindingLine     = 5
)

var hasherLibraryKey = graphfrag.ComponentKey{Purl: "pkg:maven/org.acme/liba", Version: "1.0.0"}

func writeJavaSources(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, source := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// hasherLibraryFragment mines the library as a dependency scan does and
// returns its graph fragment as stored: written to JSON and read back.
func hasherLibraryFragment(t *testing.T) (graphfrag.GraphFragmentExport, graphfrag.Fragment) {
	t.Helper()
	dir := writeJavaSources(t, hasherLibrary)
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemJava, callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	finding := func(file string) entities.Finding {
		return entities.Finding{FilePath: file, Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: hasherFindingLine, EndLine: hasherFindingLine, Match: "Digests.x(data)",
			Rules:    []entities.RuleInfo{{ID: "test.digest." + filepath.Base(file)}},
			Metadata: map[string]string{"assetType": "algorithm"},
		}}}
	}
	report := &entities.InterimReport{
		Tool:     entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules:    entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{finding(hasherStandardFinding), finding(hasherPlainFinding)},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	doc := buildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "org.acme:liba", Ecosystem: ecosystemJava,
	})
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var stored graphfrag.GraphFragmentExport
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	frag, err := graphfrag.DecodeFragment(hasherLibraryKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	return stored, frag
}

// A Java factory's fragment names the one class every return builds, and
// none when a return yields something it cannot read.
func TestFragmentNamesTheClassAFactoryConstructs(t *testing.T) {
	doc, _ := hasherLibraryFragment(t)
	got := map[string]string{}
	for _, fn := range doc.Functions {
		got[fn.Key] = fn.Constructs
	}
	if want := "org.acme.liba.(Standard)"; got["org.acme.liba.(Hashers).standard#0"] != want {
		t.Errorf("standard: constructs %q, want %q", got["org.acme.liba.(Hashers).standard#0"], want)
	}
	if c := got["org.acme.liba.(Hashers).mixed#1"]; c != "" {
		t.Errorf("mixed: constructs %q, want none: one return is not a plain new of Standard", c)
	}
	if c := got["org.acme.liba.(Standard).sum#1"]; c != "" {
		t.Errorf("Standard.sum: constructs %q, want none", c)
	}
}

// A Go fragment carries no constructs: only a Java `new T()` builds a T and
// nothing else.
func TestFragmentNamesNoConstructedClassOutsideJava(t *testing.T) {
	dir := writeJavaSources(t, map[string]string{"go.mod": "module example.com/liba\n", "liba.go": `package liba

type Hasher interface{ Sum([]byte) []byte }

type standard struct{}

func (standard) Sum(b []byte) []byte { return b }

func Standard() Hasher { return &standard{} }
`})
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemGo, callgraph.NewGoParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildGraphFragmentExport(&engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, Ecosystem: ecosystemGo})
	for _, fn := range doc.Functions {
		if fn.Constructs != "" {
			t.Errorf("%s: constructs %q in a Go fragment", fn.Key, fn.Constructs)
		}
	}
}

// hasherVerdicts sends the application request of a project that calls sum
// on what factory returns, against the library's stored fragment, and returns
// the verdict of each implementation's finding by its file.
func hasherVerdicts(t *testing.T, factory string) map[string]string {
	t.Helper()
	_, lib := hasherLibraryFragment(t)
	dir := writeJavaSources(t, map[string]string{"src/main/java/org/acme/app/Main.java": `package org.acme.app;

import org.acme.liba.Hasher;
import org.acme.liba.Hashers;

public final class Main {
    public static void main(String[] args) {
        Hasher h = Hashers.` + factory + `;
        h.sum(new byte[0]);
    }
}
`})
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemJava, callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	project := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, Ecosystem: ecosystemJava, ProjectRoot: dir}
	fragment := BuildGraphFragmentExport(project, &oid.ResolvedReport{})
	AddReceiverProducers(project, &fragment)
	plan, rejected := appreach.NewPlan(appreach.Request{
		SchemaVersion: appreach.RequestSchemaVersion,
		Dependencies:  []appreach.Dependency{{Purl: hasherLibraryKey.Purl, Version: hasherLibraryKey.Version, Direct: true}},
		CallSites:     engine.CallSites(&fragment, nil),
	}, appreach.DefaultLimits)
	if rejected != nil {
		t.Fatalf("request rejected: %s", rejected.InfoMessage)
	}
	resp, _, err := plan.Run(context.Background(), map[appreach.ComponentKey]appreach.Component{hasherLibraryKey: {Fragment: &lib}}, nil, appreach.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, dep := range resp.Dependencies {
		for _, f := range dep.Findings {
			for _, a := range f.CryptographicAssets {
				out[filepath.ToSlash(f.FilePath)] = a.Reachability + ":" + a.ReachabilityReason
			}
		}
	}
	return out
}

func verdictOf(verdicts map[string]string, file string) string {
	for path, v := range verdicts {
		if filepath.Base(path) == filepath.Base(file) {
			return v
		}
	}
	return "missing"
}

// The library's factory builds one class, so the call on its result reaches
// that class's sum only: the other implementation's finding is unreachable,
// not unknown.
func TestApplicationReachabilityNarrowsACallOnAFactoryResult(t *testing.T) {
	got := hasherVerdicts(t, "standard()")
	if v := verdictOf(got, hasherStandardFinding); v != "reachable:" {
		t.Errorf("Standard's finding: %q, want reachable; all verdicts %v", v, got)
	}
	if v := verdictOf(got, hasherPlainFinding); v != "unreachable:" {
		t.Errorf("Plain's finding: %q, want unreachable; all verdicts %v", v, got)
	}
}

// A factory with a return its fragment cannot name a class for leaves the
// call on its result as it was: every implementation is a candidate, and the
// stitch answers unknown for both findings.
func TestApplicationReachabilityKeepsACallOnAnUnreadFactory(t *testing.T) {
	got := hasherVerdicts(t, "mixed(true)")
	for _, file := range []string{hasherStandardFinding, hasherPlainFinding} {
		if v := verdictOf(got, file); v != "unknown:ambiguous_dispatch" {
			t.Errorf("%s: %q, want unknown:ambiguous_dispatch; all verdicts %v", file, v, got)
		}
	}
}
