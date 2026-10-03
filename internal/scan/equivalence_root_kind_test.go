// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// rootKindParitySrc has three roots into one crypto function: a program entry
// (main), a framework callback (an @Override of a type outside the scan) and a
// plain method nothing calls.
const rootKindParitySrc = `package com.app;

class Svc implements Runnable {
    public static void main(String[] args) {
        new Svc().mid();
    }
    @Override
    public void run() {
        mid();
    }
    void orphan() {
        mid();
    }
    void mid() {
        common();
    }
    void common() {
        javax.crypto.Cipher.getInstance("AES");
    }
}
`

// rootKindOrphanOnlySrc reaches the crypto only from methods nothing calls.
const rootKindOrphanOnlySrc = `package com.app;

class Svc {
    void orphanA() {
        mid();
    }
    void orphanB() {
        mid();
    }
    void mid() {
        javax.crypto.Cipher.getInstance("AES");
    }
}
`

// TestEquivalence_RootKind_StitchMatchesLive pins that the stitched export
// reads the same root_kind on each chain root and the same no_callers_only as
// the live export of the same component, once the fragment carries entry kinds.
func TestEquivalence_RootKind_StitchMatchesLive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		src          string
		cryptoLine   int
		wantKinds    map[string]string
		wantNoCaller bool
	}{
		{
			name: "every root nothing calls", src: rootKindOrphanOnlySrc, cryptoLine: 11,
			wantKinds:    map[string]string{"orphanA": "no_callers", "orphanB": "no_callers"},
			wantNoCaller: true,
		},
		{
			name: "main and framework entry among the roots", src: rootKindParitySrc, cryptoLine: 18,
			wantKinds: map[string]string{"main": "main", "run": "framework_entry", "orphan": "no_callers"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := graphfrag.ComponentKey{Purl: "pkg:maven/com.app/app", Version: "1.0"}
			report := reportForTerminal(t, tc.cryptoLine, `javax.crypto.Cipher.getInstance("AES")`, "javax.crypto.Cipher.getInstance")

			live := liveDependencyScanExport(t, "Svc.java", tc.src, report)
			frag := buildModuleFragment(t, key, "com.app:app", "Svc.java", tc.src, report)
			res, err := graphfrag.StitchWithOptions(key, graphfrag.DependencyGraph{},
				map[graphfrag.ComponentKey]graphfrag.Fragment{key: frag}, graphfrag.StitchOptions{EntryRootedOnly: true})
			if err != nil {
				t.Fatalf("Stitch: %v", err)
			}
			stitched := res.ToCallgraphExport(key, graphfrag.ScanMeta{RootModule: "com.app:app", Ecosystem: "java"})

			if len(live.FindingGraphs) != 1 || len(stitched.FindingGraphs) != 1 {
				t.Fatalf("finding_graphs live=%d stitched=%d, want 1", len(live.FindingGraphs), len(stitched.FindingGraphs))
			}
			liveKinds := map[string]string{}
			for _, chain := range live.FindingGraphs[0].CallChains {
				liveKinds[rootMethod(chain[0].FunctionName)] = chain[0].RootKind
			}
			stitchedKinds := map[string]string{}
			for _, chain := range stitched.FindingGraphs[0].CallChains {
				stitchedKinds[rootMethod(chain[0].FunctionName)] = chain[0].RootKind
			}
			t.Logf("live kinds %v stitched kinds %v analysis %+v", liveKinds, stitchedKinds, live.FindingGraphs[0].Analysis)
			for fn, want := range tc.wantKinds {
				if liveKinds[fn] != want || stitchedKinds[fn] != want {
					t.Errorf("root_kind of %s: live %q stitched %q, want %q", fn, liveKinds[fn], stitchedKinds[fn], want)
				}
			}
			liveOnly := live.FindingGraphs[0].Analysis != nil && live.FindingGraphs[0].Analysis.NoCallersOnly
			stitchedOnly := stitched.FindingGraphs[0].Analysis != nil && stitched.FindingGraphs[0].Analysis.NoCallersOnly
			if liveOnly != tc.wantNoCaller || stitchedOnly != tc.wantNoCaller {
				t.Errorf("no_callers_only: live %v stitched %v, want %v", liveOnly, stitchedOnly, tc.wantNoCaller)
			}
		})
	}
}

// rootMethod is the bare method name of a fully qualified function name.
func rootMethod(functionName string) string {
	return functionName[strings.LastIndex(functionName, ".")+1:]
}

// liveDependencyScanExport is the live export of a component scanned with
// dependencies, which is what makes the application's packages known and so
// gives a chain a root_kind and a finding no_callers_only.
func liveDependencyScanExport(t *testing.T, file, src string, report *entities.InterimReport) callGraphExportV2 {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app", Ecosystem: "java",
		Dependencies: []dependency.Dependency{{Module: "org.lib:digest"}},
	})
}
