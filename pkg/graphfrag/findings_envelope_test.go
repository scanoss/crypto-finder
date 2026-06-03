// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"testing"
)

// buildEnvelopeFixture returns a root+dep closure where BOTH the root and the
// dep carry a reachable crypto operation with full 1.2 asset metadata. Used to
// assert ToFindingsEnvelope emits the v1.3 findings envelope AND that its
// finding_ids match what ToCallgraphExport produces (the render-layer join key).
func buildEnvelopeFixture() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	app := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0"}
	lib := ComponentKey{Purl: "pkg:maven/net.crypto/lib", Version: "2.0"}

	fragments := map[ComponentKey]Fragment{
		app: {
			Component: app,
			Module:    "com.acme:app",
			Functions: []Function{{
				Signature: "com.acme.App.entry#0", FunctionName: "com.acme.App.entry",
				CanonicalSignature: "com.acme.App.entry(): void", FilePath: "App.java", StartLine: 5,
			}},
			ExternalCalls: []ExternalCall{{
				Caller: "com.acme.App.entry#0", TargetSignature: "net.crypto.Lib.encrypt#0",
				Resolution: ResolutionExact,
			}},
			CryptoOperations: []CryptoOperation{{
				Function: "com.acme.App.entry#0", RuleID: "rule.app",
				FilePath: "App.java", StartLine: 5, EndLine: 5,
				Match: "DigestUtils.md5(data)", OID: "1.2.840.113549.2.5",
				Source: "direct", Metadata: json.RawMessage(`{"assetType":"algorithm","algorithmName":"MD5"}`),
			}},
		},
		lib: {
			Component: lib,
			Module:    "net.crypto:lib",
			Functions: []Function{{
				Signature: "net.crypto.Lib.encrypt#0", FunctionName: "net.crypto.Lib.encrypt",
				CanonicalSignature: "net.crypto.Lib.encrypt(): void", FilePath: "Lib.java", StartLine: 25,
			}},
			CryptoOperations: []CryptoOperation{{
				Function: "net.crypto.Lib.encrypt#0", RuleID: "rule.lib",
				FilePath: "Lib.java", StartLine: 25, EndLine: 27,
				Match: `Cipher.getInstance("AES")`, OID: "2.16.840.1.101.3.4.1.2",
				Source: "direct", Metadata: json.RawMessage(`{"assetType":"algorithm","algorithmName":"AES"}`),
			}},
		},
	}
	return app, DependencyGraph{app: {lib}}, fragments
}

// findAsset returns the asset for a given file_path + finding_id, or nil.
func findAsset(env FindingsEnvelope, filePath string) *FindingAsset {
	for i := range env.Findings {
		if env.Findings[i].FilePath != filePath {
			continue
		}
		if len(env.Findings[i].CryptographicAssets) > 0 {
			return &env.Findings[i].CryptographicAssets[0]
		}
	}
	return nil
}

// TestToFindingsEnvelope_ShapeAndDepPrefix asserts the v1.3 envelope shape, the
// dep-prefixed file_path, direct/indirect source discrimination, and that
// match/end_line/oid/metadata are carried through verbatim.
func TestToFindingsEnvelope_ShapeAndDepPrefix(t *testing.T) {
	app, deps, fragments := buildEnvelopeFixture()
	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}

	env := ToFindingsEnvelope(app, deps, fragments, meta)

	if env.Version == "" {
		t.Error("envelope Version is empty, want findings schema version (e.g. 1.3)")
	}

	// Root asset: unprefixed path, source=direct.
	root := findAsset(env, "App.java")
	if root == nil {
		t.Fatalf("no asset at App.java; envelope=%+v", env)
	}
	if root.Source != "direct" {
		t.Errorf("root source = %q, want direct", root.Source)
	}
	if root.Match != "DigestUtils.md5(data)" || root.EndLine != 5 || root.OID != "1.2.840.113549.2.5" {
		t.Errorf("root asset fields not carried through: %+v", root)
	}

	// Dep asset: file_path prefixed with module@version, source=indirect.
	const depPath = "net.crypto:lib@2.0/Lib.java"
	dep := findAsset(env, depPath)
	if dep == nil {
		t.Fatalf("no asset at %s; envelope=%+v", depPath, env)
	}
	if dep.Source != "indirect" {
		t.Errorf("dep source = %q, want indirect", dep.Source)
	}
	if dep.Match != `Cipher.getInstance("AES")` || dep.EndLine != 27 {
		t.Errorf("dep asset match/end_line not carried through: %+v", dep)
	}
}

// TestToFindingsEnvelope_FindingIDMatchesCallgraphExport is the load-bearing
// invariant: the envelope's finding_ids MUST equal ToCallgraphExport's so the
// render layer's asset->call_chains join holds. Verified for the dep component
// (where the dep-prefix path construction is non-trivial).
func TestToFindingsEnvelope_FindingIDMatchesCallgraphExport(t *testing.T) {
	app, deps, fragments := buildEnvelopeFixture()
	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}

	res, err := Stitch(app, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	export := res.ToCallgraphExport(app, meta)
	env := ToFindingsEnvelope(app, deps, fragments, meta)

	// Collect finding_ids from each side.
	exportIDs := map[string]bool{}
	for _, fg := range export.FindingGraphs {
		exportIDs[fg.FindingID] = true
	}
	envIDs := map[string]bool{}
	for _, f := range env.Findings {
		for _, a := range f.CryptographicAssets {
			envIDs[a.FindingID] = true
		}
	}

	if len(exportIDs) == 0 {
		t.Fatal("ToCallgraphExport produced no finding_ids")
	}
	for id := range exportIDs {
		if !envIDs[id] {
			t.Errorf("finding_id %q present in callgraph export but missing from findings envelope (join would break); envelope ids=%v", id, envIDs)
		}
	}
}
