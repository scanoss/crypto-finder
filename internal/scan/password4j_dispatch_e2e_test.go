// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// password4jSourceDir points at a real, unmodified checkout of password4j
// 1.8.4 (its src/main/java directory), supplied via env var so the test is
// hermetic and self-skips on machines/CI without the checkout. To run:
//
//	curl -sL -o p4j.zip https://codeload.github.com/Password4j/password4j/zip/refs/tags/1.8.4
//	unzip p4j.zip
//	CRYPTO_FINDER_PASSWORD4J_SRC=$PWD/password4j-1.8.4/src/main/java \
//	  go test ./internal/scan/ -run Password4j
var password4jSourceDir = os.Getenv("CRYPTO_FINDER_PASSWORD4J_SRC")

// TestStitch_RealParse_Password4j_PBKDF2ChainSurvivesDispatchDisambiguation is
// the decisive E2E acceptance test for the stitch-dispatch-provenance change.
//
// password4j's HashBuilder.withPBKDF2() chain
// (withPBKDF2 -> with -> HashingFunction.hash (interface dispatch, 7 concrete
// implementors) -> PBKDF2Function.hash -> internalHash) crosses an interface
// call site the mine-time callgraph builder can only resolve by
// name+arity-expanding EVERY HashingFunction implementor (BcryptFunction,
// Argon2Function, PBKDF2Function, ScryptFunction, MessageDigestFunction,
// CompressedPBKDF2Function, BalloonHashingFunction). Before this change, the
// serving-path stitcher (StitchWithOptions{EntryRootedOnly: true}, mirroring
// scanoss.api's usage via pkg/reachability) fails this call site closed
// (SuppressReasonAmbiguousDispatch) and the PBEKeySpec finding inside
// internalHash never reaches withPBKDF2 in the served callgraph, even though
// the finding is real and reachable.
//
// This test mines password4j 1.8.4 with the real Java parser/builder (the same
// path `crypto-finder scan --export-graph-fragment` uses), builds the
// graph-fragment export exactly as the mining service would, decodes it back
// (round-tripping through the wire schema so resolved_receiver_type must
// survive JSON), and stitches the single-component closure. It asserts the
// PBEKeySpec finding is reached from HashBuilder.withPBKDF2 WITHOUT an
// ambiguous_dispatch suppression on that path — proof the concrete-receiver
// provenance disambiguation (pkg/graphfrag ResolvedReceiverType +
// applyDispatchGroups) does its job end to end, on real mined fragments, not
// just the hand-authored unit fixtures.
func TestStitch_RealParse_Password4j_PBKDF2ChainSurvivesDispatchDisambiguation(t *testing.T) {
	if password4jSourceDir == "" {
		t.Skip("set CRYPTO_FINDER_PASSWORD4J_SRC to a password4j 1.8.4 src/main/java checkout to run this test")
	}
	if _, err := os.Stat(password4jSourceDir); err != nil {
		t.Skipf("password4j fixture source not available at %s: %v", password4jSourceDir, err)
	}

	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: password4jSourceDir, ImportPath: "com.password4j"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(password4j): %v", err)
	}

	// Hand-author the PBEKeySpec finding the way a real crypto rule would
	// report it: PBKDF2Function.internalHash constructs
	// `new PBEKeySpec(plain, salt, iterations, length)` at line 130.
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "PBKDF2Function.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 130,
				EndLine:   130,
				Match:     "new PBEKeySpec(plain, salt, iterations, length)",
				Rules:     []entities.RuleInfo{{ID: "java.jdk.pbekeyspec.construction"}},
				Metadata:  map[string]string{"api": "javax.crypto.spec.PBEKeySpec.<init>", "assetType": "algorithm", "algorithmFamily": "PBKDF2"},
			}},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	export := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: password4jSourceDir,
		RootModule:  "com.password4j:password4j",
		Ecosystem:   "java",
	})

	// Round-trip through the wire schema (JSON) exactly like a real mine ->
	// storage -> stitch cycle, so resolved_receiver_type must survive
	// marshal/unmarshal, not just live in memory.
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal graph fragment export: %v", err)
	}
	if !strings.Contains(string(raw), `"resolved_receiver_type"`) {
		t.Fatalf("exported fragment JSON has no resolved_receiver_type field — export-time stamping did not fire")
	}

	component := graphfrag.ComponentKey{Purl: "pkg:maven/com.password4j/password4j", Version: "1.8.4"}
	frag, err := graphfrag.DecodeFragment(component, raw)
	if err != nil {
		t.Fatalf("DecodeFragment(password4j): %v", err)
	}

	fragments := map[graphfrag.ComponentKey]graphfrag.Fragment{component: frag}
	deps := graphfrag.DependencyGraph{component: nil}

	res, err := graphfrag.StitchWithOptions(component, deps, fragments, graphfrag.StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}

	assertPBKDF2ChainReachesFinding(t, res)
}

// assertPBKDF2ChainReachesFinding asserts at least one chain for the
// PBEKeySpec finding has a frame rooted at (or passing through)
// HashBuilder.withPBKDF2, proving the served callgraph threads the
// interface-dispatch call site through to the finding.
func assertPBKDF2ChainReachesFinding(t *testing.T, res *graphfrag.Result) {
	t.Helper()
	matched := make([]graphfrag.FindingChain, 0, len(res.Chains))
	for _, ch := range res.Chains {
		if ch.RuleID != "java.jdk.pbekeyspec.construction" {
			continue
		}
		matched = append(matched, ch)
	}
	if len(matched) == 0 {
		t.Fatalf("no chain found for java.jdk.pbekeyspec.construction; chains=%+v suppressed=%+v", res.Chains, res.Suppressed)
	}

	var hasWithPBKDF2Root bool
	for i := range matched {
		frames := matched[i].Frames
		for j := range frames {
			if strings.Contains(frames[j].Signature, "HashBuilder") && strings.Contains(frames[j].Signature, "withPBKDF2") {
				hasWithPBKDF2Root = true
			}
		}
	}
	if !hasWithPBKDF2Root {
		t.Fatalf("PBEKeySpec chain(s) found but none pass through HashBuilder.withPBKDF2: %+v", matched)
	}
}
