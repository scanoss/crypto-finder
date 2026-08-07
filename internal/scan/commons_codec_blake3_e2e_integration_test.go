// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// commons_codec_blake3_e2e_integration_test.go — scanoss/crypto-finder#187 scan-layer proof.
//
// Proves that entry-point synthesis (engine.SynthesizeRuleCryptoEntryPoints)
// JOINS the scanoss/crypto_rules#164 (PR #167) Commons Codec Blake3 rule api
// anchors (org.apache.commons.codec.digest.Blake3.{initHash,initKeyedHash,
// initKeyDerivationFunction} — one per mode) against a Blake3-shaped source
// file mined with the real Java parser + callgraph builder — the same path
// `crypto-finder scan --export-callgraph` uses when mining commons-codec
// itself. This is the public-export proof that the
// commons-codec-blake3.yaml contract's method+arity keys
// (internal/callgraph/contracts/java/commons-codec-blake3.yaml) match what
// the Java parser actually emits for Blake3's factory/config/operation
// methods, not just the embedded-contract loader assertions in
// java_libraries_test.go, and that all THREE modes (hash / keyed-MAC / KDF)
// resolve independently.
package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// blake3Source is a Blake3-shaped stub of
// org/apache/commons/codec/digest/Blake3.java (commons-codec 1.19.0): the
// same mode-selecting factory (initHash/initKeyedHash/
// initKeyDerivationFunction), one-shot static (hash/keyedHash),
// config/absorb (update), and operation/output (doFinalize) method shapes
// the real class declares, at the same arities the
// commons-codec-blake3.yaml contract keys on. It is a stub (not a full
// compilable copy) because the tree-sitter-based Java parser extracts
// declarations syntactically and does not require the real BLAKE3
// compression internals to be present.
const blake3Source = `package org.apache.commons.codec.digest;

public final class Blake3 {

    public static byte[] hash(byte[] data) {
        return initHash().update(data).doFinalize(32);
    }

    public static Blake3 initHash() {
        return new Blake3();
    }

    public static Blake3 initKeyDerivationFunction(byte[] kdfContext) {
        return new Blake3();
    }

    public static Blake3 initKeyedHash(byte[] key) {
        return new Blake3();
    }

    public static byte[] keyedHash(byte[] key, byte[] data) {
        return initKeyedHash(key).update(data).doFinalize(32);
    }

    public Blake3 update(byte[] in) {
        return this;
    }

    public Blake3 doFinalize(byte[] out) {
        return this;
    }

    public Blake3 reset() {
        return this;
    }
}
`

// blake3RulesYAML mirrors the scanoss/crypto_rules#164 (PR #167) rule shapes
// anchored on Blake3: one rule per mode, each anchoring on its
// mode-selecting factory api (matching what the real hash/mac/kdf
// rules.yaml files declare in their metadata.crypto.api field, even though
// their pattern-either also matches the corresponding one-shot static).
const blake3RulesYAML = `rules:
  - id: java.commons-codec.algorithm.hash.blake3
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: hash
        algorithmFamily: BLAKE3
        algorithmName: BLAKE3
        algorithmParameterSetIdentifier: "256"
        library: Apache Commons Codec
        api: org.apache.commons.codec.digest.Blake3.initHash
  - id: java.commons-codec.algorithm.mac.blake3
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: mac
        algorithmFamily: BLAKE3
        algorithmName: BLAKE3
        algorithmParameterSetIdentifier: "256"
        library: Apache Commons Codec
        api: org.apache.commons.codec.digest.Blake3.initKeyedHash
  - id: java.commons-codec.algorithm.kdf.blake3
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: kdf
        algorithmFamily: BLAKE3
        algorithmName: BLAKE3
        algorithmParameterSetIdentifier: "256"
        library: Apache Commons Codec
        api: org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction
`

// TestCommonsCodecBlake3_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors
// proves that mining commons-codec's own Blake3 source produces a
// synthesized crypto entry point for every scanoss/crypto_rules#164 mode
// anchor: initHash (hash mode), initKeyedHash (keyed-MAC mode), and
// initKeyDerivationFunction (KDF mode) — the three independent modes the
// issue #187 AC requires to be preserved so entry-point synthesis joins the
// rule anchors and the three metadata outcomes line up.
func TestCommonsCodecBlake3_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Blake3.java"), []byte(blake3Source), 0o600); err != nil {
		t.Fatal(err)
	}

	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "org.apache.commons.codec.digest"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(Blake3 stub): %v", err)
	}

	ruleDir := t.TempDir()
	rulePath := filepath.Join(ruleDir, "commons-codec-blake3.yaml")
	if err := os.WriteFile(rulePath, []byte(blake3RulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "java")

	// initHash + initKeyedHash + initKeyDerivationFunction = 3 synthesized
	// entry points, one per (definition, rule-block) pair -- the call sites
	// inside hash()/keyedHash() delegating to initHash()/initKeyedHash() are
	// same-class calls on the already-anchored factory, not separate anchors.
	const want = 3
	if n != want {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Fatalf("synthesized %d entry points, want %d; graph FQNs: %v", n, want, fqns)
	}

	byAPI := map[string]bool{}
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			byAPI[asset.Metadata["api"]] = true
		}
	}

	for _, api := range []string{
		"org.apache.commons.codec.digest.Blake3.initHash",
		"org.apache.commons.codec.digest.Blake3.initKeyedHash",
		"org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction",
	} {
		if !byAPI[api] {
			t.Errorf("no synthesized entry point for rule anchor api %q; got apis: %v", api, byAPI)
		}
	}

	// The three modes must carry DISTINCT algorithmPrimitive metadata
	// (hash/mac/kdf) so downstream consumers can tell them apart -- this is
	// the "three metadata outcomes line up" half of the issue #187 AC.
	primitiveByAPI := map[string]string{}
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			primitiveByAPI[asset.Metadata["api"]] = asset.Metadata["algorithmPrimitive"]
		}
	}
	wantPrimitive := map[string]string{
		"org.apache.commons.codec.digest.Blake3.initHash":                  "hash",
		"org.apache.commons.codec.digest.Blake3.initKeyedHash":             "mac",
		"org.apache.commons.codec.digest.Blake3.initKeyDerivationFunction": "kdf",
	}
	for api, want := range wantPrimitive {
		if got := primitiveByAPI[api]; got != want {
			t.Errorf("api %q algorithmPrimitive = %q, want %q", api, got, want)
		}
	}
}
