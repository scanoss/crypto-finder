// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// writeRule writes a minimal rule file carrying one metadata.crypto block and
// returns its path.
func writeRule(t *testing.T, dir, api, family string) string {
	t.Helper()
	body := "" +
		"rules:\n" +
		"  - id: test.rule\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: kdf\n" +
		"        algorithmFamily: " + family + "\n" +
		"        operation: keyderive\n" +
		"        api: " + api + "\n"
	p := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func graphWith(decl *callgraph.FunctionDecl) *callgraph.CallGraph {
	g := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}
	if decl != nil {
		g.Functions[decl.ID.String()] = decl
	}
	return g
}

func builderWithBcrypt() *callgraph.FunctionDecl {
	return &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "com.example", Type: "Builder", Name: "withBcrypt"},
		FilePath:  "src/main/java/com/example/Builder.java",
		StartLine: 10,
		EndLine:   12,
	}
}

func TestSynthesize_FiresForOwningLibrary(t *testing.T) {
	dir := t.TempDir()
	rule := writeRule(t, dir, "com.example.Builder.withBcrypt", "bcrypt")
	report := &entities.InterimReport{}
	graph := graphWith(builderWithBcrypt())

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule})
	if n != 1 {
		t.Fatalf("expected 1 synthesized finding, got %d", n)
	}
	asset := report.Findings[0].CryptographicAssets[0]
	if got := asset.Metadata["algorithmFamily"]; got != "bcrypt" {
		t.Errorf("algorithmFamily = %q, want bcrypt (verbatim from rule)", got)
	}
	if got := asset.Metadata["api"]; got != "com.example.Builder.withBcrypt" {
		t.Errorf("api = %q", got)
	}
	if asset.StartLine != 10 {
		t.Errorf("synthetic finding should sit at the method definition line, got %d", asset.StartLine)
	}
}

func TestSynthesize_NoOpForConsumerScan(t *testing.T) {
	// Definition absent (a consumer calls the method but does not define it).
	dir := t.TempDir()
	rule := writeRule(t, dir, "com.example.Builder.withBcrypt", "bcrypt")
	report := &entities.InterimReport{}

	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(nil), []string{rule}); n != 0 {
		t.Fatalf("expected 0 synthesized findings when definition is absent, got %d", n)
	}
}

func TestSynthesize_NoOpForShortAPI(t *testing.T) {
	// Type 1 short api (e.g. "Cipher.getInstance") must never become a join key.
	dir := t.TempDir()
	rule := writeRule(t, dir, "Cipher.getInstance", "AES")
	report := &entities.InterimReport{}
	graph := graphWith(builderWithBcrypt())

	if n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}); n != 0 {
		t.Fatalf("expected 0 synthesized findings for a non-qualified api, got %d", n)
	}
}

func TestSynthesize_NoOpWhenBodyAlreadyDetected(t *testing.T) {
	// Type 1: the method body already has a detected crypto finding, so it is
	// already a natural entry point and must not be double-counted.
	dir := t.TempDir()
	rule := writeRule(t, dir, "com.example.Builder.withBcrypt", "bcrypt")
	decl := builderWithBcrypt()
	report := &entities.InterimReport{
		Findings: []entities.Finding{{
			FilePath: decl.FilePath,
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 11, Metadata: map[string]string{"algorithmFamily": "bcrypt"}},
			},
		}},
	}

	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}); n != 0 {
		t.Fatalf("expected 0 synthesized findings when body already detected, got %d", n)
	}
}
