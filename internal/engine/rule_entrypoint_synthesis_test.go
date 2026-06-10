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
	"strings"
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

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}, "")
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

func bcprovAESEngineCtor() *callgraph.FunctionDecl {
	return &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "org.bouncycastle.crypto.engines", Type: "AESEngine", Name: "<init>"},
		FilePath:  "org/bouncycastle/crypto/engines/AESEngine.java",
		StartLine: 42,
		EndLine:   60,
	}
}

func TestSynthesize_FiresForConstructor(t *testing.T) {
	// A library public-API constructor (e.g. new AESEngine()) must surface as a
	// synthetic entry point. The join key is the canonical FQN with ".<init>",
	// NOT the Class.Class display form — this is the form functionFQN computes
	// for a constructor definition and is what a boundary rule's api must use.
	dir := t.TempDir()
	api := "org.bouncycastle.crypto.engines.AESEngine.<init>"
	rule := writeRule(t, dir, api, "AES")
	report := &entities.InterimReport{}
	graph := graphWith(bcprovAESEngineCtor())

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}, "")
	if n != 1 {
		t.Fatalf("expected 1 synthesized finding for constructor api, got %d", n)
	}
	if got := report.Findings[0].CryptographicAssets[0].Metadata["api"]; got != api {
		t.Errorf("api = %q, want %q", got, api)
	}
}

func TestSynthesize_FiresForImplicitConstructor(t *testing.T) {
	// A class with no explicit constructor (only a default) has no <init> in the
	// source AST — but if the class is scanned (another method is defined), a
	// constructor boundary rule must still surface it. RSAEngine is the real case.
	dir := t.TempDir()
	api := "org.bouncycastle.crypto.engines.RSAEngine.<init>"
	rule := writeRule(t, dir, api, "RSA")
	report := &entities.InterimReport{}
	// Only a method definition exists for the class — no <init>.
	graph := graphWith(&callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "org.bouncycastle.crypto.engines", Type: "RSAEngine", Name: "init"},
		FilePath:  "org/bouncycastle/crypto/engines/RSAEngine.java",
		StartLine: 20,
		EndLine:   30,
	})

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}, "")
	if n != 1 {
		t.Fatalf("expected 1 synthesized finding for implicit constructor, got %d", n)
	}
	if got := report.Findings[0].CryptographicAssets[0].Metadata["api"]; got != api {
		t.Errorf("api = %q, want %q", got, api)
	}
}

func TestSynthesize_NoOpForImplicitCtorWhenClassAbsent(t *testing.T) {
	// A constructor api whose class is not scanned at all must NOT synthesize.
	dir := t.TempDir()
	rule := writeRule(t, dir, "org.bouncycastle.crypto.engines.RSAEngine.<init>", "RSA")
	report := &entities.InterimReport{}
	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(nil), []string{rule}, ""); n != 0 {
		t.Fatalf("expected 0 synthesized findings when class absent, got %d", n)
	}
}

func TestSynthesize_NoOpForConsumerScan(t *testing.T) {
	// Definition absent (a consumer calls the method but does not define it).
	dir := t.TempDir()
	rule := writeRule(t, dir, "com.example.Builder.withBcrypt", "bcrypt")
	report := &entities.InterimReport{}

	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(nil), []string{rule}, ""); n != 0 {
		t.Fatalf("expected 0 synthesized findings when definition is absent, got %d", n)
	}
}

func TestSynthesize_NoOpForShortAPI(t *testing.T) {
	// Type 1 short api (e.g. "Cipher.getInstance") must never become a join key.
	dir := t.TempDir()
	rule := writeRule(t, dir, "Cipher.getInstance", "AES")
	report := &entities.InterimReport{}
	graph := graphWith(builderWithBcrypt())

	if n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}, ""); n != 0 {
		t.Fatalf("expected 0 synthesized findings for a non-qualified api, got %d", n)
	}
}

func TestSynthesize_NoOpForNonStringAPI(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	body := "" +
		"rules:\n" +
		"  - id: test.rule\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: kdf\n" +
		"        algorithmFamily: bcrypt\n" +
		"        operation: keyderive\n" +
		"        api:\n" +
		"          - com.example.Builder.withBcrypt\n"
	if err := os.WriteFile(rule, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	graph := graphWith(builderWithBcrypt())

	if n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}, ""); n != 0 {
		t.Fatalf("expected 0 synthesized findings for a non-string api, got %d", n)
	}
}

// ── T-1.5: Python FQN api synthesis gate ───────────────────────────────────

// TestSynthesizeRuleCryptoEntryPoints_Python_FQNApiHitsGate guards REQ-2.1.
// A Python rule whose api has >= 2 dots (FQN form) must produce a synthetic
// crypto entry point when the matching method definition exists in the callgraph.
// A short api (only 1 dot, e.g. "hashlib.sha256") under ecosystem="" must NOT
// produce any entry point (ecosystem="" is the Java/default >= 2-dot gate).
func TestSynthesizeRuleCryptoEntryPoints_Python_FQNApiHitsGate(t *testing.T) {
	t.Parallel()

	// Case 1: Python FQN api with >= 2 dots — must synthesize under "python" ecosystem.
	const pythonFQNApi = "cryptography.hazmat.primitives.ciphers.Cipher.encryptor"
	dirFQN := t.TempDir()
	ruleFQN := writeRule(t, dirFQN, pythonFQNApi, "AES")

	// The FunctionDecl representing the Cipher.encryptor method definition in the
	// Python callgraph. Package = module path, Type = class name, Name = method.
	cipherEncryptorDecl := &callgraph.FunctionDecl{
		ID: callgraph.FunctionID{
			Package: "cryptography.hazmat.primitives.ciphers",
			Type:    "Cipher",
			Name:    "encryptor",
		},
		FilePath:  "cryptography/hazmat/primitives/ciphers/base.py",
		StartLine: 105,
		EndLine:   115,
	}

	reportFQN := &entities.InterimReport{}
	graphFQN := graphWith(cipherEncryptorDecl)

	n := SynthesizeRuleCryptoEntryPoints(reportFQN, graphFQN, []string{ruleFQN}, "python")
	if n != 1 {
		t.Errorf("FQN api (%q): expected 1 synthesized entry point, got %d", pythonFQNApi, n)
	}
	if n > 0 {
		if got := reportFQN.Findings[0].CryptographicAssets[0].Metadata["api"]; got != pythonFQNApi {
			t.Errorf("synthesized api = %q, want %q", got, pythonFQNApi)
		}
	}

	// Case 2: Short api (1 dot) under ecosystem="" — stdlib/hashlib style must NOT synthesize.
	const shortAPI = "hashlib.sha256"
	dirShort := t.TempDir()
	ruleShort := writeRule(t, dirShort, shortAPI, "SHA-2")

	hashlibSHA256Decl := &callgraph.FunctionDecl{
		ID: callgraph.FunctionID{
			Package: "hashlib",
			Name:    "sha256",
		},
		FilePath:  "hashlib/__init__.py",
		StartLine: 200,
		EndLine:   205,
	}

	reportShort := &entities.InterimReport{}
	if n2 := SynthesizeRuleCryptoEntryPoints(reportShort, graphWith(hashlibSHA256Decl), []string{ruleShort}, ""); n2 != 0 {
		t.Errorf("short api (%q): expected 0 synthesized entry points (fails >= 2-dot gate under java/default ecosystem), got %d", shortAPI, n2)
	}
}

// ── Batch 6: Ecosystem-aware gate (Python >= 1 dot, Java >= 2 dots) ──────────

// TestSynthesize_Python_OneDotApiPasses asserts that a 1-dot api like
// "bcrypt.hashpw" PASSES the gate under ecosystem="python" and produces a
// synthetic entry point when the function is defined in the callgraph.
func TestSynthesize_Python_OneDotApiPasses(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		api  string
		name string
	}{
		{"bcrypt.hashpw", "bcrypt-hashpw"},
		{"jwt.encode", "jwt-encode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			rule := writeRule(t, dir, tc.api, "bcrypt")
			decl := &callgraph.FunctionDecl{
				ID: callgraph.FunctionID{
					Package: strings.Split(tc.api, ".")[0],
					Name:    strings.Split(tc.api, ".")[1],
				},
				FilePath:  strings.Split(tc.api, ".")[0] + "/__init__.py",
				StartLine: 50,
				EndLine:   60,
			}
			report := &entities.InterimReport{}
			n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, "python")
			if n != 1 {
				t.Errorf("api=%q (Python, 1-dot): expected 1 synthesized entry point, got %d", tc.api, n)
			}
		})
	}
}

// TestSynthesize_Python_ZeroDotBareNameFails asserts that a 0-dot bare name like
// "hashpw" (no dots) FAILS the gate even under ecosystem="python".
func TestSynthesize_Python_ZeroDotBareNameFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rule := writeRule(t, dir, "hashpw", "bcrypt")
	decl := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Name: "hashpw"},
		FilePath:  "bcrypt/__init__.py",
		StartLine: 50,
		EndLine:   60,
	}
	report := &entities.InterimReport{}
	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, "python"); n != 0 {
		t.Errorf("0-dot bare name under Python: expected 0 synthesized entry points, got %d", n)
	}
}

// TestSynthesize_Java_OneDotApiStillFails asserts that a 1-dot api like
// "Cipher.getInstance" FAILS the gate under ecosystem="java" (and "") — no regression.
func TestSynthesize_Java_OneDotApiStillFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rule := writeRule(t, dir, "Cipher.getInstance", "AES")
	decl := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Type: "Cipher", Name: "getInstance"},
		FilePath:  "Cipher.java",
		StartLine: 10,
		EndLine:   20,
	}
	report := &entities.InterimReport{}
	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, "java"); n != 0 {
		t.Errorf("1-dot api under Java: expected 0 synthesized entry points, got %d", n)
	}
	// Also verify with empty ecosystem (default Java behavior).
	report2 := &entities.InterimReport{}
	if n := SynthesizeRuleCryptoEntryPoints(report2, graphWith(decl), []string{rule}, ""); n != 0 {
		t.Errorf("1-dot api under default ecosystem: expected 0 synthesized entry points, got %d", n)
	}
}

// TestSynthesize_Java_TwoPlusDotsStillPasses asserts that a Java >= 2-dot api like
// "com.password4j.HashBuilder.withBcrypt" still passes under ecosystem="java" — no regression.
func TestSynthesize_Java_TwoPlusDotsStillPasses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rule := writeRule(t, dir, "com.password4j.HashBuilder.withBcrypt", "bcrypt")
	decl := &callgraph.FunctionDecl{
		ID: callgraph.FunctionID{
			Package: "com.password4j",
			Type:    "HashBuilder",
			Name:    "withBcrypt",
		},
		FilePath:  "src/main/java/com/password4j/HashBuilder.java",
		StartLine: 42,
		EndLine:   55,
	}
	report := &entities.InterimReport{}
	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, "java"); n != 1 {
		t.Errorf("2+-dot api under Java: expected 1 synthesized entry point, got %d", n)
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

	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, ""); n != 0 {
		t.Fatalf("expected 0 synthesized findings when body already detected, got %d", n)
	}
}
