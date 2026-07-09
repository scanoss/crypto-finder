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
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
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

// aesEngineInitAPI is the shared api FQN used by the multi-crypto-function
// synthesis tests below, mirroring the real DCA rules
// java.bouncycastle.algorithm.block-cipher.aes-init-encrypt/aes-init-decrypt,
// which both carry api: org.bouncycastle.crypto.engines.AESEngine.init.
const aesEngineInitAPI = "org.bouncycastle.crypto.engines.AESEngine.init"

// writeRuleWithID writes an AES rule file for aesEngineInitAPI carrying one
// metadata.crypto block with an explicit rule id and operation. Used to
// construct multi-rule same-api scenarios (e.g. AESEngine.init shared by an
// encrypt rule and a decrypt rule) where the caller passes the shared dir
// (not the individual file path) to SynthesizeRuleCryptoEntryPoints.
func writeRuleWithID(t *testing.T, dir, filename, ruleID, operation string) {
	t.Helper()
	body := "" +
		"rules:\n" +
		"  - id: " + ruleID + "\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: block-cipher\n" +
		"        algorithmFamily: AES\n" +
		"        operation: " + operation + "\n" +
		"        api: " + aesEngineInitAPI + "\n"
	p := filepath.Join(dir, filename)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
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

func TestSynthesize_Python_PyiDeclSetsLanguage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rule := writeRule(t, dir, "bcrypt.hashpw", "bcrypt")
	decl := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "bcrypt", Name: "hashpw"},
		FilePath:  "bcrypt/__init__.pyi",
		StartLine: 5,
		EndLine:   5,
	}
	report := &entities.InterimReport{}
	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, "python"); n != 1 {
		t.Fatalf("expected 1 synthesized entry point, got %d", n)
	}
	if got := report.Findings[0].Language; got != "python" {
		t.Fatalf("Language = %q, want python", got)
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

func TestSynthesize_DrbgFindingDoesNotSuppressBoundaryAsset(t *testing.T) {
	dir := t.TempDir()
	rule := writeRule(t, dir, "argon2.PasswordHasher.hash", "Argon2")
	decl := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "argon2", Type: "PasswordHasher", Name: "hash"},
		FilePath:  "argon2/_password_hasher.py",
		StartLine: 190,
		EndLine:   205,
	}
	report := &entities.InterimReport{
		Findings: []entities.Finding{{
			FilePath: decl.FilePath,
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 201,
				Metadata: map[string]string{
					"algorithmPrimitive": "drbg",
					"api":                "urandom",
				},
			}},
		}},
	}

	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, "python"); n != 1 {
		t.Fatalf("expected boundary asset despite supporting drbg finding, got %d", n)
	}
	if got := len(report.Findings[0].CryptographicAssets); got != 2 {
		t.Fatalf("assets len = %d, want drbg + synthesized KDF", got)
	}
}

func TestSynthesize_UnresolvedAlgorithmNameFallsBackToFamily(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(rule, []byte(""+
		"rules:\n"+
		"  - id: test.rule\n"+
		"    metadata:\n"+
		"      crypto:\n"+
		"        assetType: algorithm\n"+
		"        algorithmPrimitive: kdf\n"+
		"        algorithmFamily: Argon2\n"+
		"        algorithmName: Argon2$variant\n"+
		"        algorithmParameterSetIdentifier: $variant\n"+
		"        operation: keyderive\n"+
		"        api: argon2.low_level.hash_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decl := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "argon2.low_level", Name: "hash_secret"},
		FilePath:  "argon2/low_level.py",
		StartLine: 52,
		EndLine:   80,
	}
	report := &entities.InterimReport{}

	if n := SynthesizeRuleCryptoEntryPoints(report, graphWith(decl), []string{rule}, "python"); n != 1 {
		t.Fatalf("expected generic synthetic finding, got %d", n)
	}
	asset := report.Findings[0].CryptographicAssets[0]
	// algorithmName templated from an unbound caller arg ($variant) is unknowable
	// at the definition site, so it falls back to the family instead of vanishing.
	if asset.Metadata["algorithmName"] != "Argon2" {
		t.Fatalf("expected algorithmName to fall back to family %q, got %q", "Argon2", asset.Metadata["algorithmName"])
	}
	if asset.Metadata["algorithmFamily"] != "Argon2" {
		t.Fatalf("expected stable algorithmFamily to be preserved, got %q", asset.Metadata["algorithmFamily"])
	}
	// A non-name field with no family equivalent has no sensible fallback and is
	// still removed rather than left as a literal "$variant".
	if v, ok := asset.Metadata["algorithmParameterSetIdentifier"]; ok {
		t.Fatalf("expected unresolved algorithmParameterSetIdentifier to be removed, got %q", v)
	}
}

// ── Multi-crypto-function synthesis (shared api, different operation) ──────

// aesEngineInitDecl mimics org.bouncycastle.crypto.engines.AESEngine.init(...),
// the shared declaration site for both the encrypt and decrypt boundary rules.
func aesEngineInitDecl() *callgraph.FunctionDecl {
	return &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "org.bouncycastle.crypto.engines", Type: "AESEngine", Name: "init"},
		FilePath:  "org/bouncycastle/crypto/engines/AESEngine.java",
		StartLine: 70,
		EndLine:   90,
	}
}

// TestSynthesize_SharedAPIDifferentOperation_ProducesTwoAssets guards the DCA
// case where two rules (aes-init-encrypt / aes-init-decrypt) legitimately share
// one api (AESEngine.init) but carry different operation/cryptoFunction. Both
// must synthesize as separate assets at the same declaration site.
func TestSynthesize_SharedAPIDifferentOperation_ProducesTwoAssets(t *testing.T) {
	dir := t.TempDir()
	const api = aesEngineInitAPI
	writeRuleWithID(t, dir, "encrypt.yaml", "java.bouncycastle.algorithm.block-cipher.aes-init-encrypt", "encrypt")
	writeRuleWithID(t, dir, "decrypt.yaml", "java.bouncycastle.algorithm.block-cipher.aes-init-decrypt", "decrypt")

	report := &entities.InterimReport{}
	graph := graphWith(aesEngineInitDecl())

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{dir}, "")
	if n != 2 {
		t.Fatalf("expected 2 synthesized assets (encrypt + decrypt), got %d", n)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding (same file), got %d", len(report.Findings))
	}
	assets := report.Findings[0].CryptographicAssets
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets at the shared declaration site, got %d", len(assets))
	}

	ops := map[string]bool{}
	for _, a := range assets {
		if a.StartLine != 70 {
			t.Errorf("asset StartLine = %d, want 70 (method decl line)", a.StartLine)
		}
		if a.Metadata["api"] != api {
			t.Errorf("asset api = %q, want %q", a.Metadata["api"], api)
		}
		ops[a.Metadata["operation"]] = true
	}
	if !ops["encrypt"] || !ops["decrypt"] {
		t.Fatalf("expected one encrypt and one decrypt asset, got operations: %v", ops)
	}
}

// TestSynthesize_BackfillsCryptoFunctionFromOperation guards metadata parity
// with call-site matches: the semgrep transformer backfills cryptoFunction
// from operation (extractCryptoMetadata), and production DCA rules carry only
// `operation`. A synthetic asset must expose the same cryptoFunction key a
// real match of the same rule would have, or downstream consumers (dep-tree
// metadata readers) see the field missing on mined entry points only.
func TestSynthesize_BackfillsCryptoFunctionFromOperation(t *testing.T) {
	dir := t.TempDir()
	writeRuleWithID(t, dir, "encrypt.yaml", "java.bouncycastle.algorithm.block-cipher.aes-init-encrypt", "encrypt")

	report := &entities.InterimReport{}
	graph := graphWith(aesEngineInitDecl())

	if n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{dir}, ""); n != 1 {
		t.Fatalf("expected 1 synthesized asset, got %d", n)
	}
	md := report.Findings[0].CryptographicAssets[0].Metadata
	if md["cryptoFunction"] != "encrypt" {
		t.Fatalf("cryptoFunction = %q, want %q (backfilled from operation)", md["cryptoFunction"], "encrypt")
	}
}

// TestSynthesize_DuplicateRuleCryptoBlock_DedupesToOneAsset guards the case
// where the identical rule (same crypto block) is discovered twice (e.g. it
// appears verbatim in two rule files walked during indexing). Only one asset
// should synthesize — dedup keys off full metadata equality, not just api.
func TestSynthesize_DuplicateRuleCryptoBlock_DedupesToOneAsset(t *testing.T) {
	dir := t.TempDir()
	// Same rule id, same operation, same everything -- written to two files.
	writeRuleWithID(t, dir, "a.yaml", "java.bouncycastle.algorithm.block-cipher.aes-init-encrypt", "encrypt")
	writeRuleWithID(t, dir, "b.yaml", "java.bouncycastle.algorithm.block-cipher.aes-init-encrypt", "encrypt")

	report := &entities.InterimReport{}
	graph := graphWith(aesEngineInitDecl())

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{dir}, "")
	if n != 1 {
		t.Fatalf("expected 1 synthesized asset (identical block deduped), got %d", n)
	}
}

// TestSynthesize_SingleRuleAPI_Unchanged is a regression guard: a single rule
// per api must keep producing exactly one asset (no accidental fan-out from the
// map[string][]map[string]string refactor).
func TestSynthesize_SingleRuleAPI_Unchanged(t *testing.T) {
	dir := t.TempDir()
	rule := writeRule(t, dir, "com.example.Builder.withBcrypt", "bcrypt")
	report := &entities.InterimReport{}
	graph := graphWith(builderWithBcrypt())

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}, "")
	if n != 1 {
		t.Fatalf("expected 1 synthesized finding, got %d", n)
	}
}

// TestSynthesize_TerminalFinding_SuppressesBothSharedAPIBlocks guards ordering:
// when the method body already has a REAL detected primitive finding, BOTH
// shared-api blocks (encrypt and decrypt) must be suppressed -- and critically,
// the second block must be suppressed because of the REAL finding, not because
// the first synthetic sibling (added moments earlier) looks like a terminal
// finding to functionBodyHasTerminalFinding.
func TestSynthesize_TerminalFinding_SuppressesBothSharedAPIBlocks(t *testing.T) {
	dir := t.TempDir()
	writeRuleWithID(t, dir, "encrypt.yaml", "java.bouncycastle.algorithm.block-cipher.aes-init-encrypt", "encrypt")
	writeRuleWithID(t, dir, "decrypt.yaml", "java.bouncycastle.algorithm.block-cipher.aes-init-decrypt", "decrypt")

	decl := aesEngineInitDecl()
	report := &entities.InterimReport{
		Findings: []entities.Finding{{
			FilePath: decl.FilePath,
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 75, // inside [70,90]
				Metadata:  map[string]string{"algorithmPrimitive": "block-cipher", "algorithmFamily": "AES"},
			}},
		}},
	}
	graph := graphWith(decl)

	n := SynthesizeRuleCryptoEntryPoints(report, graph, []string{dir}, "")
	if n != 0 {
		t.Fatalf("expected 0 synthesized assets (method body already has a real finding), got %d", n)
	}
	// Only the original real finding should remain -- no synthetic siblings leaked in.
	if got := len(report.Findings[0].CryptographicAssets); got != 1 {
		t.Fatalf("expected exactly 1 asset (the original real finding), got %d", got)
	}
}

// TestBuildSyntheticAssetFromRule_ParameterConditions verifies the synthesis
// path parses metadata["parameterCondition"] into the structured
// ParameterConditions field, the same way the live-match transformer path
// does (see TestExtractCryptoMetadata_ParameterConditions).
func TestBuildSyntheticAssetFromRule_ParameterConditions(t *testing.T) {
	meta := map[string]string{
		"operation":          "encrypt",
		"parameterCondition": "param[0]==true",
		"assetType":          "algorithm",
	}
	fn := &callgraph.FunctionDecl{StartLine: 42, EndLine: 55}

	asset := buildSyntheticAssetFromRule("org.bouncycastle.crypto.engines.AESEngine.init", meta, fn)

	if len(asset.ParameterConditions) != 1 {
		t.Fatalf("ParameterConditions = %#v, want 1 entry", asset.ParameterConditions)
	}
	cond := asset.ParameterConditions[0]
	if cond.Raw != "param[0]==true" || cond.Value != "true" {
		t.Errorf("ParameterConditions[0] = %+v, want raw=param[0]==true value=true", cond)
	}
	if asset.Metadata["parameterCondition"] != "param[0]==true" {
		t.Errorf("Metadata[parameterCondition] = %q, want verbatim passthrough", asset.Metadata["parameterCondition"])
	}
}

// TestBuildSyntheticAssetFromRule_ParameterConditions_AntiDrift feeds the
// SAME raw parameterCondition through the synthesis path
// (buildSyntheticAssetFromRule) and the live-match transformer path
// (semgrep.TransformSemgrepCompatibleOutputToInterimFormat, which drives
// extractCryptoMetadata), asserting the two resulting []Condition slices are
// structurally identical. Both paths MUST call the same
// paramcondition.ParseAll entry point, or the two ingestion structures could
// drift apart for the same rule predicate (spec Req 5).
func TestBuildSyntheticAssetFromRule_ParameterConditions_AntiDrift(t *testing.T) {
	const raw = "param[0|forEncryption]~=^enc"

	meta := map[string]string{
		"operation":          "encrypt",
		"parameterCondition": raw,
	}
	fn := &callgraph.FunctionDecl{StartLine: 1, EndLine: 1}
	synthAsset := buildSyntheticAssetFromRule("org.bouncycastle.crypto.engines.AESEngine.init", meta, fn)

	semgrepOutput := &entities.SemgrepOutput{
		Results: []entities.SemgrepResult{{
			CheckID: "java.bouncycastle.algorithm.block-cipher.aes-init-encrypt",
			Path:    "AESEngine.java",
			Extra: entities.SemgrepExtra{
				Metadata: entities.SemgrepMetadata{
					Crypto: map[string]any{
						"operation":          "encrypt",
						"parameterCondition": raw,
					},
				},
			},
		}},
	}
	transformerReport := semgrep.TransformSemgrepCompatibleOutputToInterimFormat(
		semgrepOutput, entities.ToolInfo{}, ".", nil, true,
	)
	if len(transformerReport.Findings) != 1 || len(transformerReport.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("transformer report shape = %+v, want exactly 1 finding with 1 asset", transformerReport)
	}
	transformerAsset := transformerReport.Findings[0].CryptographicAssets[0]

	if !reflect.DeepEqual(synthAsset.ParameterConditions, transformerAsset.ParameterConditions) {
		t.Fatalf("synthesis and transformer paths diverged:\nsynthesis:   %+v\ntransformer: %+v",
			synthAsset.ParameterConditions, transformerAsset.ParameterConditions)
	}
}
