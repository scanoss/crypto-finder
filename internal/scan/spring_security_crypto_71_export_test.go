// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// TestBuildGraphFragmentExport_Issue182SpringSecurityCrypto71EncoderLifecycle is
// the scanoss/crypto-finder#182 E2E acceptance test: it proves the new
// spring-security-crypto-7.1.yaml contracts resolve end to end through the
// same export path Issue #137's RsaSecretEncryptor test
// (spring_lifecycle_export_test.go) exercises, for the three encoder-surface
// shapes this ticket adds:
//
//  1. A Password4j-backed encoder (BcryptPassword4jPasswordEncoder) is
//     constructed (factory) and its encode()/matches() calls resolve to
//     role "operation" PURELY via the BcryptPassword4jPasswordEncoder ->
//     PasswordEncoder hierarchy edge -- no per-class encode/matches contract
//     is authored in spring-security-crypto-7.1.yaml, so this is the decisive
//     proof the "prefer the shared interface" authoring rule actually holds
//     for the new password4j classes, not just an assertion in the YAML
//     audit comment.
//  2. The hand-rolled BCrypt static terminal: hashpw(raw, gensalt()) mirrors
//     the real call shape from spring-security-crypto's own
//     BCryptPasswordEncoder.encode() (and the crypto_rules#162 fixture) --
//     gensalt() is a supporting call (role: factory) feeding hashpw() (role:
//     operation), and checkpw() is a separate operation call.
//  3. Encryptors.delux(...) (factory) returns a TextEncryptor whose
//     encrypt()/decrypt() calls resolve to role "operation" via the
//     pre-existing TextEncryptor contract in spring-security-crypto.yaml
//     (6.3.4) -- proving the new file's hierarchy edge alone is sufficient,
//     without redeclaring TextEncryptor.encrypt/decrypt.
func TestBuildGraphFragmentExport_Issue182SpringSecurityCrypto71EncoderLifecycle(t *testing.T) {
	t.Parallel()

	const (
		pkgPassword4j = "org.springframework.security.crypto.password4j"
		pkgBcrypt     = "org.springframework.security.crypto.bcrypt"
		pkgEncrypt    = "org.springframework.security.crypto.encrypt"
	)

	ownerID := callgraph.FunctionID{Package: "com.acme", Type: "Secrets", Name: "roundTrip#0"}

	// 1. Password4j-backed encoder: construct + encode + matches.
	p4jFactoryID := callgraph.FunctionID{Package: pkgPassword4j, Type: "BcryptPassword4jPasswordEncoder", Name: "<init>#0"}
	p4jEncodeID := callgraph.FunctionID{Package: pkgPassword4j, Type: "BcryptPassword4jPasswordEncoder", Name: "encode#1"}
	p4jMatchesID := callgraph.FunctionID{Package: pkgPassword4j, Type: "BcryptPassword4jPasswordEncoder", Name: "matches#2"}

	// 2. Hand-rolled BCrypt: hashpw(raw, gensalt()) + checkpw(raw, hashed).
	bcryptHashpwID := callgraph.FunctionID{Package: pkgBcrypt, Type: "BCrypt", Name: "hashpw#2"}
	bcryptGensaltID := callgraph.FunctionID{Package: pkgBcrypt, Type: "BCrypt", Name: "gensalt#0"}
	bcryptCheckpwID := callgraph.FunctionID{Package: pkgBcrypt, Type: "BCrypt", Name: "checkpw#2"}

	// 3. Encryptors.delux(...) -> TextEncryptor.encrypt/decrypt.
	deluxFactoryID := callgraph.FunctionID{Package: pkgEncrypt, Type: "Encryptors", Name: "delux#2"}
	deluxEncryptID := callgraph.FunctionID{Package: pkgEncrypt, Type: "TextEncryptor", Name: "encrypt#1"}
	deluxDecryptID := callgraph.FunctionID{Package: pkgEncrypt, Type: "TextEncryptor", Name: "decrypt#1"}

	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		ownerID.String(): {
			ID:        ownerID,
			FilePath:  "Secrets.java",
			StartLine: 1,
			EndLine:   12,
			Calls: []callgraph.FunctionCall{
				{Callee: p4jFactoryID, FilePath: "Secrets.java", Line: 3, Raw: "new BcryptPassword4jPasswordEncoder()", AssignedVar: "encoder"},
				{Callee: p4jEncodeID, FilePath: "Secrets.java", Line: 4, Raw: "encoder.encode(raw)", ReceiverVar: "encoder"},
				{Callee: p4jMatchesID, FilePath: "Secrets.java", Line: 5, Raw: "encoder.matches(raw, hashed)", ReceiverVar: "encoder"},
				{Callee: bcryptGensaltID, FilePath: "Secrets.java", Line: 6, Raw: "BCrypt.gensalt()"},
				{Callee: bcryptHashpwID, FilePath: "Secrets.java", Line: 6, Raw: "BCrypt.hashpw(raw, BCrypt.gensalt())"},
				{Callee: bcryptCheckpwID, FilePath: "Secrets.java", Line: 7, Raw: "BCrypt.checkpw(raw, hashed)"},
				{Callee: deluxFactoryID, FilePath: "Secrets.java", Line: 8, Raw: "Encryptors.delux(password, salt)", AssignedVar: "textEncryptor"},
				{Callee: deluxEncryptID, FilePath: "Secrets.java", Line: 9, Raw: "textEncryptor.encrypt(text)", ReceiverVar: "textEncryptor"},
				{Callee: deluxDecryptID, FilePath: "Secrets.java", Line: 10, Raw: "textEncryptor.decrypt(text)", ReceiverVar: "textEncryptor"},
			},
		},
		p4jFactoryID.String():    {ID: p4jFactoryID, FilePath: "BcryptPassword4jPasswordEncoder.java", StartLine: 1, ReturnType: pkgPassword4j + ".BcryptPassword4jPasswordEncoder"},
		p4jEncodeID.String():     {ID: p4jEncodeID, FilePath: "BcryptPassword4jPasswordEncoder.java", StartLine: 2, ReturnType: "java.lang.String", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.CharSequence"}}},
		p4jMatchesID.String():    {ID: p4jMatchesID, FilePath: "BcryptPassword4jPasswordEncoder.java", StartLine: 3, ReturnType: "boolean", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.CharSequence"}, {Type: "java.lang.String"}}},
		bcryptHashpwID.String():  {ID: bcryptHashpwID, FilePath: "BCrypt.java", StartLine: 1, ReturnType: "java.lang.String", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}, {Type: "java.lang.String"}}},
		bcryptGensaltID.String(): {ID: bcryptGensaltID, FilePath: "BCrypt.java", StartLine: 2, ReturnType: "java.lang.String"},
		bcryptCheckpwID.String(): {ID: bcryptCheckpwID, FilePath: "BCrypt.java", StartLine: 3, ReturnType: "boolean", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}, {Type: "java.lang.String"}}},
		deluxFactoryID.String():  {ID: deluxFactoryID, FilePath: "Encryptors.java", StartLine: 1, ReturnType: pkgEncrypt + ".TextEncryptor", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.CharSequence"}, {Type: "java.lang.CharSequence"}}},
		deluxEncryptID.String():  {ID: deluxEncryptID, FilePath: "Encryptors.java", StartLine: 2, ReturnType: "java.lang.String", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
		deluxDecryptID.String():  {ID: deluxDecryptID, FilePath: "Encryptors.java", StartLine: 3, ReturnType: "java.lang.String", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
	}}

	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "Secrets.java",
		Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{
			{
				FindingID: "p4j-bcrypt-encoder",
				StartLine: 3,
				EndLine:   3,
				Match:     "new BcryptPassword4jPasswordEncoder()",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkgPassword4j + ".BcryptPassword4jPasswordEncoder.<init>",
					"assetType": "algorithm",
				},
			},
			{
				FindingID: "bcrypt-handrolled-hash",
				StartLine: 6,
				EndLine:   6,
				Match:     "BCrypt.hashpw(raw, BCrypt.gensalt())",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkgBcrypt + ".BCrypt.hashpw",
					"assetType": "algorithm",
				},
			},
			{
				FindingID: "encryptors-delux",
				StartLine: 8,
				EndLine:   8,
				Match:     "Encryptors.delux(password, salt)",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkgEncrypt + ".Encryptors.delux",
					"assetType": "algorithm",
				},
			},
		},
	}}}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.CryptoAnnotations) != 3 {
		t.Fatalf("crypto_annotations = %#v, want 3 findings", payload.CryptoAnnotations)
	}

	categoryByFunction := map[string]string{}
	for _, support := range payload.SupportingCalls {
		if support.SupportingCall != nil {
			categoryByFunction[support.SupportingCall.FunctionName] = support.Category
		}
	}

	// (1) Password4j encoder: encode/matches resolve to "operation" purely via
	// the BcryptPassword4jPasswordEncoder -> PasswordEncoder hierarchy edge --
	// no per-class contract is authored for these two methods.
	wantOperation := []string{
		pkgPassword4j + ".BcryptPassword4jPasswordEncoder.encode",
		pkgPassword4j + ".BcryptPassword4jPasswordEncoder.matches",
		// (2) hand-rolled BCrypt: hashpw/checkpw are the operations.
		pkgBcrypt + ".BCrypt.hashpw",
		pkgBcrypt + ".BCrypt.checkpw",
		// (3) TextEncryptor returned by Encryptors.delux.
		pkgEncrypt + ".TextEncryptor.encrypt",
		pkgEncrypt + ".TextEncryptor.decrypt",
	}
	for _, name := range wantOperation {
		if categoryByFunction[name] != "operation" {
			t.Errorf("%s category = %q, want operation; supporting_calls = %#v", name, categoryByFunction[name], payload.SupportingCalls)
		}
	}

	// gensalt() is a supporting factory call (creates the salt material fed
	// into hashpw()), distinct from the operation calls above.
	if got := categoryByFunction[pkgBcrypt+".BCrypt.gensalt"]; got != "factory" {
		t.Errorf("BCrypt.gensalt category = %q, want factory; supporting_calls = %#v", got, payload.SupportingCalls)
	}

	if len(payload.CryptoAnnotations[0].SupportingCallIDs) < 1 {
		t.Fatalf("p4j-bcrypt-encoder supporting_call_ids = %#v, want at least encode/matches", payload.CryptoAnnotations[0].SupportingCallIDs)
	}
}
