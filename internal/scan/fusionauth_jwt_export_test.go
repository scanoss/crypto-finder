// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// FusionAuth JWT authors sign and verify once, on its Signer and Verifier
// interfaces. This proves the concrete HMACVerifier.verify and RSASigner.sign
// declarations reach the export as operation supporting calls through the
// hierarchy edges alone, beside their factories.
func TestBuildGraphFragmentExport_FusionAuthJWTSignerVerifierLifecycle(t *testing.T) {
	t.Parallel()

	const (
		pkgHMAC = "io.fusionauth.jwt.hmac"
		pkgRSA  = "io.fusionauth.jwt.rsa"
	)

	ownerID := callgraph.FunctionID{Package: "com.acme", Type: "Tokens", Name: "roundTrip#0"}
	hmacFactoryID := callgraph.FunctionID{Package: pkgHMAC, Type: "HMACVerifier", Name: "newVerifier#1"}
	hmacVerifyID := callgraph.FunctionID{Package: pkgHMAC, Type: "HMACVerifier", Name: "verify#3"}
	rsaFactoryID := callgraph.FunctionID{Package: pkgRSA, Type: "RSASigner", Name: "newSHA256Signer#1"}
	rsaSignID := callgraph.FunctionID{Package: pkgRSA, Type: "RSASigner", Name: "sign#1"}

	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		ownerID.String(): {
			ID:        ownerID,
			FilePath:  "Tokens.java",
			StartLine: 1,
			EndLine:   8,
			Calls: []callgraph.FunctionCall{
				{Callee: hmacFactoryID, FilePath: "Tokens.java", Line: 3, Raw: "HMACVerifier.newVerifier(secret)", AssignedVar: "verifier"},
				{Callee: hmacVerifyID, FilePath: "Tokens.java", Line: 4, Raw: "verifier.verify(alg, message, signature)", ReceiverVar: "verifier"},
				{Callee: rsaFactoryID, FilePath: "Tokens.java", Line: 5, Raw: "RSASigner.newSHA256Signer(pem)", AssignedVar: "signer"},
				{Callee: rsaSignID, FilePath: "Tokens.java", Line: 6, Raw: "signer.sign(payload)", ReceiverVar: "signer"},
			},
		},
		hmacFactoryID.String(): {ID: hmacFactoryID, FilePath: "HMACVerifier.java", StartLine: 10, ReturnType: pkgHMAC + ".HMACVerifier", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
		hmacVerifyID.String():  {ID: hmacVerifyID, FilePath: "HMACVerifier.java", StartLine: 20, ReturnType: "void", Parameters: []callgraph.FunctionParameter{{Type: "io.fusionauth.jwt.domain.Algorithm"}, {Type: "byte[]"}, {Type: "byte[]"}}},
		rsaFactoryID.String():  {ID: rsaFactoryID, FilePath: "RSASigner.java", StartLine: 10, ReturnType: pkgRSA + ".RSASigner", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
		rsaSignID.String():     {ID: rsaSignID, FilePath: "RSASigner.java", StartLine: 20, ReturnType: "byte[]", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
	}}

	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "Tokens.java",
		Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{
			{
				FindingID: "hmac-verifier",
				StartLine: 3,
				EndLine:   3,
				Match:     "HMACVerifier.newVerifier(secret)",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata:  map[string]string{"api": pkgHMAC + ".HMACVerifier.newVerifier", "assetType": "algorithm"},
			},
			{
				FindingID: "rsa-signer",
				StartLine: 5,
				EndLine:   5,
				Match:     "RSASigner.newSHA256Signer(pem)",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata:  map[string]string{"api": pkgRSA + ".RSASigner.newSHA256Signer", "assetType": "algorithm"},
			},
		},
	}}}

	payload := buildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.CryptoAnnotations) != 2 {
		t.Fatalf("crypto_annotations = %#v, want 2", payload.CryptoAnnotations)
	}

	categoryByFunction := map[string]string{}
	for _, support := range payload.SupportingCalls {
		if support.SupportingCall != nil {
			categoryByFunction[support.SupportingCall.FunctionName] = support.Category
		}
	}
	for name, want := range map[string]string{
		pkgHMAC + ".HMACVerifier.newVerifier": "factory",
		pkgHMAC + ".HMACVerifier.verify":      "operation",
		pkgRSA + ".RSASigner.newSHA256Signer": "factory",
		pkgRSA + ".RSASigner.sign":            "operation",
	} {
		if got := categoryByFunction[name]; got != want {
			t.Errorf("%s category = %q, want %q; supporting_calls = %#v", name, got, want, payload.SupportingCalls)
		}
	}
	for _, annotation := range payload.CryptoAnnotations {
		if len(annotation.SupportingCallIDs) < 2 {
			t.Errorf("%s supporting_call_ids = %#v, want its factory and operation", annotation.FindingID, annotation.SupportingCallIDs)
		}
	}
}
