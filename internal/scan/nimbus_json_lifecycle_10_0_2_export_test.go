// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// TestBuildGraphFragmentExport_Issue184NimbusJoseJwt1002JSONLifecycle is the
// scanoss/crypto-finder#184 E2E acceptance test: it proves the new
// nimbus-jose-jwt-10.0.2.yaml contracts resolve end to end through the same
// export path Issue #137's RsaSecretEncryptor test
// (spring_lifecycle_export_test.go) and Issue #182's spring-security-crypto
// 7.1 test (spring_security_crypto_71_export_test.go) exercise, for a
// synthesized-entry-point finding anchored on JWSObjectJSON.<init> /
// JWEObjectJSON.<init>: construct (factory), sign/encrypt/decrypt
// (operation), the general/flattened serialisation methods (output), and
// parse (factory) all resolve through deriveContractSupportingCalls
// (internal/scan/export.go), which walks the contract KB by builder-type
// lineage rather than requiring an in-source call chain.
//
// Scope note: this test deliberately does NOT exercise
// JWSObjectJSON.Signature.verify/toJWSObject or JWEObjectJSON.Recipient
// (.<init>/.toJSONObject/.parse) through this export path. Those two nested
// value types are independent classes -- not builder-type-lineage
// descendants of JWSObjectJSON/JWEObjectJSON reachable via
// exportBuildContext.typeOrAncestor -- so deriveContractSupportingCalls's
// "one builder type + its return-type chain" heuristic does not attach them
// to a JWSObjectJSON.<init>/JWEObjectJSON.<init> finding, by design of that
// heuristic (it was built for single-class fluent builders like
// SslContextBuilder/HashBuilder, not independent bridging value types). Their
// return-type/role correctness is fully proven at the KB layer by
// TestLoadEmbeddedJava_NimbusJoseJwt1002JSONLifecycle
// (internal/callgraph/contracts/java_libraries_test.go), and the
// nimbus-jose-jwt-10.0.2.yaml audit comment records this export-layer
// heuristic mismatch explicitly rather than silently overstating export-path
// coverage.
func TestBuildGraphFragmentExport_Issue184NimbusJoseJwt1002JSONLifecycle(t *testing.T) {
	t.Parallel()

	const pkg = "com.nimbusds.jose"

	ownerID := callgraph.FunctionID{Package: "com.acme", Type: "Tokens", Name: "roundTrip#0"}

	// JWSObjectJSON: construct, sign, serializeGeneral, parse.
	jwsCtorID := callgraph.FunctionID{Package: pkg, Type: "JWSObjectJSON", Name: "<init>#1"}
	jwsSignID := callgraph.FunctionID{Package: pkg, Type: "JWSObjectJSON", Name: "sign#2"}
	jwsSerializeID := callgraph.FunctionID{Package: pkg, Type: "JWSObjectJSON", Name: "serializeGeneral#0"}
	jwsParseID := callgraph.FunctionID{Package: pkg, Type: "JWSObjectJSON", Name: "parse#1"}

	// JWEObjectJSON: construct, encrypt, decrypt, serializeGeneral, parse.
	jweCtorID := callgraph.FunctionID{Package: pkg, Type: "JWEObjectJSON", Name: "<init>#2"}
	jweEncryptID := callgraph.FunctionID{Package: pkg, Type: "JWEObjectJSON", Name: "encrypt#1"}
	jweDecryptID := callgraph.FunctionID{Package: pkg, Type: "JWEObjectJSON", Name: "decrypt#1"}
	jweSerializeID := callgraph.FunctionID{Package: pkg, Type: "JWEObjectJSON", Name: "serializeGeneral#0"}
	jweParseID := callgraph.FunctionID{Package: pkg, Type: "JWEObjectJSON", Name: "parse#1"}

	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		ownerID.String(): {
			ID:        ownerID,
			FilePath:  "Tokens.java",
			StartLine: 1,
			EndLine:   12,
			Calls: []callgraph.FunctionCall{
				{Callee: jwsCtorID, FilePath: "Tokens.java", Line: 3, Raw: "new JWSObjectJSON(payload)", AssignedVar: "jwsJson"},
				{Callee: jwsSignID, FilePath: "Tokens.java", Line: 4, Raw: "jwsJson.sign(header, signer)", ReceiverVar: "jwsJson"},
				{Callee: jwsSerializeID, FilePath: "Tokens.java", Line: 5, Raw: "jwsJson.serializeGeneral()", ReceiverVar: "jwsJson"},
				{Callee: jwsParseID, FilePath: "Tokens.java", Line: 6, Raw: "JWSObjectJSON.parse(json)", AssignedVar: "parsedJws"},

				{Callee: jweCtorID, FilePath: "Tokens.java", Line: 8, Raw: "new JWEObjectJSON(jweHeader, payload)", AssignedVar: "jweJson"},
				{Callee: jweEncryptID, FilePath: "Tokens.java", Line: 9, Raw: "jweJson.encrypt(encrypter)", ReceiverVar: "jweJson"},
				{Callee: jweDecryptID, FilePath: "Tokens.java", Line: 10, Raw: "jweJson.decrypt(decrypter)", ReceiverVar: "jweJson"},
				{Callee: jweSerializeID, FilePath: "Tokens.java", Line: 11, Raw: "jweJson.serializeGeneral()", ReceiverVar: "jweJson"},
				{Callee: jweParseID, FilePath: "Tokens.java", Line: 12, Raw: "JWEObjectJSON.parse(json)", AssignedVar: "parsedJwe"},
			},
		},
		jwsCtorID.String():      {ID: jwsCtorID, FilePath: "JWSObjectJSON.java", StartLine: 1, ReturnType: pkg + ".JWSObjectJSON", Parameters: []callgraph.FunctionParameter{{Type: pkg + ".Payload"}}},
		jwsSignID.String():      {ID: jwsSignID, FilePath: "JWSObjectJSON.java", StartLine: 2, ReturnType: "void", Parameters: []callgraph.FunctionParameter{{Type: pkg + ".JWSHeader"}, {Type: pkg + ".JWSSigner"}}},
		jwsSerializeID.String(): {ID: jwsSerializeID, FilePath: "JWSObjectJSON.java", StartLine: 3, ReturnType: "java.lang.String"},
		jwsParseID.String():     {ID: jwsParseID, FilePath: "JWSObjectJSON.java", StartLine: 4, ReturnType: pkg + ".JWSObjectJSON", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},

		jweCtorID.String():      {ID: jweCtorID, FilePath: "JWEObjectJSON.java", StartLine: 1, ReturnType: pkg + ".JWEObjectJSON", Parameters: []callgraph.FunctionParameter{{Type: pkg + ".JWEHeader"}, {Type: pkg + ".Payload"}}},
		jweEncryptID.String():   {ID: jweEncryptID, FilePath: "JWEObjectJSON.java", StartLine: 2, ReturnType: "void", Parameters: []callgraph.FunctionParameter{{Type: pkg + ".JWEEncrypter"}}},
		jweDecryptID.String():   {ID: jweDecryptID, FilePath: "JWEObjectJSON.java", StartLine: 3, ReturnType: "void", Parameters: []callgraph.FunctionParameter{{Type: pkg + ".JWEDecrypter"}}},
		jweSerializeID.String(): {ID: jweSerializeID, FilePath: "JWEObjectJSON.java", StartLine: 4, ReturnType: "java.lang.String"},
		jweParseID.String():     {ID: jweParseID, FilePath: "JWEObjectJSON.java", StartLine: 5, ReturnType: pkg + ".JWEObjectJSON", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
	}}

	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "Tokens.java",
		Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{
			{
				FindingID: "jws-json-construct",
				StartLine: 3,
				EndLine:   3,
				Match:     "new JWSObjectJSON(payload)",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkg + ".JWSObjectJSON.<init>",
					"assetType": "algorithm",
				},
			},
			{
				FindingID: "jwe-json-construct",
				StartLine: 8,
				EndLine:   8,
				Match:     "new JWEObjectJSON(jweHeader, payload)",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkg + ".JWEObjectJSON.<init>",
					"assetType": "algorithm",
				},
			},
		},
	}}}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.CryptoAnnotations) != 2 {
		t.Fatalf("crypto_annotations = %#v, want 2 findings", payload.CryptoAnnotations)
	}

	categoryByFunction := map[string]string{}
	for _, support := range payload.SupportingCalls {
		if support.SupportingCall != nil {
			categoryByFunction[support.SupportingCall.FunctionName] = support.Category
		}
	}

	wantOperation := []string{
		pkg + ".JWSObjectJSON.sign",
		pkg + ".JWEObjectJSON.encrypt",
		pkg + ".JWEObjectJSON.decrypt",
	}
	for _, name := range wantOperation {
		if categoryByFunction[name] != "operation" {
			t.Errorf("%s category = %q, want operation; supporting_calls = %#v", name, categoryByFunction[name], payload.SupportingCalls)
		}
	}

	wantOutput := []string{
		pkg + ".JWSObjectJSON.serializeGeneral",
		pkg + ".JWEObjectJSON.serializeGeneral",
	}
	for _, name := range wantOutput {
		if categoryByFunction[name] != "output" {
			t.Errorf("%s category = %q, want output; supporting_calls = %#v", name, categoryByFunction[name], payload.SupportingCalls)
		}
	}

	wantFactory := []string{
		pkg + ".JWSObjectJSON.parse",
		pkg + ".JWEObjectJSON.parse",
	}
	for _, name := range wantFactory {
		if categoryByFunction[name] != "factory" {
			t.Errorf("%s category = %q, want factory; supporting_calls = %#v", name, categoryByFunction[name], payload.SupportingCalls)
		}
	}

	for i, name := range []string{"jws-json-construct", "jwe-json-construct"} {
		if len(payload.CryptoAnnotations[i].SupportingCallIDs) < 1 {
			t.Errorf("%s supporting_call_ids = %#v, want at least one supporting call", name, payload.CryptoAnnotations[i].SupportingCallIDs)
		}
	}
}
