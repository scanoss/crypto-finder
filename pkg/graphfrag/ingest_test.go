// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestDecodeFragment_MapsResolutionMetadata proves the ingestion adapter maps
// crypto-finder's graph-fragment export JSON (including the resolution fields)
// onto graphfrag.Fragment, so the stitch policy receives real classifications
// rather than the fail-closed zero value.
func TestDecodeFragment_MapsResolutionMetadata(t *testing.T) {
	const fragmentJSON = `{
	  "schema_version": "graph-fragment-1.0",
	  "scan_metadata": { "ecosystem": "java", "root_module": "org.bridge:b-bridge" },
	  "functions": [
	    { "key": "org.bridge.(Bridge).bridge#0", "file_path": "Bridge.java" },
	    { "key": "org.bridge.(Bridge).helper#0", "file_path": "Bridge.java" }
	  ],
	  "internal_edges": [
	    {
	      "caller_key": "org.bridge.(Bridge).bridge#0",
	      "callee_key": "org.bridge.(Bridge).helper#0",
	      "line": 5,
	      "resolution": "exact"
	    }
	  ],
	  "external_calls": [
	    {
	      "caller_key": "org.bridge.(Bridge).bridge#0",
	      "target_key": "net.crypto.(Sink).encrypt#1",
	      "line": 6,
	      "resolution": "interface_dispatch",
	      "declared_type": "net.crypto.Provider",
	      "method_name": "encrypt",
	      "arity": 1
	    }
	  ],
	  "crypto_annotations": [
	    {
	      "function_key": "org.bridge.(Bridge).helper#0",
	      "finding_id": "abc123",
	      "rule_id": "java.crypto.cipher.getinstance",
	      "symbol": "javax.crypto.Cipher.getInstance"
	    }
	  ]
	}`

	component := ComponentKey{Purl: "pkg:maven/org.bridge/b-bridge", Version: "1.0.0"}
	frag, err := DecodeFragment(component, []byte(fragmentJSON))
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	if frag.Component != component {
		t.Fatalf("Component = %#v, want %#v", frag.Component, component)
	}
	if len(frag.Functions) != 2 || frag.Functions[0].Signature != "org.bridge.(Bridge).bridge#0" {
		t.Fatalf("Functions = %#v", frag.Functions)
	}
	if len(frag.InternalEdges) != 1 {
		t.Fatalf("InternalEdges len = %d, want 1", len(frag.InternalEdges))
	}
	ie := frag.InternalEdges[0]
	if ie.Resolution != ResolutionExact || ie.CallSite != 5 {
		t.Fatalf("internal edge = %#v, want exact at line 5", ie)
	}
	if len(frag.ExternalCalls) != 1 {
		t.Fatalf("ExternalCalls len = %d, want 1", len(frag.ExternalCalls))
	}
	ec := frag.ExternalCalls[0]
	if ec.TargetSignature != "net.crypto.(Sink).encrypt#1" {
		t.Fatalf("external target = %q", ec.TargetSignature)
	}
	if ec.Resolution != ResolutionInterfaceDispatch || ec.DeclaredType != "net.crypto.Provider" || ec.MethodName != "encrypt" || ec.Arity != 1 || ec.CallSite != 6 {
		t.Fatalf("external edge metadata = %#v", ec)
	}
	if len(frag.CryptoOperations) != 1 || frag.CryptoOperations[0].FindingID != "abc123" {
		t.Fatalf("CryptoOperations = %#v", frag.CryptoOperations)
	}
}

// TestDecodeFragment_UnknownResolutionFromLegacyFragment proves an old fragment
// (exported before the resolution fields existed) decodes to ResolutionUnknown,
// which the stitcher fails closed on — safe under-reporting, never a false
// positive.
func TestDecodeFragment_UnknownResolutionFromLegacyFragment(t *testing.T) {
	const legacy = `{
	  "schema_version": "graph-fragment-1.0",
	  "functions": [{ "key": "a.(A).f#0" }],
	  "external_calls": [{ "caller_key": "a.(A).f#0", "target_key": "b.(B).g#0" }]
	}`

	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/a/a", Version: "1"}, []byte(legacy))
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if len(frag.ExternalCalls) != 1 || frag.ExternalCalls[0].Resolution != ResolutionUnknown {
		t.Fatalf("legacy external edge resolution = %#v, want ResolutionUnknown", frag.ExternalCalls)
	}
}

// TestDecodeFragment_MapsRoleFields proves the ingestion adapter maps
// issue-103's method_role/role_provenance/parameter_roles fields from a
// crypto_entry_points fragment entry onto the decoded CryptoEntryPoint, and
// parameter_roles from a supporting_calls entry's supporting_call onto the
// decoded CryptoCall — the plumbing WU2/WU3 need to carry these fields
// through the fragment round-trip to the stitch/served path.
func TestDecodeFragment_MapsRoleFields(t *testing.T) {
	const fragmentJSON = `{
	  "schema_version": "graph-fragment-1.6",
	  "functions": [{ "key": "org.bc.(AESEngine).processBlock#4" }],
	  "crypto_entry_points": [
	    {
	      "function_key": "org.bc.(AESEngine).processBlock#4",
	      "method": "processBlock",
	      "method_role": "operation",
	      "role_provenance": {
	        "kind": "contract-operation-inherited",
	        "contract_method": "org.bouncycastle.crypto.BlockCipher.processBlock",
	        "inherited_from": "org.bc.AESEngine.<init>",
	        "inherited": { "algorithm_family": "AES", "primitive": "block-cipher" }
	      },
	      "parameter_roles": [
	        { "index": 0, "role": "operation-determining" }
	      ]
	    }
	  ],
	  "supporting_calls": [
	    {
	      "supporting_id": "sup1",
	      "function_key": "org.pkg.(Svc).run#0",
	      "supporting_call": {
	        "function_name": "org.bc.KeyParameter.<init>",
	        "parameter_roles": [
	          {
	            "index": 0,
	            "name": "key",
	            "role": "metadata-contributing",
	            "contributes": { "property": "keySize", "derivation": "argument_bit_length" }
	          }
	        ]
	      }
	    }
	  ]
	}`

	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/bc/bc", Version: "1"}, []byte(fragmentJSON))
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	if len(frag.CryptoEntryPoints) != 1 {
		t.Fatalf("CryptoEntryPoints = %#v, want 1", frag.CryptoEntryPoints)
	}
	ep := frag.CryptoEntryPoints[0]
	if ep.MethodRole != "operation" {
		t.Fatalf("MethodRole = %q, want operation", ep.MethodRole)
	}
	if ep.RoleProvenance == nil || ep.RoleProvenance.Kind != "contract-operation-inherited" ||
		ep.RoleProvenance.Inherited == nil || ep.RoleProvenance.Inherited.AlgorithmFamily != "AES" ||
		ep.RoleProvenance.Inherited.Primitive != "block-cipher" {
		t.Fatalf("RoleProvenance = %#v, want kind=contract-operation-inherited inherited={AES,block-cipher}", ep.RoleProvenance)
	}
	if len(ep.ParameterRoles) != 1 || ep.ParameterRoles[0].Role != "operation-determining" {
		t.Fatalf("ParameterRoles = %#v, want 1 entry role=operation-determining", ep.ParameterRoles)
	}

	if len(frag.SupportingCalls) != 1 || frag.SupportingCalls[0].SupportingCall == nil {
		t.Fatalf("SupportingCalls = %#v, want 1 with SupportingCall set", frag.SupportingCalls)
	}
	sc := frag.SupportingCalls[0].SupportingCall
	if len(sc.ParameterRoles) != 1 {
		t.Fatalf("SupportingCall.ParameterRoles = %#v, want 1 entry", sc.ParameterRoles)
	}
	pr := sc.ParameterRoles[0]
	if pr.Index != 0 || pr.Name != "key" || pr.Role != "metadata-contributing" ||
		pr.Contributes == nil || pr.Contributes.Property != "keySize" || pr.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("SupportingCall.ParameterRoles[0] = %#v, want index=0 key metadata-contributing keySize/argument_bit_length", pr)
	}
}

// TestDecodeFragment_LegacyFragment_NoRoleFields proves a fragment exported
// before issue-103 (no method_role/role_provenance/parameter_roles) decodes
// with nil/empty values for the new fields — safe structural-only
// degradation, matching the existing 1.0/1.1 precedent for CryptoCall/EntryCall.
func TestDecodeFragment_LegacyFragment_NoRoleFields(t *testing.T) {
	const legacy = `{
	  "schema_version": "graph-fragment-1.6",
	  "functions": [{ "key": "a.(A).f#0" }],
	  "crypto_entry_points": [
	    { "function_key": "a.(A).f#0", "method": "f" }
	  ]
	}`

	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/a/a", Version: "1"}, []byte(legacy))
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if len(frag.CryptoEntryPoints) != 1 {
		t.Fatalf("CryptoEntryPoints = %#v, want 1", frag.CryptoEntryPoints)
	}
	ep := frag.CryptoEntryPoints[0]
	if ep.MethodRole != "" || ep.RoleProvenance != nil || ep.ParameterRoles != nil {
		t.Fatalf("legacy entry point role fields = %#v, want all empty/nil", ep)
	}
}

func TestDecodeFragment_InvalidResolutionNormalized(t *testing.T) {
	const invalid = `{
	  "schema_version": "graph-fragment-1.1",
	  "functions": [{ "key": "a.(A).f#0" }],
	  "external_calls": [{
	    "caller_key": "a.(A).f#0",
	    "target_key": "b.(B).g#0",
	    "resolution": "typo"
	  }]
	}`

	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/a/a", Version: "1"}, []byte(invalid))
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if len(frag.ExternalCalls) != 1 || frag.ExternalCalls[0].Resolution != ResolutionUnknown {
		t.Fatalf("invalid external edge resolution = %#v, want ResolutionUnknown", frag.ExternalCalls)
	}
}

// TestStitch_EndToEnd_BouncyCastleFalsePositiveKilled reproduces the handover's
// real finding through the full producer-schema -> adapter -> stitch path:
//
//   - The REAL path: root.decryptPrivateKey -> bcpkix.decryptPrivateKeyInfo
//     --exact--> bcprov.EncryptedPrivateKeyInfo.getEncryptedData (a true marker).
//   - The BOGUS path: bcpkix.decryptPrivateKeyInfo --name_only(get#1)-->
//     bcprov.SP800SecureRandomBuilder.get --exact--> bcprov.BCrypt.generate.
//     The get() edge is an over-broad name+arity dispatch guess; crypto-finder's
//     fluent fallback fabricated it. It must NOT carry reachability into BCrypt.
//
// Expectation matches the handover's conclusion exactly: the BCrypt marker is
// unreachable (false positive killed) while the getEncryptedData marker still
// stitches (true positive preserved).
func TestStitch_EndToEnd_BouncyCastleFalsePositiveKilled(t *testing.T) {
	root := ComponentKey{Purl: "pkg:maven/com.mastercard.developer/client-encryption-java", Version: "1.6.0"}
	bcpkix := ComponentKey{Purl: "pkg:maven/org.bouncycastle/bcpkix-jdk18on", Version: "1.78.1"}
	bcprov := ComponentKey{Purl: "pkg:maven/org.bouncycastle/bcprov-jdk18on", Version: "1.78.1"}

	rootJSON := `{
	  "schema_version": "graph-fragment-1.0",
	  "functions": [{ "key": "com.mastercard.developer.crypto.thirdparty.(BouncyCastlePkixCrypto).decryptPrivateKey#2" }],
	  "external_calls": [{
	    "caller_key": "com.mastercard.developer.crypto.thirdparty.(BouncyCastlePkixCrypto).decryptPrivateKey#2",
	    "target_key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1",
	    "resolution": "exact", "line": 42
	  }]
	}`

	bcpkixJSON := `{
	  "schema_version": "graph-fragment-1.0",
	  "functions": [{ "key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1" }],
	  "external_calls": [
	    {
	      "caller_key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1",
	      "target_key": "org.bouncycastle.crypto.prng.(SP800SecureRandomBuilder).get#1",
	      "resolution": "name_only", "method_name": "get", "arity": 1, "line": 88
	    },
	    {
	      "caller_key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1",
	      "target_key": "org.bouncycastle.asn1.pkcs.(EncryptedPrivateKeyInfo).getEncryptedData#0",
	      "resolution": "exact", "line": 90
	    }
	  ]
	}`

	bcprovJSON := `{
	  "schema_version": "graph-fragment-1.0",
	  "functions": [
	    { "key": "org.bouncycastle.crypto.prng.(SP800SecureRandomBuilder).get#1" },
	    { "key": "org.bouncycastle.crypto.generators.(BCrypt).generate#3" },
	    { "key": "org.bouncycastle.asn1.pkcs.(EncryptedPrivateKeyInfo).getEncryptedData#0" }
	  ],
	  "internal_edges": [{
	    "caller_key": "org.bouncycastle.crypto.prng.(SP800SecureRandomBuilder).get#1",
	    "callee_key": "org.bouncycastle.crypto.generators.(BCrypt).generate#3",
	    "resolution": "exact", "line": 120
	  }],
	  "crypto_annotations": [
	    { "function_key": "org.bouncycastle.crypto.generators.(BCrypt).generate#3", "finding_id": "bogus-bcrypt", "symbol": "BCrypt.generate" },
	    { "function_key": "org.bouncycastle.asn1.pkcs.(EncryptedPrivateKeyInfo).getEncryptedData#0", "finding_id": "real-getencrypteddata", "symbol": "getEncryptedData" }
	  ]
	}`

	fragments := map[ComponentKey]Fragment{}
	for ck, raw := range map[ComponentKey]string{root: rootJSON, bcpkix: bcpkixJSON, bcprov: bcprovJSON} {
		frag, err := DecodeFragment(ck, []byte(raw))
		if err != nil {
			t.Fatalf("DecodeFragment(%s): %v", ck, err)
		}
		fragments[ck] = frag
	}

	deps := DependencyGraph{
		root:   {bcpkix},
		bcpkix: {bcprov},
	}

	res, err := Stitch(root, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}

	reached := map[string]bool{}
	for _, ch := range res.Chains {
		reached[ch.FindingID] = true
	}
	if reached["bogus-bcrypt"] {
		t.Fatalf("BCrypt false positive was NOT killed: %#v", res.Chains)
	}
	if !reached["real-getencrypteddata"] {
		t.Fatalf("true-positive getEncryptedData path was lost; chains = %#v", res.Chains)
	}

	var sawNameOnlyGet bool
	for _, s := range res.Suppressed {
		if s.Reason == SuppressReasonNameOnly && s.MethodName == "get" {
			sawNameOnlyGet = true
		}
	}
	if !sawNameOnlyGet {
		t.Fatalf("expected the over-broad get() edge to be recorded as suppressed name_only: %#v", res.Suppressed)
	}
}
