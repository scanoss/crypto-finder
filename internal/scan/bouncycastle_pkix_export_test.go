// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// TestBuildGraphFragmentExport_Issue185BouncyCastlePkixLifecycle is the
// scanoss/crypto-finder#185 E2E acceptance test: it proves the new
// bouncycastle-pkix.yaml contracts resolve end to end through the same
// export path issue #182's spring_security_crypto_71_export_test.go
// exercises, for the three bcpkix builder-lifecycle shapes this ticket adds:
//
//  1. X.509 certificate issuance via the JCA convenience subclass:
//     JcaX509v3CertificateBuilder is constructed (factory), then
//     addExtension(...) and build(ContentSigner) are called on it -- NEITHER
//     is overridden by JcaX509v3CertificateBuilder in bcpkix source, so both
//     must resolve to their "config"/"factory" roles PURELY via the
//     JcaX509v3CertificateBuilder -> X509v3CertificateBuilder hierarchy edge.
//     This is the decisive proof the "prefer the shared interface" authoring
//     rule (no addExtension/build contract duplicated on the Jca subclass)
//     actually holds, not just an assertion in the YAML audit comment.
//  2. The ContentSigner factory JcaContentSignerBuilder.build(PrivateKey)
//     feeds cert issuance's build(ContentSigner) call.
//  3. The two scanoss/crypto_rules protocol/cms/rules.yaml api anchors --
//     org.bouncycastle.cms.CMSSignedDataGenerator.<init> and
//     org.bouncycastle.cms.CMSEnvelopedDataGenerator.<init> -- each resolve
//     their full lifecycle (constructor factory, addSignerInfoGenerator/
//     addRecipientInfoGenerator config, generate() operation terminal
//     producing CMSSignedData/CMSEnvelopedData) so a real crypto_rules
//     finding on either constructor joins a complete supporting-call chain,
//     not just the bare constructor.
func TestBuildGraphFragmentExport_Issue185BouncyCastlePkixLifecycle(t *testing.T) {
	t.Parallel()

	const (
		pkgCertJcajce  = "org.bouncycastle.cert.jcajce"
		pkgOperatorJca = "org.bouncycastle.operator.jcajce"
		pkgCms         = "org.bouncycastle.cms"
	)

	ownerID := callgraph.FunctionID{Package: "com.acme.pki", Type: "Issuer", Name: "issueCertificate#0"}

	// 1. Cert issuance via the Jca convenience subclass: construct, then add an
	// extension and build -- NEITHER addExtension nor build is overridden by
	// JcaX509v3CertificateBuilder in bcpkix source, so their call sites resolve
	// to the base X509v3CertificateBuilder declaration (mirroring how a real
	// parser attributes an inherited, non-overridden method call to its
	// actual declaring class).
	certCtorID := callgraph.FunctionID{Package: pkgCertJcajce, Type: "JcaX509v3CertificateBuilder", Name: "<init>#6"}
	certAddExtID := callgraph.FunctionID{Package: "org.bouncycastle.cert", Type: "X509v3CertificateBuilder", Name: "addExtension#3"}
	certBuildID := callgraph.FunctionID{Package: "org.bouncycastle.cert", Type: "X509v3CertificateBuilder", Name: "build#1"}

	// 2. ContentSigner factory feeding cert issuance's build(ContentSigner).
	signerCtorID := callgraph.FunctionID{Package: pkgOperatorJca, Type: "JcaContentSignerBuilder", Name: "<init>#1"}
	signerBuildID := callgraph.FunctionID{Package: pkgOperatorJca, Type: "JcaContentSignerBuilder", Name: "build#1"}

	// 3a. CMSSignedDataGenerator: the crypto_rules cms.signature rule anchor.
	// addSignerInfoGenerator is declared on the shared CMSSignedGenerator base
	// (not overridden), same inherited-declaration reasoning as (1).
	cmsSignedCtorID := callgraph.FunctionID{Package: pkgCms, Type: "CMSSignedDataGenerator", Name: "<init>#0"}
	cmsAddSignerID := callgraph.FunctionID{Package: pkgCms, Type: "CMSSignedGenerator", Name: "addSignerInfoGenerator#1"}
	cmsSignedGenID := callgraph.FunctionID{Package: pkgCms, Type: "CMSSignedDataGenerator", Name: "generate#1"}

	// 3b. CMSEnvelopedDataGenerator: the crypto_rules cms.encryption rule
	// anchor. addRecipientInfoGenerator is declared on the shared
	// CMSEnvelopedGenerator base (not overridden).
	cmsEnvCtorID := callgraph.FunctionID{Package: pkgCms, Type: "CMSEnvelopedDataGenerator", Name: "<init>#0"}
	cmsAddRecipientID := callgraph.FunctionID{Package: pkgCms, Type: "CMSEnvelopedGenerator", Name: "addRecipientInfoGenerator#1"}
	cmsEnvGenID := callgraph.FunctionID{Package: pkgCms, Type: "CMSEnvelopedDataGenerator", Name: "generate#2"}

	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		ownerID.String(): {
			ID:        ownerID,
			FilePath:  "Issuer.java",
			StartLine: 1,
			EndLine:   14,
			Calls: []callgraph.FunctionCall{
				{Callee: certCtorID, FilePath: "Issuer.java", Line: 3, Raw: "new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey)", AssignedVar: "certBuilder"},
				{Callee: certAddExtID, FilePath: "Issuer.java", Line: 4, Raw: "certBuilder.addExtension(oid, true, value)", ReceiverVar: "certBuilder"},
				{Callee: signerCtorID, FilePath: "Issuer.java", Line: 5, Raw: "new JcaContentSignerBuilder(\"SHA256withRSA\")", AssignedVar: "signerBuilder"},
				{Callee: signerBuildID, FilePath: "Issuer.java", Line: 6, Raw: "signerBuilder.build(privateKey)", ReceiverVar: "signerBuilder", AssignedVar: "signer"},
				{Callee: certBuildID, FilePath: "Issuer.java", Line: 7, Raw: "certBuilder.build(signer)", ReceiverVar: "certBuilder"},
				{Callee: cmsSignedCtorID, FilePath: "Issuer.java", Line: 9, Raw: "new CMSSignedDataGenerator()", AssignedVar: "signedGen"},
				{Callee: cmsAddSignerID, FilePath: "Issuer.java", Line: 10, Raw: "signedGen.addSignerInfoGenerator(signerInfoGen)", ReceiverVar: "signedGen"},
				{Callee: cmsSignedGenID, FilePath: "Issuer.java", Line: 11, Raw: "signedGen.generate(content)", ReceiverVar: "signedGen"},
				{Callee: cmsEnvCtorID, FilePath: "Issuer.java", Line: 12, Raw: "new CMSEnvelopedDataGenerator()", AssignedVar: "envGen"},
				{Callee: cmsAddRecipientID, FilePath: "Issuer.java", Line: 13, Raw: "envGen.addRecipientInfoGenerator(recipientGen)", ReceiverVar: "envGen"},
				{Callee: cmsEnvGenID, FilePath: "Issuer.java", Line: 14, Raw: "envGen.generate(content, encryptor)", ReceiverVar: "envGen"},
			},
		},
		certCtorID.String():        {ID: certCtorID, FilePath: "JcaX509v3CertificateBuilder.java", StartLine: 1, ReturnType: pkgCertJcajce + ".JcaX509v3CertificateBuilder"},
		certAddExtID.String():      {ID: certAddExtID, FilePath: "X509v3CertificateBuilder.java", StartLine: 2, ReturnType: "org.bouncycastle.cert.X509v3CertificateBuilder", Parameters: []callgraph.FunctionParameter{{Type: "org.bouncycastle.asn1.ASN1ObjectIdentifier"}, {Type: "boolean"}, {Type: "org.bouncycastle.asn1.ASN1Encodable"}}},
		certBuildID.String():       {ID: certBuildID, FilePath: "X509v3CertificateBuilder.java", StartLine: 3, ReturnType: "org.bouncycastle.cert.X509CertificateHolder", Parameters: []callgraph.FunctionParameter{{Type: "org.bouncycastle.operator.ContentSigner"}}},
		signerCtorID.String():      {ID: signerCtorID, FilePath: "JcaContentSignerBuilder.java", StartLine: 1, ReturnType: pkgOperatorJca + ".JcaContentSignerBuilder", Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}}},
		signerBuildID.String():     {ID: signerBuildID, FilePath: "JcaContentSignerBuilder.java", StartLine: 2, ReturnType: "org.bouncycastle.operator.ContentSigner", Parameters: []callgraph.FunctionParameter{{Type: "java.security.PrivateKey"}}},
		cmsSignedCtorID.String():   {ID: cmsSignedCtorID, FilePath: "CMSSignedDataGenerator.java", StartLine: 1, ReturnType: pkgCms + ".CMSSignedDataGenerator"},
		cmsAddSignerID.String():    {ID: cmsAddSignerID, FilePath: "CMSSignedGenerator.java", StartLine: 2, ReturnType: "void", Parameters: []callgraph.FunctionParameter{{Type: "org.bouncycastle.cms.SignerInfoGenerator"}}},
		cmsSignedGenID.String():    {ID: cmsSignedGenID, FilePath: "CMSSignedDataGenerator.java", StartLine: 3, ReturnType: "org.bouncycastle.cms.CMSSignedData", Parameters: []callgraph.FunctionParameter{{Type: "org.bouncycastle.cms.CMSTypedData"}}},
		cmsEnvCtorID.String():      {ID: cmsEnvCtorID, FilePath: "CMSEnvelopedDataGenerator.java", StartLine: 1, ReturnType: pkgCms + ".CMSEnvelopedDataGenerator"},
		cmsAddRecipientID.String(): {ID: cmsAddRecipientID, FilePath: "CMSEnvelopedGenerator.java", StartLine: 2, ReturnType: "void", Parameters: []callgraph.FunctionParameter{{Type: "org.bouncycastle.cms.RecipientInfoGenerator"}}},
		cmsEnvGenID.String():       {ID: cmsEnvGenID, FilePath: "CMSEnvelopedDataGenerator.java", StartLine: 3, ReturnType: "org.bouncycastle.cms.CMSEnvelopedData", Parameters: []callgraph.FunctionParameter{{Type: "org.bouncycastle.cms.CMSTypedData"}, {Type: "org.bouncycastle.operator.OutputEncryptor"}}},
	}}

	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "Issuer.java",
		Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{
			{
				FindingID: "cert-issuance-jca-x509v3-builder",
				StartLine: 3,
				EndLine:   3,
				Match:     "new JcaX509v3CertificateBuilder(...)",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkgCertJcajce + ".JcaX509v3CertificateBuilder.<init>",
					"assetType": "certificate",
				},
			},
			{
				FindingID: "content-signer-builder",
				StartLine: 5,
				EndLine:   5,
				Match:     "new JcaContentSignerBuilder(\"SHA256withRSA\")",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkgOperatorJca + ".JcaContentSignerBuilder.<init>",
					"assetType": "algorithm",
				},
			},
			{
				FindingID: "cms-signed-data-signature",
				StartLine: 9,
				EndLine:   9,
				Match:     "new CMSSignedDataGenerator()",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkgCms + ".CMSSignedDataGenerator.<init>",
					"assetType": "protocol",
				},
			},
			{
				FindingID: "cms-enveloped-data-encryption",
				StartLine: 12,
				EndLine:   12,
				Match:     "new CMSEnvelopedDataGenerator()",
				Rules:     []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
				Metadata: map[string]string{
					"api":       pkgCms + ".CMSEnvelopedDataGenerator.<init>",
					"assetType": "protocol",
				},
			},
		},
	}}}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.CryptoAnnotations) != 4 {
		t.Fatalf("crypto_annotations = %#v, want 4 findings", payload.CryptoAnnotations)
	}

	categoryByFunction := map[string]string{}
	for _, support := range payload.SupportingCalls {
		if support.SupportingCall != nil {
			categoryByFunction[support.SupportingCall.FunctionName] = support.Category
		}
	}

	// (1) Cert issuance via the Jca subclass: addExtension/build resolve to
	// "config"/"factory" PURELY via the JcaX509v3CertificateBuilder ->
	// X509v3CertificateBuilder hierarchy edge -- no per-method contract is
	// authored on the Jca subclass for either, and the supporting call's
	// FunctionName correctly reports the base class that actually declares
	// the method (X509v3CertificateBuilder), not the Jca subtype.
	wantCategory := map[string]string{
		pkgCertJcajce + ".JcaX509v3CertificateBuilder.<init>":         "factory",
		"org.bouncycastle.cert.X509v3CertificateBuilder.addExtension": "config",
		"org.bouncycastle.cert.X509v3CertificateBuilder.build":        "factory",
		// (2) ContentSigner factory.
		pkgOperatorJca + ".JcaContentSignerBuilder.<init>": "factory",
		pkgOperatorJca + ".JcaContentSignerBuilder.build":  "factory",
		// (3a) CMSSignedDataGenerator full lifecycle -- addSignerInfoGenerator
		// resolves via the CMSSignedDataGenerator -> CMSSignedGenerator
		// hierarchy edge, reporting CMSSignedGenerator as its declaring class.
		pkgCms + ".CMSSignedDataGenerator.<init>":             "factory",
		pkgCms + ".CMSSignedGenerator.addSignerInfoGenerator": "config",
		pkgCms + ".CMSSignedDataGenerator.generate":           "operation",
		// (3b) CMSEnvelopedDataGenerator full lifecycle -- same reasoning via
		// the CMSEnvelopedGenerator hierarchy edge.
		pkgCms + ".CMSEnvelopedDataGenerator.<init>":                "factory",
		pkgCms + ".CMSEnvelopedGenerator.addRecipientInfoGenerator": "config",
		pkgCms + ".CMSEnvelopedDataGenerator.generate":              "operation",
	}
	for name, want := range wantCategory {
		if got := categoryByFunction[name]; got != want {
			t.Errorf("%s category = %q, want %q; supporting_calls = %#v", name, got, want, payload.SupportingCalls)
		}
	}

	for i, finding := range payload.CryptoAnnotations {
		if len(finding.SupportingCallIDs) < 1 {
			t.Errorf("finding[%d] (%s) supporting_call_ids = %#v, want at least the constructor's own supporting calls", i, finding.FindingID, finding.SupportingCallIDs)
		}
	}
}
