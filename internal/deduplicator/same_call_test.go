// Copyright 2025 SCANOSS
//
// SPDX-License-Identifier: Apache-2.0

package deduplicator

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

func callAsset(startCol, endCol int, ruleID string, metadata map[string]string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: 7, EndLine: 7, StartCol: startCol, EndCol: endCol,
		Match:    "getInstance(name)",
		Rules:    []entities.RuleInfo{{ID: ruleID, Severity: "INFO"}},
		Metadata: metadata,
	}
}

func describe(assets []entities.CryptographicAsset) []string {
	out := make([]string, 0, len(assets))
	for i := range assets {
		a := &assets[i]
		ids := make([]string, 0, len(a.Rules))
		for _, r := range a.Rules {
			ids = append(ids, r.ID)
		}
		keys := slices.Sorted(maps.Keys(a.Metadata))
		pairs := make([]string, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, k+"="+a.Metadata[k])
		}
		out = append(out, fmt.Sprintf("%d-%d %v %v", a.StartCol, a.EndCol, ids, pairs))
	}
	return out
}

func dedupFile(assets ...entities.CryptographicAsset) []string {
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "Crypto.java", CryptographicAssets: assets}}}
	return describe(DeduplicateInterimReport(report).Findings[0].CryptographicAssets)
}

func TestDeduplicate_SameCallSameAlgorithmPrefersSpecificRule(t *testing.T) {
	specific := callAsset(10, 20, "jca.signature.ml-dsa", map[string]string{
		"assetType": "algorithm", "algorithmName": "ML-DSA-65", "api": "Signature.getInstance",
		"parameterCondition": "param[0]==ML-DSA-65",
	})
	generic := callAsset(10, 20, "jca.signature.ml-dsa.generic", map[string]string{
		"assetType": "algorithm", "algorithmName": "ML-DSA-65", "api": "KeyPairGenerator.getInstance", "library": "JCA",
	})

	got := dedupFile(generic, specific)
	want := []string{
		"10-20 [jca.signature.ml-dsa jca.signature.ml-dsa.generic] " +
			"[algorithmName=ML-DSA-65 api=Signature.getInstance assetType=algorithm library=JCA parameterCondition=param[0]==ML-DSA-65]",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
}

func TestDeduplicate_UnresolvedCallMergesIntoNamedAlgorithm(t *testing.T) {
	unresolved := callAsset(30, 34, "jca.cipher.dynamic-cipher", map[string]string{
		"assetType": "algorithm", "algorithmPrimitive": "block-cipher", "api": "javax.crypto.Cipher.getInstance",
	})
	named := callAsset(30, 34, "jca.cipher.aes-gcm", map[string]string{
		"assetType": "algorithm", "algorithmName": "AES-GCM", "algorithmFamily": "AES", "algorithmPrimitive": "ae", "api": "Cipher.getInstance",
	})

	got := dedupFile(unresolved, named)
	want := []string{
		"30-34 [jca.cipher.aes-gcm jca.cipher.dynamic-cipher] " +
			"[algorithmFamily=AES algorithmName=AES-GCM algorithmPrimitive=ae api=Cipher.getInstance assetType=algorithm]",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
}

func TestDeduplicate_SameCallKeepsDistinctAssetsApart(t *testing.T) {
	aes := callAsset(10, 20, "aes", map[string]string{"assetType": "algorithm", "algorithmName": "AES-GCM", "api": "a"})
	des := callAsset(10, 20, "des", map[string]string{"assetType": "algorithm", "algorithmName": "DES", "api": "b"})
	unresolvedElsewhere := callAsset(25, 30, "dynamic", map[string]string{"assetType": "algorithm", "algorithmPrimitive": "hash"})
	rsa2048 := callAsset(10, 20, "keygen", map[string]string{"assetType": "related-crypto-material", "materialType": "key", "materialAlgorithm": "RSA", "materialSize": "2048"})
	rsa3072 := callAsset(10, 20, "keygen-init", map[string]string{"assetType": "related-crypto-material", "materialType": "key", "materialAlgorithm": "RSA", "materialSize": "3072"})

	got := dedupFile(aes, des, unresolvedElsewhere, rsa2048, rsa3072)
	if len(got) != 5 {
		t.Fatalf("got %d assets, want 5 distinct ones:\n%q", len(got), got)
	}
}

func TestDeduplicate_SameCallSameMaterialMerges(t *testing.T) {
	a := callAsset(10, 20, "keygen", map[string]string{"assetType": "related-crypto-material", "materialType": "key", "materialAlgorithm": "EC", "materialCurve": "secp384r1", "api": "a"})
	b := callAsset(12, 18, "keygen.generic", map[string]string{"assetType": "related-crypto-material", "materialType": "key", "materialAlgorithm": "EC", "materialCurve": "secp384r1", "api": "b"})

	got := dedupFile(a, b)
	want := []string{"10-20 [keygen keygen.generic] [api=a assetType=related-crypto-material materialAlgorithm=EC materialCurve=secp384r1 materialType=key]"}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
}

func TestDeduplicate_UnresolvedKeyCallAbsorbedByResolvedAssetOfAnyType(t *testing.T) {
	unresolvedKey := callAsset(10, 20, "jca.key.dynamic-keypairgenerator", map[string]string{
		"assetType": "related-crypto-material", "materialType": "key", "api": "KeyPairGenerator.getInstance",
	})
	namedKey := callAsset(10, 20, "jca.key.keypairgenerator-rsa", map[string]string{
		"assetType": "related-crypto-material", "materialType": "key", "materialAlgorithm": "RSA", "materialSize": "2048",
	})
	if got, want := dedupFile(unresolvedKey, namedKey), []string{
		"10-20 [jca.key.keypairgenerator-rsa jca.key.dynamic-keypairgenerator] " +
			"[assetType=related-crypto-material materialAlgorithm=RSA materialSize=2048 materialType=key]",
	}; !slices.Equal(got, want) {
		t.Fatalf("key: got\n%q\nwant\n%q", got, want)
	}

	namedAlgorithm := callAsset(10, 20, "jca.signature.ml-dsa.keypairgenerator", map[string]string{
		"assetType": "algorithm", "algorithmName": "ML-DSA-65", "algorithmFamily": "ML-DSA",
	})
	if got, want := dedupFile(unresolvedKey, namedAlgorithm), []string{
		"10-20 [jca.signature.ml-dsa.keypairgenerator jca.key.dynamic-keypairgenerator] " +
			"[algorithmFamily=ML-DSA algorithmName=ML-DSA-65 assetType=algorithm]",
	}; !slices.Equal(got, want) {
		t.Fatalf("algorithm: got\n%q\nwant\n%q", got, want)
	}
}

func TestDeduplicate_UnresolvedKeyCallKeptBesideUnrelatedMaterial(t *testing.T) {
	unresolvedKey := callAsset(10, 20, "jca.key.dynamic-keypairgenerator", map[string]string{
		"assetType": "related-crypto-material", "materialType": "key",
	})
	iv := callAsset(10, 20, "jca.iv.gcmparameterspec", map[string]string{
		"assetType": "related-crypto-material", "materialType": "initialization-vector",
	})
	if got := dedupFile(unresolvedKey, iv); len(got) != 2 {
		t.Fatalf("an IV does not resolve a key pair generator call, want both assets kept; got %q", got)
	}
}

func TestDeduplicate_UnresolvedCallInsideAMultiLineSpanIsKept(t *testing.T) {
	block := entities.CryptographicAsset{
		StartLine: 10, EndLine: 20, StartCol: 5, EndCol: 10,
		Rules:    []entities.RuleInfo{{ID: "jca.cipher.aes"}},
		Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "AES", "algorithmPrimitive": "block-cipher"},
	}
	digest := entities.CryptographicAsset{
		StartLine: 15, EndLine: 15, StartCol: 40, EndCol: 44,
		Rules:    []entities.RuleInfo{{ID: "jca.hash.dynamic-message-digest"}},
		Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "hash"},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "Crypto.java", CryptographicAssets: []entities.CryptographicAsset{block, digest}}}}
	if got := DeduplicateInterimReport(report).Findings[0].CryptographicAssets; len(got) != 2 {
		t.Fatalf("an unresolved call inside another rule's multi-line span is a different call, want 2 assets, got %d", len(got))
	}
}

func TestDeduplicate_SameCallMergeKeepsParsedParameterConditions(t *testing.T) {
	condition, err := paramcondition.Parse("param[0]==AES/GCM/NoPadding")
	if err != nil {
		t.Fatal(err)
	}
	conditioned := callAsset(10, 20, "jca.cipher.aes-gcm", map[string]string{
		"assetType": "algorithm", "algorithmName": "AES-GCM", "parameterCondition": condition.Raw,
	})
	conditioned.ParameterConditions = []paramcondition.Condition{condition}
	richer := callAsset(10, 20, "jca.cipher.aes-gcm-init", map[string]string{
		"assetType": "algorithm", "algorithmName": "AES-GCM", "algorithmMode": "GCM", "algorithmPrimitive": "ae", "api": "Cipher.init", "library": "JCA",
	})

	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "Crypto.java", CryptographicAssets: []entities.CryptographicAsset{conditioned, richer}}}}
	got := DeduplicateInterimReport(report).Findings[0].CryptographicAssets
	if len(got) != 1 {
		t.Fatalf("want one merged asset, got %d", len(got))
	}
	if got[0].Metadata["parameterCondition"] != condition.Raw || len(got[0].ParameterConditions) != 1 {
		t.Fatalf("metadata condition %q and parsed conditions %v must agree", got[0].Metadata["parameterCondition"], got[0].ParameterConditions)
	}
}

func TestDeduplicate_SameNameWithDifferentKeySizeStaysSeparate(t *testing.T) {
	aes128 := callAsset(10, 20, "jca.cipher.aes-a", map[string]string{"assetType": "algorithm", "algorithmName": "AES", "keySize": "128"})
	aes256 := callAsset(10, 20, "jca.cipher.aes-b", map[string]string{"assetType": "algorithm", "algorithmName": "AES", "keySize": "256"})
	if got := dedupFile(aes128, aes256); len(got) != 2 {
		t.Fatalf("different key sizes are different assets, got %q", got)
	}
}
