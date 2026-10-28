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
	for _, a := range assets {
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
