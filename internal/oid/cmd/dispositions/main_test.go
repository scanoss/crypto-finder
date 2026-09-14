package main

import (
	"strings"
	"testing"
)

func TestExpectations_MatchesPinnedFixtureParserSyntax(t *testing.T) {
	input := "// TEST-METADATA: assetType=algorithm, algorithmName=AES-256-GCM\n# TEST-METADATA: assetType:algorithm algorithmName:SHA-256\n"
	got := expectations(input)
	if len(got) != 2 || got[0]["algorithmName"] != "AES-256-GCM" || got[1]["algorithmName"] != "SHA-256" {
		t.Fatalf("expectations() = %#v", got)
	}
}

func TestCanonical_IsIndependentOfMetadataOrder(t *testing.T) {
	first := canonical(map[string]string{"algorithmName": "AES", "assetType": "algorithm"})
	second := canonical(map[string]string{"assetType": "algorithm", "algorithmName": "AES"})
	if first != second {
		t.Fatalf("canonical metadata drift: %q != %q", first, second)
	}
}

func TestSelector_ExcludesNonIdentityFixtureFields(t *testing.T) {
	got := selector(map[string]string{"assetType": "algorithm", "algorithmName": "AES", "library": "openssl"})
	if len(got) != 2 || got["library"] != "" {
		t.Fatalf("selector() = %#v", got)
	}
}

func TestDeduplicateSignatures_RejectsDuplicateCanonicalSourceSignature(t *testing.T) {
	_, err := deduplicateSourceRows([]sourceRow{
		{source: "fixtures/a.test.go#1", facts: map[string]string{"assetType": "algorithm", "algorithmName": "AES-256-GCM"}},
		{source: "fixtures/a.test.go#1", facts: map[string]string{"algorithmName": "AES-256-GCM", "assetType": "algorithm"}},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate source identity") {
		t.Fatalf("deduplicateSourceRows() error = %v, want duplicate source identity", err)
	}
}

func TestDeduplicateSourceRows_AllowsRepeatedSemanticSelectorAtDifferentSources(t *testing.T) {
	rows, err := deduplicateSourceRows([]sourceRow{
		{source: "fixtures/a.test.go#1", facts: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256"}},
		{source: "fixtures/b.test.go#1", facts: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256"}},
	})
	if err != nil || len(rows) != 2 {
		t.Fatalf("deduplicateSourceRows() = %#v, %v; distinct source rows sharing selector are valid", rows, err)
	}
	semantic := collapseSemanticRows(rows)
	if len(semantic) != 1 || semantic[0].source != "fixtures/a.test.go#1" {
		t.Fatalf("collapseSemanticRows() = %#v, want deterministic representative", semantic)
	}
}

func TestDeduplicateSourceRows_RejectsSameSourceWithDifferentFacts(t *testing.T) {
	_, err := deduplicateSourceRows([]sourceRow{
		{source: "fixtures/a.test.go#1", facts: map[string]string{"assetType": "algorithm", "algorithmName": "AES-128-CBC"}},
		{source: "fixtures/a.test.go#1", facts: map[string]string{"assetType": "algorithm", "algorithmName": "AES-256-CBC"}},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate source identity") {
		t.Fatalf("deduplicateSourceRows() error = %v, want duplicate source identity", err)
	}
}
