package pqc

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// protoAsset is a TLS protocol finding in the project's own code, carrying the
// rule PURL the dependency phase enriched with the resolved version.
func protoAsset(rulePURL string) *entities.CryptographicAsset {
	return &entities.CryptographicAsset{
		Metadata: map[string]string{"assetType": "protocol", "protocolType": "tls", "protocolName": "TLS"},
		PURL:     rulePURL,
	}
}

// depAsset is the same finding found inside a dependency's own source.
func depAsset(dep *entities.DependencyInfo) *entities.CryptographicAsset {
	a := protoAsset("")
	a.DependencyInfo = dep
	return a
}

func TestClassifyFromDefaultGroups(t *testing.T) {
	// A TLS protocol finding inside a known dependency gets the worst status
	// among the library version's default groups: every current library still
	// offers classical groups, so the verdict is vulnerable.
	c := classifyFromDefaultGroups(protoAsset("pkg:cargo/rustls@0.23.25"))
	if c == nil || c.Status != "vulnerable" || c.Family != "ECDH" || c.Deadline != 2030 {
		t.Fatalf("rustls@0.23.25 = %+v; want vulnerable/ECDH/2030", c)
	}

	// A finding inside a dependency's own source names it through
	// DependencyInfo instead, and reaches the same entry.
	// The scanner builds this PURL with purl.Dependency(ecosystem, module,
	// version), so it arrives versioned: the id must be the base, never the
	// versioned spelling.
	if c := classifyFromDefaultGroups(depAsset(&entities.DependencyInfo{
		Module: "rustls", Version: "0.23.25", PURL: "pkg:cargo/rustls@0.23.25",
	})); c == nil || c.Status != "vulnerable" {
		t.Fatalf("dependency-sourced finding = %+v; want vulnerable", c)
	}

	// An ecosystem whose resolver writes no PURL reaches the entry by module.
	if c := classifyFromDefaultGroups(depAsset(&entities.DependencyInfo{
		Module: "rust/rustls", Version: "0.23.25",
	})); c == nil || c.Status != "vulnerable" {
		t.Fatalf("module-only finding = %+v; want vulnerable", c)
	}

	// A rule PURL the dependency phase could not enrich names no version, so
	// the table is never asked a question it would answer for another version.
	if c := classifyFromDefaultGroups(protoAsset("pkg:cargo/rustls")); c != nil {
		t.Fatalf("unversioned purl classified: %+v", c)
	}

	// A library the table does not cover gets no answer.
	if c := classifyFromDefaultGroups(protoAsset("pkg:npm/left-pad@1.0.0")); c != nil {
		t.Fatalf("unknown module classified: %+v", c)
	}

	// A version below the table's oldest row gets no answer: the data only
	// speaks for versions it can cite.
	if c := classifyFromDefaultGroups(protoAsset("pkg:cargo/rustls@0.20.0")); c != nil {
		t.Fatalf("pre-table version classified: %+v", c)
	}

	// The project's own standard library names neither purl nor version, so it
	// stays unclassified, as roadmap#72 specifies.
	if c := classifyFromDefaultGroups(protoAsset("")); c != nil {
		t.Fatalf("direct finding classified: %+v", c)
	}

	// Only TLS protocol findings qualify; an algorithm asset keeps its own path.
	a := protoAsset("pkg:cargo/rustls@0.23.25")
	a.Metadata["assetType"] = "algorithm"
	if c := classifyFromDefaultGroups(a); c != nil {
		t.Fatalf("algorithm asset classified from defaults: %+v", c)
	}
}
