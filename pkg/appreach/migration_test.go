// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/pqc"
)

func cryptoAsset(source, family, metadata string) *CryptographicAssetDTO {
	return &CryptographicAssetDTO{
		Source:   source,
		Metadata: json.RawMessage(metadata),
		PQC:      &pqc.Classification{Status: "vulnerable", Family: family},
	}
}

// Direct findings fold under the requested component, indirect ones under
// their dependency, and a finding that is not vulnerable gets no path.
func TestAnnotateMigrationGroupsPerComponent(t *testing.T) {
	jose := &DependencyInfoDTO{Module: "github.com/go-jose/go-jose/v4", Version: "v4.1.4", PURL: "pkg:golang/github.com/go-jose/go-jose/v4"}
	safe := &CryptographicAssetDTO{
		Source: "direct", Metadata: json.RawMessage(`{"algorithmPrimitive":"hash"}`),
		PQC: &pqc.Classification{Status: "not_applicable", Family: "SHA-2"},
	}
	block := &ComponentDataDTO{
		Purl: "pkg:golang/github.com/coreos/go-oidc/v3", Version: "v3.21.0",
		Findings: []*FindingDTO{
			{CryptographicAssets: []*CryptographicAssetDTO{
				cryptoAsset("direct", "RSA", `{"algorithmPrimitive":"pke","operation":"keygen"}`),
				cryptoAsset("direct", "ECDSA", `{"algorithmPrimitive":"signature","operation":"sign"}`),
				safe,
			}},
			{DependencyInfo: jose, CryptographicAssets: []*CryptographicAssetDTO{
				cryptoAsset(SourceIndirect, "ECDSA", `{"algorithmPrimitive":"signature","operation":"sign"}`),
				cryptoAsset(SourceIndirect, "RSA", `{"algorithmPrimitive":"pke","operation":"encrypt"}`),
			}},
		},
	}

	AnnotateMigration(block)

	if safe.Migration != nil {
		t.Errorf("a not-applicable finding has a migration: %+v", safe.Migration)
	}
	if len(block.MigrationSummary) != 2 {
		t.Fatalf("migration_summary = %s, want one group per component", mustJSON(t, block.MigrationSummary))
	}
	own, dep := block.MigrationSummary[0], block.MigrationSummary[1]
	if own.Component != "pkg:golang/github.com/coreos/go-oidc/v3@v3.21.0" || own.Source != "direct" ||
		own.Path != "redesign" || own.Counts["redesign"] != 1 || own.Counts["swap"] != 1 || own.Inferred != 1 || len(own.SizeRisk) != 0 {
		t.Errorf("direct group = %s", mustJSON(t, own))
	}
	if dep.Component != "pkg:golang/github.com/go-jose/go-jose/v4@v4.1.4" || dep.Source != SourceIndirect ||
		dep.Path != "blocked" || dep.Counts["upgrade"] != 1 || dep.Counts["blocked"] != 1 || dep.Inferred != 0 ||
		len(dep.SizeRisk) != 1 || dep.SizeRisk[0] != "jwt" {
		t.Errorf("indirect group = %s", mustJSON(t, dep))
	}
}

func TestHasVersion(t *testing.T) {
	cases := map[string]bool{
		"pkg:npm/@angular/core":                              false,
		"pkg:npm/@angular/core@17.0.0":                       true,
		"pkg:golang/github.com/go-jose/go-jose/v4":           false,
		"pkg:golang/golang.org/x/crypto@v0.31.0":             true,
		"pkg:maven/org.bouncycastle/bcprov-jdk18on":          false,
		"github.com/go-jose/go-jose/v4":                      false,
		"":                                                   false,
		"pkg:maven/a/b@1.0?repository_url=https://x/y":       true,
		"pkg:golang/x/y@v1.0.0#sub/dir":                      true,
		"pkg:npm/%40acme/crypto?vcs_url=git@github.com:a":    false,
		"pkg:npm/%40angular/core@17.0.0":                     true,
		"pkg:github/openssl/openssl@refs/tags/openssl-3.5.0": true,
	}
	for purl, want := range cases {
		if got := hasVersion(purl); got != want {
			t.Errorf("hasVersion(%q) = %v, want %v", purl, got, want)
		}
	}
}

func summaryKeys(block *ComponentDataDTO) []string {
	keys := make([]string, 0, len(block.MigrationSummary))
	for _, s := range block.MigrationSummary {
		keys = append(keys, s.Source+" "+s.Component)
	}
	return keys
}

// The component key of an indirect group: the purl with its version appended
// once, the module when no purl was recorded, a scoped npm purl handled.
func TestAnnotateMigrationComponentKeys(t *testing.T) {
	sign := `{"algorithmPrimitive":"signature","operation":"sign"}`
	in := func(dep *DependencyInfoDTO) *FindingDTO {
		return &FindingDTO{DependencyInfo: dep, CryptographicAssets: []*CryptographicAssetDTO{cryptoAsset(SourceIndirect, "ECDSA", sign)}}
	}
	block := &ComponentDataDTO{Purl: "pkg:npm/app", Findings: []*FindingDTO{
		in(&DependencyInfoDTO{Module: "@angular/core", Version: "17.0.0", PURL: "pkg:npm/@angular/core"}),
		in(&DependencyInfoDTO{Module: "@noble/curves", Version: "1.9.0", PURL: "pkg:npm/%40noble/curves"}),
		in(&DependencyInfoDTO{Module: "jose", Version: "5.2.0", PURL: "pkg:npm/jose@5.2.0"}),
		in(&DependencyInfoDTO{Module: "example.org/mod", Version: "v1.2.3"}),
		{CryptographicAssets: []*CryptographicAssetDTO{cryptoAsset("direct", "ECDSA", sign)}},
	}}

	AnnotateMigration(block)

	want := []string{
		"indirect pkg:npm/@angular/core@17.0.0",
		"indirect pkg:npm/%40noble/curves@1.9.0",
		"indirect pkg:npm/jose@5.2.0",
		"indirect example.org/mod@v1.2.3",
		"direct pkg:npm/app",
	}
	if got := summaryKeys(block); len(got) != len(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("group %d = %q, want %q", i, got[i], want[i])
			}
		}
	}
}

// An asset's own dependency_info wins over its file's.
func TestAnnotateMigrationAssetDependencyWins(t *testing.T) {
	asset := cryptoAsset(SourceIndirect, "ECDSA", `{"algorithmPrimitive":"signature","operation":"sign"}`)
	asset.DependencyInfo = &DependencyInfoDTO{Module: "github.com/go-jose/go-jose/v4", Version: "v4.1.4", PURL: "pkg:golang/github.com/go-jose/go-jose/v4"}
	block := &ComponentDataDTO{Purl: "pkg:golang/app", Version: "v1", Findings: []*FindingDTO{{
		DependencyInfo:      &DependencyInfoDTO{Module: "example.org/other", Version: "v9", PURL: "pkg:golang/example.org/other"},
		CryptographicAssets: []*CryptographicAssetDTO{asset},
	}}}

	AnnotateMigration(block)

	if got := summaryKeys(block); len(got) != 1 || got[0] != "indirect pkg:golang/github.com/go-jose/go-jose/v4@v4.1.4" {
		t.Errorf("groups = %v, want the asset's own dependency", got)
	}
	if asset.Migration == nil || asset.Migration.Path != "upgrade" {
		t.Errorf("migration = %+v, want upgrade from the asset's dependency", asset.Migration)
	}
}

// Defensive edges: nil entries, an indirect finding with no dependency, a block
// with nothing vulnerable, and a second pass over the same block.
func TestAnnotateMigrationEdges(t *testing.T) {
	orphan := cryptoAsset(SourceIndirect, "ECDSA", `{"algorithmPrimitive":"signature","operation":"sign"}`)
	block := &ComponentDataDTO{Purl: "pkg:golang/app", Findings: []*FindingDTO{
		nil,
		{CryptographicAssets: []*CryptographicAssetDTO{nil, orphan, {Source: "direct"}}},
	}}

	AnnotateMigration(block)
	if orphan.Migration == nil {
		t.Error("an indirect finding with no dependency lost its own path")
	}
	if block.MigrationSummary != nil {
		t.Errorf("summary = %s, want none: the orphan belongs to no component", mustJSON(t, block.MigrationSummary))
	}

	safe := &ComponentDataDTO{Purl: "pkg:golang/app", Findings: []*FindingDTO{{CryptographicAssets: []*CryptographicAssetDTO{
		{Source: "direct", Metadata: json.RawMessage(`{"algorithmPrimitive":"hash"}`), PQC: &pqc.Classification{Status: "not_applicable"}},
	}}}}
	AnnotateMigration(safe)
	if body := string(mustJSON(t, safe)); strings.Contains(body, "migration") {
		t.Errorf("a block with nothing vulnerable serializes migration fields: %s", body)
	}

	twice := &ComponentDataDTO{Purl: "pkg:golang/app", Version: "v1", Findings: []*FindingDTO{{CryptographicAssets: []*CryptographicAssetDTO{
		cryptoAsset("direct", "ECDSA", `{"algorithmPrimitive":"signature","operation":"sign"}`),
	}}}}
	AnnotateMigration(twice)
	first := string(mustJSON(t, twice))
	AnnotateMigration(twice)
	if second := string(mustJSON(t, twice)); second != first {
		t.Errorf("a second pass changed the block:\n%s\n%s", first, second)
	}
}

func TestWithVersion(t *testing.T) {
	for _, tt := range []struct{ purl, version, want string }{
		{"pkg:golang/x/y", "v1.0.0", "pkg:golang/x/y@v1.0.0"},
		{"pkg:golang/x/y@v1.0.0", "v2.0.0", "pkg:golang/x/y@v1.0.0"},
		{"pkg:golang/x/y", "", "pkg:golang/x/y"},
		{"pkg:maven/a/b?repository_url=https://x/y", "1.0", "pkg:maven/a/b@1.0?repository_url=https://x/y"},
		{"pkg:golang/x/y#sub/dir", "v1", "pkg:golang/x/y@v1#sub/dir"},
		{"pkg:npm/%40angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"},
		{"pkg:npm/@angular/core", "17.0.0", "pkg:npm/@angular/core@17.0.0"},
		{"example.org/mod", "v1.2.3", "example.org/mod@v1.2.3"},
	} {
		if got := withVersion(tt.purl, tt.version); got != tt.want {
			t.Errorf("withVersion(%q, %q) = %q, want %q", tt.purl, tt.version, got, tt.want)
		}
	}
}

// A dependency with neither a purl nor a module belongs to no component.
func TestAnnotateMigrationDependencyWithOnlyAVersion(t *testing.T) {
	asset := cryptoAsset(SourceIndirect, "ECDSA", `{"algorithmPrimitive":"signature","operation":"sign"}`)
	block := &ComponentDataDTO{Purl: "pkg:golang/app", Version: "v1", Findings: []*FindingDTO{{
		DependencyInfo:      &DependencyInfoDTO{Version: "v1"},
		CryptographicAssets: []*CryptographicAssetDTO{asset},
	}}}

	AnnotateMigration(block)

	if asset.Migration == nil {
		t.Error("the finding lost its own path")
	}
	if block.MigrationSummary != nil {
		t.Errorf("summary = %s, want none", mustJSON(t, block.MigrationSummary))
	}
}

// A direct finding never takes its file's dependency: no borrowed path, size
// risk or group.
func TestAnnotateMigrationDirectIgnoresFileDependency(t *testing.T) {
	asset := cryptoAsset("direct", "ECDSA", `{"algorithmPrimitive":"signature","operation":"sign"}`)
	block := &ComponentDataDTO{Purl: "pkg:golang/app", Version: "v1", Findings: []*FindingDTO{{
		DependencyInfo:      &DependencyInfoDTO{Module: "github.com/go-jose/go-jose/v4", Version: "v4.1.4", PURL: "pkg:golang/github.com/go-jose/go-jose/v4"},
		CryptographicAssets: []*CryptographicAssetDTO{asset},
	}}}

	AnnotateMigration(block)

	if asset.Migration == nil || asset.Migration.Path != "swap" || asset.Migration.SizeRisk != "" {
		t.Errorf("migration = %s, want swap with no size risk", mustJSON(t, asset.Migration))
	}
	if got := summaryKeys(block); len(got) != 1 || got[0] != "direct pkg:golang/app@v1" {
		t.Errorf("groups = %v, want the requested component only", got)
	}
}

// A stored "dependency" source counts as indirect; an empty source as direct.
func TestAnnotateMigrationSourceSpellings(t *testing.T) {
	jose := &DependencyInfoDTO{Module: "github.com/go-jose/go-jose/v4", Version: "v4.1.4", PURL: "pkg:golang/github.com/go-jose/go-jose/v4"}
	sign := `{"algorithmPrimitive":"signature","operation":"sign"}`
	for source, want := range map[string]string{
		storedSourceDependency: "indirect pkg:golang/github.com/go-jose/go-jose/v4@v4.1.4",
		"":                     "direct pkg:golang/app@v1",
	} {
		block := &ComponentDataDTO{Purl: "pkg:golang/app", Version: "v1", Findings: []*FindingDTO{{
			DependencyInfo: jose, CryptographicAssets: []*CryptographicAssetDTO{cryptoAsset(source, "ECDSA", sign)},
		}}}
		AnnotateMigration(block)
		if got := summaryKeys(block); len(got) != 1 || got[0] != want {
			t.Errorf("source %q: groups = %v, want %q", source, got, want)
		}
	}
}

// Edge spellings of a key: an @ in a subpath and a module that names a version.
func TestWithVersionEdges(t *testing.T) {
	for _, tt := range []struct{ purl, version, want string }{
		{"pkg:golang/x/y#a@b", "v1", "pkg:golang/x/y@v1#a@b"},
		{"m@v1", "v2", "m@v1"},
	} {
		if got := withVersion(tt.purl, tt.version); got != tt.want {
			t.Errorf("withVersion(%q, %q) = %q, want %q", tt.purl, tt.version, got, tt.want)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
