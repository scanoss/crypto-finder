// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package pqc

import (
	"encoding/json"
	"testing"
)

func vulnerable(family string) *Classification {
	return &Classification{Status: "vulnerable", Family: family}
}

func TestMigrationFor(t *testing.T) {
	jose := &Dependency{Module: "github.com/go-jose/go-jose/v4", Version: "v4.1.4", Purl: "pkg:golang/github.com/go-jose/go-jose/v4@v4.1.4"}
	cases := []struct {
		name     string
		c        *Classification
		metadata string
		source   string
		library  string
		dep      *Dependency
		want     string // path, or "" for no migration
		inferred bool
		sizeRisk string
	}{
		{"not classified", nil, `{}`, "direct", "", nil, "", false, ""},
		{"not vulnerable", &Classification{Status: "not_applicable", Family: "SHA-2"}, `{"algorithmPrimitive":"hash"}`, "direct", "", nil, "", false, ""},
		{"own signature", vulnerable("EdDSA"), `{"algorithmPrimitive":"signature","operation":"sign"}`, "direct", "", nil, "swap", false, ""},
		{"own key agreement", vulnerable("ECDH"), `{"algorithmPrimitive":"key-agree"}`, "direct", "", nil, "redesign", false, ""},
		{"own RSA key generation", vulnerable("RSA"), `{"algorithmPrimitive":"pke","operation":"keygen"}`, "direct", "", nil, "redesign", true, ""},
		{"own call into a JWT library", vulnerable("ECDSA"), `{"algorithmPrimitive":"signature"}`, "direct", "pkg:golang/github.com/golang-jwt/jwt/v5", nil, "swap", false, "jwt"},
		{"signature inside go-jose", vulnerable("ECDSA"), `{"algorithmPrimitive":"signature","operation":"sign"}`, "indirect", "", jose, "upgrade", false, "jwt"},
		{"encryption inside go-jose", vulnerable("RSA"), `{"algorithmPrimitive":"pke","operation":"encrypt"}`, "indirect", "", jose, "blocked", false, "jwt"},
	}
	for _, tc := range cases {
		got := MigrationFor(tc.c, json.RawMessage(tc.metadata), tc.source, tc.library, tc.dep)
		if tc.want == "" {
			if got != nil {
				t.Errorf("%s: migration = %+v, want none", tc.name, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("%s: no migration, want %s", tc.name, tc.want)
			continue
		}
		if got.Path != tc.want || got.Inferred != tc.inferred || got.SizeRisk != tc.sizeRisk || got.Reason == "" {
			t.Errorf("%s: migration = %+v, want path %s inferred %v size_risk %q and a reason", tc.name, got, tc.want, tc.inferred, tc.sizeRisk)
		}
	}
}

func TestSummarizePaths(t *testing.T) {
	worst, counts := SummarizePaths([]string{"upgrade", "swap", "upgrade", "blocked"})
	if worst != "blocked" {
		t.Errorf("worst = %s, want blocked", worst)
	}
	if counts["upgrade"] != 2 || counts["swap"] != 1 || counts["blocked"] != 1 || len(counts) != 3 {
		t.Errorf("counts = %v", counts)
	}
}

// Metadata the service cannot read still yields a path from the family, and
// never a panic.
func TestMigrationForTolerantOfMetadata(t *testing.T) {
	for _, metadata := range []string{``, `null`, `not json`, `{"algorithmPrimitive":7,"operation":["sign"]}`} {
		got := MigrationFor(vulnerable("ECDSA"), json.RawMessage(metadata), "direct", "", nil)
		if got == nil || got.Path != "swap" || !got.Inferred {
			t.Errorf("metadata %q: migration = %+v, want swap inferred from the family", metadata, got)
		}
	}
}

func TestMigrationForDependencyEdges(t *testing.T) {
	sign := json.RawMessage(`{"algorithmPrimitive":"signature","operation":"sign"}`)

	noVersion := MigrationFor(vulnerable("ECDSA"), sign, "indirect", "", &Dependency{Module: "github.com/go-jose/go-jose/v4", Purl: "pkg:golang/github.com/go-jose/go-jose/v4"})
	if noVersion == nil || noVersion.Path != "upgrade" || noVersion.Reason != "ensure github.com/go-jose/go-jose/v4 >= 4.1.8" {
		t.Errorf("dependency without version: %+v, want upgrade with an ensure reason", noVersion)
	}
	unknown := MigrationFor(vulnerable("ECDSA"), sign, "indirect", "", &Dependency{Module: "example.org/unknown", Version: "v1.0.0", Purl: "pkg:golang/example.org/unknown@v1.0.0"})
	if unknown == nil || unknown.Path != "blocked" {
		t.Errorf("dependency with no libraries.yaml entry: %+v, want blocked", unknown)
	}
	for _, status := range []string{"safe", "hybrid", "unassessed", "not_applicable", ""} {
		if got := MigrationFor(&Classification{Status: status, Family: "X"}, sign, "direct", "", nil); got != nil {
			t.Errorf("status %q: migration = %+v, want none", status, got)
		}
	}
}

// The dataset releases behind this API: purls in another case (Go namespaces
// arrive lowercased) and a dependency with no purl.
func TestMigrationForDatasetLookups(t *testing.T) {
	kex := json.RawMessage(`{"algorithmPrimitive":"key-agree"}`)
	m := MigrationFor(vulnerable("ECDH"), kex, "indirect", "",
		&Dependency{Module: "github.com/ProtonMail/go-crypto", Version: "v1.8.0", Purl: "pkg:golang/github.com/protonmail/go-crypto@v1.8.0"})
	if m == nil || m.Path != "upgrade" || m.Reason != "github.com/ProtonMail/go-crypto v1.8.0 already supports ML-KEM: switch to it" {
		t.Errorf("lowercased Go purl: %+v", m)
	}
	m = MigrationFor(vulnerable("ECDSA"), json.RawMessage(`{"algorithmPrimitive":"signature"}`), "indirect", "",
		&Dependency{Module: "github.com/go-jose/go-jose/v4", Version: "v4.1.4"})
	if m == nil || m.Path != "blocked" || m.Reason != "PQC support of github.com/go-jose/go-jose/v4 is unknown (no purl)" {
		t.Errorf("dependency without purl: %+v", m)
	}
}

// A dependency whose version only sits in its purl is compared by that version.
func TestMigrationForVersionFromPurl(t *testing.T) {
	sign := json.RawMessage(`{"algorithmPrimitive":"signature","operation":"sign"}`)
	for purl, want := range map[string]string{
		"pkg:golang/github.com/go-jose/go-jose/v4@v4.1.9": "github.com/go-jose/go-jose/v4 v4.1.9 already supports ML-DSA: switch to it",
		"pkg:golang/github.com/go-jose/go-jose/v4@v4.1.4": "upgrade github.com/go-jose/go-jose/v4 to >= 4.1.8",
		"pkg:golang/github.com/go-jose/go-jose/v4":        "ensure github.com/go-jose/go-jose/v4 >= 4.1.8",
	} {
		m := MigrationFor(vulnerable("ECDSA"), sign, "indirect", "", &Dependency{Module: "github.com/go-jose/go-jose/v4", Purl: purl})
		if m == nil || m.Reason != want {
			t.Errorf("%s: %+v, want %q", purl, m, want)
		}
	}
	for purl, want := range map[string]string{
		"pkg:golang/x/y@v1.2.0":                    "v1.2.0",
		"pkg:npm/@scope/name@1.0.0?arch=x64#lib":   "1.0.0",
		"pkg:npm/%40scope/name":                    "",
		"pkg:maven/a/b?repository_url=https://x/y": "",
	} {
		if got := purlVersion(purl); got != want {
			t.Errorf("purlVersion(%q) = %q, want %q", purl, got, want)
		}
	}
}

// The operation comes from `operation` alone, and the dependency's module names it in
// the reason even when it differs from the purl's name.
func TestMigrationForReadsOperationAndModule(t *testing.T) {
	m := MigrationFor(vulnerable("RSA"), json.RawMessage(`{"algorithmPrimitive":"pke","operation":"encrypt","cryptoFunction":"keygen"}`), "direct", "", nil)
	if m == nil || m.Inferred {
		t.Errorf("operation encrypt was not read: %+v", m)
	}
	m = MigrationFor(vulnerable("ECDSA"), json.RawMessage(`{"algorithmPrimitive":"signature"}`), "indirect", "",
		&Dependency{Module: "org.bouncycastle:bcprov-jdk18on", Version: "1.70", Purl: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.70"})
	if m == nil || m.Reason != "upgrade org.bouncycastle:bcprov-jdk18on to >= 1.79" {
		t.Errorf("reason does not name the module: %+v", m)
	}
}
