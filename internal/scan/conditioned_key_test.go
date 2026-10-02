// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// catalogOf indexes one rule per key, named after the key, so rulesForCall
// answers which keys name a call.
func catalogOf(graph *callgraph.CallGraph, ecosystem string, keys ...string) conditionedCatalog {
	rules := make(map[string][]engine.RuleCryptoMetadata, len(keys))
	for _, key := range keys {
		rules[key] = []engine.RuleCryptoMetadata{{Rule: entities.RuleInfo{ID: key}}}
	}
	return conditionedCatalog{rules: rules, keys: newConditionedKeyMatcher(graph, ecosystem)}
}

func matchedKeys(catalog conditionedCatalog, call *callgraph.FunctionCall) []string {
	rules := catalog.rulesForCall(call)
	keys := make([]string, 0, len(rules))
	for i := range rules {
		keys = append(keys, rules[i].Rule.ID)
	}
	return keys
}

func TestConditionedKeys_RustPathForms(t *testing.T) {
	t.Parallel()

	catalog := catalogOf(nil, ecosystemRust,
		"openssl::hash::MessageDigest::from_name",
		"hash::MessageDigest::from_name",
		"MessageDigest::from_name",
		"from_name",
		"jsonwebtoken::Header::new",
		"Digest::from_name",
		"other::hash::MessageDigest::from_name",
		"ssl::hash::MessageDigest::from_name",
		"MessageDigest::from_name::extra",
	)
	digest := callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "openssl::hash", Type: "MessageDigest", Name: "from_name"}}
	header := callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "jsonwebtoken", Type: "Header", Name: "new"}}
	bare := callgraph.FunctionCall{Callee: callgraph.FunctionID{Name: "new"}, Raw: "Header::new"}

	tests := []struct {
		name string
		call callgraph.FunctionCall
		want []string
	}{
		{
			name: "full path and every trailing segment run name the callee",
			call: digest,
			want: []string{"MessageDigest::from_name", "from_name", "hash::MessageDigest::from_name", "openssl::hash::MessageDigest::from_name"},
		},
		{name: "use-imported type", call: header, want: []string{"jsonwebtoken::Header::new"}},
		{name: "an unresolved method names no qualified key", call: bare, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchedKeys(catalog, &tt.call); !slices.Equal(got, tt.want) {
				t.Fatalf("matched keys = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConditionedKeys_GoImportNames(t *testing.T) {
	t.Parallel()

	keys := []string{"jwt.GetSigningMethod", "GetSigningMethod", "jws.GetSigningMethod", "v5.GetSigningMethod", "jwt-go.GetSigningMethod", "jwt.NewWithClaims"}
	// A parsed package whose clause differs from its last path segment.
	renamed := callgraph.FunctionID{Package: "github.com/dgrijalva/jwt-go", Name: "GetSigningMethod"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		renamed.String(): {ID: renamed, OwnerType: "package", OwnerName: "jwt"},
	}}
	parsed := catalogOf(graph, ecosystemGo, keys...)
	unparsed := catalogOf(nil, ecosystemGo, keys...)

	tests := []struct {
		name    string
		catalog conditionedCatalog
		call    callgraph.FunctionCall
		want    []string
	}{
		{
			name:    "major version suffix is not the package name",
			catalog: unparsed,
			call:    callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "github.com/golang-jwt/jwt/v5", Name: "GetSigningMethod"}, Raw: "jwt.GetSigningMethod"},
			want:    []string{"GetSigningMethod", "jwt.GetSigningMethod"},
		},
		{
			name:    "aliased import still names the package",
			catalog: unparsed,
			call:    callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "github.com/golang-jwt/jwt/v5", Name: "GetSigningMethod"}, Raw: "j.GetSigningMethod"},
			want:    []string{"GetSigningMethod", "jwt.GetSigningMethod"},
		},
		{
			name:    "parsed package clause wins over the path segment",
			catalog: parsed,
			call:    callgraph.FunctionCall{Callee: renamed, Raw: "jwt.GetSigningMethod"},
			want:    []string{"GetSigningMethod", "jwt.GetSigningMethod"},
		},
		{
			name:    "unparsed package falls back to the name an unaliased import binds",
			catalog: unparsed,
			call:    callgraph.FunctionCall{Callee: renamed, Raw: "jwt.GetSigningMethod"},
			want:    []string{"GetSigningMethod", "jwt-go.GetSigningMethod"},
		},
		{
			name:    "unresolved qualifier matches the call as written",
			catalog: unparsed,
			call:    callgraph.FunctionCall{Callee: callgraph.FunctionID{Name: "NewWithClaims"}, Raw: "jwt.NewWithClaims", ReceiverVar: "jwt"},
			want:    []string{"jwt.NewWithClaims"},
		},
		{
			name:    "unresolved qualifier does not match another package's key",
			catalog: unparsed,
			call:    callgraph.FunctionCall{Callee: callgraph.FunctionID{Name: "GetSigningMethod"}, Raw: "jwt.GetSigningMethod", ReceiverVar: "jwt"},
			want:    []string{"GetSigningMethod", "jwt.GetSigningMethod"},
		},
		{
			name:    "unresolved receiver variable names no package key",
			catalog: unparsed,
			call:    callgraph.FunctionCall{Callee: callgraph.FunctionID{Name: "NewWithClaims"}, Raw: "signer.NewWithClaims", ReceiverVar: "signer"},
			want:    nil,
		},
		{
			name:    "a different package of the same function name",
			catalog: unparsed,
			call:    callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "github.com/go-jose/go-jose/v4/jws", Name: "GetSigningMethod"}, Raw: "jws.GetSigningMethod"},
			want:    []string{"GetSigningMethod", "jws.GetSigningMethod"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchedKeys(tt.catalog, &tt.call); !slices.Equal(got, tt.want) {
				t.Fatalf("matched keys = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConditionedKeys_OtherEcosystemsKeepDotSuffixMatching(t *testing.T) {
	t.Parallel()

	catalog := catalogOf(nil, "python", "Cipher", "hashlib.new", "AES.new", "Crypto.Cipher.AES.new")
	call := callgraph.FunctionCall{Callee: callgraph.FunctionID{Name: "new"}}
	if got, want := matchedKeys(catalog, &call), []string{"AES.new", "Crypto.Cipher.AES.new", "hashlib.new"}; !slices.Equal(got, want) {
		t.Fatalf("bare python callee matched %q, want %q", got, want)
	}
	call = callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "cryptography.hazmat.primitives.ciphers", Name: "Cipher"}}
	if got, want := matchedKeys(catalog, &call), []string{"Cipher"}; !slices.Equal(got, want) {
		t.Fatalf("qualified python callee matched %q, want %q", got, want)
	}
}

func TestMaterializeConditionedFindings_RustQualifiedKey(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: rust.openssl.digest
    message: digest by name
    severity: INFO
    pattern: openssl::hash::MessageDigest::from_name($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: "$v"
        parameterCondition: param[0]~=(?P<v>.+)
`)
	fnID := callgraph.FunctionID{Package: "probe", Name: "digest"}
	callee := callgraph.FunctionID{Package: "openssl::hash", Type: "MessageDigest", Name: "from_name"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		fnID.String(): {
			ID: fnID, FilePath: "src/main.rs", StartLine: 1, EndLine: 3,
			Calls: []callgraph.FunctionCall{{Callee: callee, FilePath: "src/main.rs", Line: 2, StartCol: 5, EndCol: 40, Arguments: []string{`"sha256"`}}},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "src/main.rs", Language: "rust", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 2, EndLine: 2, StartCol: 5, EndCol: 40, Match: `MessageDigest::from_name("sha256")`,
		Rules: []entities.RuleInfo{{ID: "rust.openssl.anchor"}},
	}}}}}

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: ecosystemRust}, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	asset := report.Findings[0].CryptographicAssets[0]
	if asset.Rules[0].ID != "rust.openssl.digest" || asset.Metadata["algorithmName"] != "sha256" {
		t.Fatalf("materialized asset = %#v", asset)
	}
}

func TestConditionedCatalog_AppliesOnlyRulesForTheScanEcosystem(t *testing.T) {
	t.Parallel()

	rule := func(id string, languages ...string) engine.RuleCryptoMetadata {
		return engine.RuleCryptoMetadata{Rule: entities.RuleInfo{ID: id}, Languages: languages}
	}
	// One key, as the real catalog holds it: rules of several languages share
	// `bcrypt.hash`, so only the language decides which applies.
	rules := map[string][]engine.RuleCryptoMetadata{
		"bcrypt.hash": {
			rule("python.passlib.bcrypt", "python"),
			rule("rust.bcrypt.hash", "rust"),
			rule("generic.no-language"),
		},
	}
	call := callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "bcrypt", Name: "hash"}}

	tests := []struct {
		ecosystem string
		want      []string
	}{
		{ecosystem: ecosystemRust, want: []string{"generic.no-language", "rust.bcrypt.hash"}},
		{ecosystem: ecosystemPython, want: []string{"generic.no-language", "python.passlib.bcrypt"}},
		{ecosystem: "", want: []string{"generic.no-language", "python.passlib.bcrypt", "rust.bcrypt.hash"}},
	}
	for _, tt := range tests {
		catalog := conditionedCatalog{rules: rules, keys: newConditionedKeyMatcher(nil, tt.ecosystem), ecosystem: tt.ecosystem}
		if got := matchedKeys(catalog, &call); !slices.Equal(got, tt.want) {
			t.Errorf("ecosystem %q: rules = %v, want %v", tt.ecosystem, got, tt.want)
		}
	}
}

func TestRuleTargetsEcosystem_MapsSemgrepLanguages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		languages []string
		ecosystem string
		want      bool
	}{
		{[]string{"javascript", "typescript"}, ecosystemNode, true},
		{[]string{"cpp"}, ecosystemC, true},
		{[]string{"c"}, ecosystemCPP, true},
		{[]string{"Java"}, ecosystemJava, true},
		{[]string{"python"}, ecosystemJava, false},
		{[]string{"go"}, ecosystemRust, false},
		{nil, ecosystemRust, true},
		{[]string{"ruby"}, "ruby", true},
	}
	for _, tc := range cases {
		if got := ruleTargetsEcosystem(tc.languages, tc.ecosystem); got != tc.want {
			t.Errorf("ruleTargetsEcosystem(%v, %q) = %v, want %v", tc.languages, tc.ecosystem, got, tc.want)
		}
	}
}
