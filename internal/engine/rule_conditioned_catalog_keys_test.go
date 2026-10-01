// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package engine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// conditionedCatalogKeys loads one conditioned rule whose matching section is
// body (YAML at rule indentation) and returns the catalog keys it lands under.
func conditionedCatalogKeys(t *testing.T, body string) []string {
	t.Helper()
	rule := "rules:\n" +
		"  - id: test.conditioned\n" +
		"    message: test\n" +
		"    severity: INFO\n" +
		indentYAML(body, "    ") +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmName: X\n" +
		"        parameterCondition: param[0]==x\n"
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for key, rules := range LoadRuleCryptoMetadata([]string{path}) {
		for _, r := range rules {
			if r.Rule.ID == "test.conditioned" {
				keys = append(keys, key)
			}
		}
	}
	slices.Sort(keys)
	return keys
}

func indentYAML(body, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.Trim(body, "\n"), "\n") {
		b.WriteString(prefix + line + "\n")
	}
	return b.String()
}

func TestLoadRuleCryptoMetadata_ReadsEveryPatternShape(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "top-level pattern",
			body: `pattern: Cipher.getInstance($ALG)`,
			want: []string{"Cipher.getInstance"},
		},
		{
			name: "top-level pattern-either",
			body: `
pattern-either:
  - pattern: new GMac(new GCMBlockCipher(new AESEngine()))
  - pattern: hashlib.new($NAME)`,
			want: []string{"GMac.<init>", "hashlib.new"},
		},
		{
			name: "sink pattern without patterns",
			body: `
pattern-sources:
  - pattern: Source.make(...)
pattern-sinks:
  - pattern: MessageDigest.getInstance($ALG)`,
			want: []string{"MessageDigest.getInstance"},
		},
		{
			name: "sink pattern-either without patterns",
			body: `
pattern-sources:
  - pattern: $ALG
pattern-sinks:
  - pattern-either:
      - pattern: Mac.getInstance($ALG)
      - pattern: Mac.getInstance($ALG, $PROVIDER)`,
			want: []string{"Mac.getInstance"},
		},
		{
			name: "sink patterns",
			body: `
pattern-sources:
  - patterns:
      - pattern: $ALG
pattern-sinks:
  - patterns:
      - pattern: Signature.getInstance($ALG)
      - focus-metavariable: $ALG`,
			want: []string{"Signature.getInstance"},
		},
		{
			name: "patterns inside pattern-either at any nesting",
			body: `
patterns:
  - pattern-either:
      - patterns:
          - pattern-inside: |
              import hmac
              ...
          - pattern-either:
              - pattern: hmac.new($KEY, $MSG, $DIGEST)
              - patterns:
                  - pattern: hmac.digest($KEY, $MSG, $DIGEST)
      - patterns:
          - pattern: OpenSSL::Cipher.new($NAME)`,
			want: []string{"OpenSSL::Cipher.new", "hmac.digest", "hmac.new"},
		},
		{
			name: "typed metavariable receiver names the type",
			body: `
pattern-either:
  - pattern: (AESEngine $E).init(true, ...)
  - pattern: (org.example.Builder $B).with($F)`,
			want: []string{"AESEngine.init", "org.example.Builder.with"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := conditionedCatalogKeys(t, tt.body); !slices.Equal(got, tt.want) {
				t.Fatalf("keys = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRuleCryptoMetadata_MetavariableCalleeKeys(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "anchored alternation",
			body: `
patterns:
  - pattern-inside: |
      #include "$HEADER"
      ...
  - pattern: $FUNC($CTX, $MODE, ...)
  - metavariable-regex:
      metavariable: $HEADER
      regex: '^<?tomcrypt\.h>?$'
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^(gcm_init|gcm_memory)$'`,
			want: []string{"gcm_init", "gcm_memory"},
		},
		{
			name: "alternation of anchored branches",
			body: `
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^ccm_memory$|ccm_process$'`,
			want: []string{"ccm_memory", "ccm_process"},
		},
		{
			name: "factored alternation with an optional suffix",
			body: `
patterns:
  - pattern: $FUNC($HD, $ALGO, ...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^gcry_md_(?:open|hash_buffers?)$'`,
			want: []string{"gcry_md_hash_buffer", "gcry_md_hash_buffers", "gcry_md_open"},
		},
		{
			name: "metavariable-pattern with one identifier",
			body: `
patterns:
  - pattern: $FUNC($ALG)
  - metavariable-pattern:
      metavariable: $FUNC
      pattern: EVP_get_digestbyname`,
			want: []string{"EVP_get_digestbyname"},
		},
		{
			name: "metavariable-pattern with a pattern-either of identifiers",
			body: `
patterns:
  - pattern: $FUNC($ALG)
  - metavariable-pattern:
      metavariable: $FUNC
      pattern-either:
        - pattern: EVP_get_cipherbyname
        - pattern: EVP_get_digestbyname`,
			want: []string{"EVP_get_cipherbyname", "EVP_get_digestbyname"},
		},
		{
			name: "constructor of a constrained type",
			body: `
patterns:
  - pattern: new $T($ALG)
  - metavariable-regex:
      metavariable: $T
      regex: '^(HMac|CMac)$'`,
			want: []string{"CMac.<init>", "HMac.<init>"},
		},
		{
			name: "constrained method segment",
			body: `
patterns:
  - pattern: OpenSSL::Digest.$M($NAME, ...)
  - metavariable-regex:
      metavariable: $M
      regex: '^(?:digest|new)$'`,
			want: []string{"OpenSSL::Digest.digest", "OpenSSL::Digest.new"},
		},
		{
			name: "outer constraint reaches nested alternatives",
			body: `
patterns:
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^(argon2_hash|argon2_verify)$'
  - pattern-either:
      - pattern: $FUNC($T, ...)
      - patterns:
          - pattern: $FUNC($T)`,
			want: []string{"argon2_hash", "argon2_verify"},
		},
		{
			name: "constraints on one metavariable intersect",
			body: `
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^(rsa_sign_hash_ex|rsa_verify_hash_ex)$'
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^(rsa_sign_hash_ex|rsa_encrypt_key_ex)$'`,
			want: []string{"rsa_sign_hash_ex"},
		},
		{
			name: "constraint in a sibling alternative does not apply",
			body: `
pattern-either:
  - patterns:
      - pattern: $FUNC(...)
  - patterns:
      - pattern: Other.call(...)
      - metavariable-regex:
          metavariable: $FUNC
          regex: '^gcm_init$'`,
			want: []string{"Other.call"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := conditionedCatalogKeys(t, tt.body); !slices.Equal(got, tt.want) {
				t.Fatalf("keys = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRuleCryptoMetadata_ProducesNoKeyWithoutAConcreteCallee(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "callee only inside pattern-inside and pattern-not",
			body: `
patterns:
  - pattern-inside: Cipher.getInstance(...)
  - pattern-not-inside: Mac.getInstance(...)
  - pattern-not: Signature.getInstance(...)
  - pattern: $ALG`,
		},
		{
			name: "callee only in pattern-sources",
			body: `
pattern-sources:
  - pattern: Cipher.getInstance($ALG)
pattern-sinks:
  - pattern: $BUILDER.update(...)`,
		},
		{
			name: "method on a require call",
			body: `pattern: require("crypto").createHash($ALGO)`,
		},
		{
			name: "method on a call result",
			body: `pattern: Password.hash(...).with($F)`,
		},
		{
			name: "control keyword that reads as a call",
			body: `pattern: if (hashlib.new($ALGO))`,
		},
		{
			name: "builtin new with parentheses",
			body: `pattern: new(Cipher)`,
		},
		{
			name: "unconstrained receiver metavariable",
			body: `pattern: $CRYPTO.createHash($ALGO)`,
		},
		{
			name: "unconstrained function metavariable",
			body: `pattern: $FUNC($ALGO)`,
		},
		{
			name: "unbounded regex",
			body: `
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^psa_\w+$'`,
		},
		{
			name: "regex without an end anchor",
			body: `
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: '^gcm_init'`,
		},
		{
			name: "alternation with an open branch",
			body: `
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: 'ccm_memory|ccm_process$'`,
		},
		{
			name: "case-insensitive regex",
			body: `
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: '(?i)^md5_init$'`,
		},
		{
			name: "metavariable-pattern that is not an identifier",
			body: `
patterns:
  - pattern: $FUNC(...)
  - metavariable-pattern:
      metavariable: $FUNC
      pattern: $LIB.init`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := conditionedCatalogKeys(t, tt.body); len(got) != 0 {
				t.Fatalf("keys = %q, want none", got)
			}
		})
	}
}

func TestLoadRuleCryptoMetadata_RequireCallDoesNotHideThePlainSpelling(t *testing.T) {
	got := conditionedCatalogKeys(t, `
pattern-either:
  - pattern: crypto.createHash($ALGO)
  - pattern: require("crypto").createHash($ALGO)`)
	if !slices.Equal(got, []string{"crypto.createHash"}) {
		t.Fatalf("keys = %q, want only crypto.createHash", got)
	}
}
