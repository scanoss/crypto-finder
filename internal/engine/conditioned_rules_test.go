// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/conditioned"
)

const conditionedRulesYAML = `rules:
  - id: java.kdf.pbkdf2
    message: PBKDF2
    severity: info
    languages: [java]
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: $ALG
          - metavariable-regex:
              metavariable: $ALG
              regex: '"?(?P<family>PBKDF2)with(?P<prf>\w+)"?'
    pattern-sinks:
      - pattern-either:
          - pattern: SecretKeyFactory.getInstance($ALG)
          - pattern: javax.crypto.SecretKeyFactory.getInstance($ALG)
    metadata:
      purl: pkg:maven/org.bouncycastle/bcprov-jdk18on
      crypto:
        algorithmName: $family-$prf
        parameterCondition: param[0]~=^PBKDF2
  - id: python.kdf.pbkdf2
    message: PBKDF2
    severity: info
    languages: [python]
    pattern: SecretKeyFactory.getInstance($ALG)
    metadata:
      crypto:
        algorithmName: X
        parameterCondition: param[0]==x
  - id: java.unconditioned
    message: AES
    severity: info
    languages: [java]
    pattern: Cipher.getInstance($ALG)
    metadata:
      crypto:
        algorithmName: AES
`

// The catalog a application reachability request carries is the scan's own
// conditioned rules for the ecosystem: one rule however many symbols it is
// indexed under, its package URL apart from its metadata, its binders as
// sources the API compiles back, and nothing a scan would not specialize with.
func TestConditionedRules(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(conditionedRulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := ConditionedRules([]string{path}, "java")
	if len(rules) != 1 {
		t.Fatalf("%d rules, want the Java conditioned rule only: %+v", len(rules), rules)
	}
	rule := rules[0]
	if rule.ID != "java.kdf.pbkdf2" || rule.Severity != "INFO" || rule.PURL != "pkg:maven/org.bouncycastle/bcprov-jdk18on" {
		t.Errorf("rule = %+v", rule)
	}
	if _, leaked := rule.Metadata[RulePURLMetadataKey]; leaked || rule.Metadata["parameterCondition"] != "param[0]~=^PBKDF2" {
		t.Errorf("metadata = %v", rule.Metadata)
	}
	if !slices.Equal(rule.Symbols, []string{"SecretKeyFactory.getInstance", "javax.crypto.SecretKeyFactory.getInstance"}) {
		t.Errorf("symbols = %v", rule.Symbols)
	}
	catalog, err := conditioned.NewCatalog(rules)
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	spec, ok := catalog.RulesFor("javax.crypto.SecretKeyFactory.getInstance")[0].Specialize([]conditioned.Argument{{Value: `"PBKDF2withHmacSHA256"`}})
	if !ok || spec.Metadata["algorithmName"] != "PBKDF2-HmacSHA256" {
		t.Errorf("specialized through the sent binders: %v, %v; want algorithmName PBKDF2-HmacSHA256", spec.Metadata, ok)
	}
}
