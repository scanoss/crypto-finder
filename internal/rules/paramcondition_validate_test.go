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

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validRuleYAML = `
rules:
  - id: java.bouncycastle.algorithm.block-cipher.aes-init-encrypt
    metadata:
      crypto:
        operation: encrypt
        parameterCondition: "param[0]==true"
        api: org.bouncycastle.crypto.engines.AESEngine.init
`

const malformedRuleYAML = `
rules:
  - id: java.bouncycastle.algorithm.block-cipher.aes-init-broken
    metadata:
      crypto:
        operation: encrypt
        parameterCondition: "param[]==true"
        api: org.bouncycastle.crypto.engines.AESEngine.init
`

const noConditionRuleYAML = `
rules:
  - id: java.jca.algorithm.digest.md5
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: MD5
`

func writeRuleFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rule fixture %s: %v", path, err)
	}
	return path
}

func TestValidateParameterConditions_ValidRuleset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRuleFile(t, dir, "valid.yaml", validRuleYAML)
	writeRuleFile(t, dir, "no-condition.yaml", noConditionRuleYAML)

	if err := ValidateParameterConditions([]string{dir}); err != nil {
		t.Fatalf("ValidateParameterConditions() = %v, want nil", err)
	}
}

func TestValidateParameterConditions_MalformedPredicateAborts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRuleFile(t, dir, "valid.yaml", validRuleYAML)
	writeRuleFile(t, dir, "broken.yaml", malformedRuleYAML)

	err := ValidateParameterConditions([]string{dir})
	if err == nil {
		t.Fatal("ValidateParameterConditions() = nil, want error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "java.bouncycastle.algorithm.block-cipher.aes-init-broken") {
		t.Errorf("error %q does not name the offending rule id", msg)
	}
	if !strings.Contains(msg, "param[]==true") {
		t.Errorf("error %q does not contain the raw malformed predicate", msg)
	}
}

func TestValidateParameterConditions_NoConditionKeyIsNil(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRuleFile(t, dir, "no-condition.yaml", noConditionRuleYAML)

	if err := ValidateParameterConditions([]string{dir}); err != nil {
		t.Fatalf("ValidateParameterConditions() = %v, want nil", err)
	}
}

func TestValidateParameterConditions_AcceptsIndividualFilePaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeRuleFile(t, dir, "valid.yaml", validRuleYAML)

	if err := ValidateParameterConditions([]string{path}); err != nil {
		t.Fatalf("ValidateParameterConditions() = %v, want nil", err)
	}
}
