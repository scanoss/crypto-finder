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
	"strings"
	"testing"
)

func TestComputeRulesHash_Deterministic(t *testing.T) {
	dir := t.TempDir()

	// Create two rule files
	rule1 := filepath.Join(dir, "rule1.yaml")
	rule2 := filepath.Join(dir, "rule2.yaml")
	if err := os.WriteFile(rule1, []byte("rule: aes-detect"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule2, []byte("rule: rsa-detect"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Same paths in different order should produce the same hash
	hash1, err := ComputeRulesHash([]string{rule1, rule2})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}
	hash2, err := ComputeRulesHash([]string{rule2, rule1})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hash should be order-independent: %q != %q", hash1, hash2)
	}

	if len(hash1) != 16 {
		t.Errorf("hash length: got %d, want 16", len(hash1))
	}
}

func TestComputeRulesHash_ChangesWithContent(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")

	if err := os.WriteFile(rule, []byte("rule: aes-detect"), 0o640); err != nil {
		t.Fatal(err)
	}
	hash1, err := ComputeRulesHash([]string{rule})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}

	// Modify the rule file content
	if err := os.WriteFile(rule, []byte("rule: aes-detect-v2"), 0o640); err != nil {
		t.Fatal(err)
	}
	hash2, err := ComputeRulesHash([]string{rule})
	if err != nil {
		t.Fatalf("ComputeRulesHash: %v", err)
	}

	if hash1 == hash2 {
		t.Error("hash should change when rule content changes")
	}
}

func TestComputeRulesHash_DirectoryPath(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	nestedDir := filepath.Join(rulesDir, "go")

	if err := os.MkdirAll(nestedDir, 0o750); err != nil {
		t.Fatal(err)
	}

	rule1 := filepath.Join(rulesDir, "base.yaml")
	rule2 := filepath.Join(nestedDir, "crypto.yml")
	nonRuleFile := filepath.Join(rulesDir, "manifest.json")

	if err := os.WriteFile(rule1, []byte("rule: base"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule2, []byte("rule: nested"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nonRuleFile, []byte(`{"checksum":"abc"}`), 0o640); err != nil {
		t.Fatal(err)
	}

	hashFromDir, err := ComputeRulesHash([]string{rulesDir})
	if err != nil {
		t.Fatalf("ComputeRulesHash directory: %v", err)
	}
	hashFromFiles, err := ComputeRulesHash([]string{rule1, rule2})
	if err != nil {
		t.Fatalf("ComputeRulesHash files: %v", err)
	}

	if hashFromDir != hashFromFiles {
		t.Errorf("directory hash should match explicit rule file hash: %q != %q", hashFromDir, hashFromFiles)
	}
}

func TestComputeRulesHash_DirectoryWithoutRuleFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, err := ComputeRulesHash([]string{dir})
	if err == nil {
		t.Fatal("expected error for directory without rule files")
	}
	if !strings.Contains(err.Error(), "no rule files found in directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeRulesHash_AllowsOverlappingRulePaths(t *testing.T) {
	rulesDir := t.TempDir()
	nestedDir := filepath.Join(rulesDir, "nested")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	rule1 := filepath.Join(rulesDir, "base.yaml")
	rule2 := filepath.Join(nestedDir, "crypto.yml")
	if err := os.WriteFile(rule1, []byte("rule: base"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule2, []byte("rule: nested"), 0o640); err != nil {
		t.Fatal(err)
	}

	hashFromOverlappingPaths, err := ComputeRulesHash([]string{rulesDir, nestedDir})
	if err != nil {
		t.Fatalf("ComputeRulesHash overlapping paths: %v", err)
	}
	hashFromDir, err := ComputeRulesHash([]string{rulesDir})
	if err != nil {
		t.Fatalf("ComputeRulesHash directory: %v", err)
	}

	if hashFromOverlappingPaths != hashFromDir {
		t.Fatalf("overlapping path hash = %q, want %q", hashFromOverlappingPaths, hashFromDir)
	}
}

func TestComputeRulesHash_EmptyPaths(t *testing.T) {
	if _, err := ComputeRulesHash(nil); err == nil || !strings.Contains(err.Error(), "no rule files provided") {
		t.Fatalf("expected no rule files provided error, got %v", err)
	}
}

func TestExpandRulePathForHash_MissingPath(t *testing.T) {
	var files []string
	seen := map[string]struct{}{}

	if _, _, err := expandRulePathForHash(filepath.Join(t.TempDir(), "missing"), &files, seen); err == nil || !strings.Contains(err.Error(), "failed to stat rule path") {
		t.Fatalf("expected stat error, got %v", err)
	}
}

func TestExpandRulePathForHash_DirectFileAndDuplicate(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(rule, []byte("rule: x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var files []string
	seen := map[string]struct{}{}

	found, added, err := expandRulePathForHash(rule, &files, seen)
	if err != nil {
		t.Fatalf("expandRulePathForHash first call: %v", err)
	}
	if !found || !added {
		t.Fatalf("expected first file call to be found+added, got found=%v added=%v", found, added)
	}

	found, added, err = expandRulePathForHash(rule, &files, seen)
	if err != nil {
		t.Fatalf("expandRulePathForHash second call: %v", err)
	}
	if !found || added {
		t.Fatalf("expected duplicate file call to be found without add, got found=%v added=%v", found, added)
	}
}

func TestAddUniqueRulePathAndIsRuleFile(t *testing.T) {
	var files []string
	seen := map[string]struct{}{}

	if !addUniqueRulePath("a.yaml", &files, seen) {
		t.Fatal("expected first addUniqueRulePath call to add file")
	}
	if addUniqueRulePath("a.yaml", &files, seen) {
		t.Fatal("expected duplicate addUniqueRulePath call to return false")
	}
	if len(files) != 1 || files[0] != "a.yaml" {
		t.Fatalf("files = %#v, want [a.yaml]", files)
	}

	if !isRuleFile("rule.yaml") || !isRuleFile("rule.YML") {
		t.Fatal("expected yaml/yml files to be recognized")
	}
	if isRuleFile("rule.json") {
		t.Fatal("expected non-yaml file to be rejected")
	}
}
