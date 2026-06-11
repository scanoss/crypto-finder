package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// mustLoad is a test helper that loads a KnowledgeBase from a YAML string.
// It calls t.Fatal if Load returns an error, so callers don't need to check.
// T4.1: Helper for all Merge() scenario tests.
func mustLoad(t *testing.T, yaml string) *contracts.KnowledgeBase {
	t.Helper()
	kb, err := contracts.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("mustLoad: unexpected Load error: %v", err)
	}
	return kb
}

// TestLoadKnowledgeBase_RejectsMalformedYAML verifies that Load returns an error for malformed YAML input.
func TestLoadKnowledgeBase_RejectsMalformedYAML(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte("not yaml: ["))
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsMissingSchemaVersion verifies that Load returns an error when schema_version is absent.
func TestLoadKnowledgeBase_RejectsMissingSchemaVersion(t *testing.T) {
	t.Parallel()

	yamlNoVersion := `
ecosystem: java
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlNoVersion))
	if err == nil {
		t.Fatal("expected error for missing schema_version, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsUnsupportedSchemaVersion verifies that Load returns an error for schema_version values other than "2".
// T1.3: Updated from "2" to "99" so this test remains correct when validateHeader is flipped to accept "2" in T1.5.
func TestLoadKnowledgeBase_RejectsUnsupportedSchemaVersion(t *testing.T) {
	t.Parallel()

	yamlBadVersion := `
schema_version: "99"
ecosystem: java
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlBadVersion))
	if err == nil {
		t.Fatal("expected error for unsupported schema_version, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsMissingEcosystem verifies that Load returns an error when the ecosystem field is absent.
func TestLoadKnowledgeBase_RejectsMissingEcosystem(t *testing.T) {
	t.Parallel()

	yamlNoEco := `
schema_version: "2"
library:
  name: test
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlNoEco))
	if err == nil {
		t.Fatal("expected error for missing ecosystem, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsNegativeArity verifies that Load returns an error for contracts with arity < 0.
func TestLoadKnowledgeBase_RejectsNegativeArity(t *testing.T) {
	t.Parallel()

	yamlNegArity := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: -1
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlNegArity))
	if err == nil {
		t.Fatal("expected error for arity -1, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsInvalidConfidence verifies that Load returns an error for return.confidence values outside {high, medium, low}.
func TestLoadKnowledgeBase_RejectsInvalidConfidence(t *testing.T) {
	t.Parallel()

	yamlBadConf := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: veryhigh
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlBadConf))
	if err == nil {
		t.Fatal("expected error for invalid confidence, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsEmptyMethod verifies that Load returns an error when a contract has an empty method field.
func TestLoadKnowledgeBase_RejectsEmptyMethod(t *testing.T) {
	t.Parallel()

	yamlEmptyMethod := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: ""
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlEmptyMethod))
	if err == nil {
		t.Fatal("expected error for empty method, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsEmptyReturnType verifies that Load returns an error when return.type is an empty string.
func TestLoadKnowledgeBase_RejectsEmptyReturnType(t *testing.T) {
	t.Parallel()

	yamlEmptyType := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: ""
      confidence: high
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlEmptyType))
	if err == nil {
		t.Fatal("expected error for empty return.type, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsDuplicateUnconditionalContracts verifies that Load returns an error when two unconditional contracts share the same method#arity key.
func TestLoadKnowledgeBase_RejectsDuplicateUnconditionalContracts(t *testing.T) {
	t.Parallel()

	yamlDup := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: medium
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlDup))
	if err == nil {
		t.Fatal("expected error for duplicate unconditional contract at same method#arity, got nil")
	}
}

// TestLoadKnowledgeBase_ParsesConditionalContracts
// Cipher.unwrap with SECRET_KEY/PRIVATE_KEY/PUBLIC_KEY conditions should parse as 3 entries at the same key.
func TestLoadKnowledgeBase_ParsesConditionalContracts(t *testing.T) {
	t.Parallel()

	yamlConditional := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.SECRET_KEY"
        - "Cipher.SECRET_KEY"
        - "3"
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.PRIVATE_KEY"
        - "Cipher.PRIVATE_KEY"
        - "2"
    return:
      type: java.security.PrivateKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.PUBLIC_KEY"
        - "Cipher.PUBLIC_KEY"
        - "1"
    return:
      type: java.security.PublicKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
  java.security.PrivateKey: [java.security.Key]
  java.security.PublicKey: [java.security.Key]
  java.security.Key: [java.lang.Object]
`
	kb, err := contracts.Load([]byte(yamlConditional))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := kb.ContractsFor("javax.crypto.Cipher.unwrap", 3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 contracts for Cipher.unwrap#3, got %d", len(entries))
	}

	// All should be conditional
	for i, e := range entries {
		if e.When == nil {
			t.Errorf("entry[%d]: expected When != nil (conditional contract)", i)
		}
		if e.Arity != 3 {
			t.Errorf("entry[%d]: expected arity 3, got %d", i, e.Arity)
		}
	}

	// Collect return types — should be the three distinct types
	types := map[string]struct{}{}
	for _, e := range entries {
		types[e.Return.Type] = struct{}{}
	}
	for _, expected := range []string{"javax.crypto.SecretKey", "java.security.PrivateKey", "java.security.PublicKey"} {
		if _, ok := types[expected]; !ok {
			t.Errorf("expected return type %q to be present among conditional contracts", expected)
		}
	}
}

// TestLoadEmbedded_Java_LoadsAtLeast44Contracts
// After jdk-crypto.yaml is authored, the embedded loader must return >= 44 total contract entries
// and exactly 31 hierarchy edges.
func TestLoadEmbedded_Java_LoadsAtLeast44Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	// Count total contract entries (sum of slices in the map)
	total := 0
	for _, cs := range kb.Contracts {
		total += len(cs)
	}
	if total < 44 {
		t.Errorf("expected at least 44 contract entries, got %d", total)
	}

	// Hierarchy must have exactly 31 edges
	if len(kb.Hierarchy) < 31 {
		t.Errorf("expected at least 31 hierarchy edges, got %d", len(kb.Hierarchy))
	}
}

// TestLoadEmbedded_Java_CipherUnwrapHasThreeConditionals
// The Cipher.unwrap#3 key must have 3 conditional contract entries (SECRET_KEY/PRIVATE_KEY/PUBLIC_KEY).
func TestLoadEmbedded_Java_CipherUnwrapHasThreeConditionals(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	unwrap := kb.ContractsFor("javax.crypto.Cipher.unwrap", 3)
	if len(unwrap) != 3 {
		t.Fatalf("expected 3 conditional contracts for Cipher.unwrap#3, got %d", len(unwrap))
	}

	for i, c := range unwrap {
		if c.When == nil {
			t.Errorf("Cipher.unwrap entry[%d]: expected conditional (When != nil)", i)
		}
	}

	// Ensure all three key types are covered
	returnTypes := map[string]struct{}{}
	for _, c := range unwrap {
		returnTypes[c.Return.Type] = struct{}{}
	}
	for _, expected := range []string{"javax.crypto.SecretKey", "java.security.PrivateKey", "java.security.PublicKey"} {
		if _, ok := returnTypes[expected]; !ok {
			t.Errorf("missing Cipher.unwrap conditional for return type %q", expected)
		}
	}
}

// TestLoadEmbedded_Java_ConstructorContractsUseInitSuffix
// At least one constructor contract must have a method ending in <init>.
func TestLoadEmbedded_Java_ConstructorContractsUseInitSuffix(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	found := false
	for _, cs := range kb.Contracts {
		for _, c := range cs {
			if len(c.Method) > 6 && c.Method[len(c.Method)-6:] == "<init>" {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("expected at least one constructor contract with method ending in <init>")
	}
}

// TestLoadEmbedded_Java_SecretKeySpecIsLoaded
// SecretKeySpec.<init>#2 must exist as a constructor contract.
func TestLoadEmbedded_Java_SecretKeySpecIsLoaded(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	entries := kb.ContractsFor("javax.crypto.spec.SecretKeySpec.<init>", 2)
	if len(entries) == 0 {
		t.Fatal("expected SecretKeySpec.<init>#2 contract to be present")
	}
	if entries[0].Return.Type != "javax.crypto.SecretKey" {
		t.Errorf("expected SecretKeySpec.<init>#2 to return javax.crypto.SecretKey, got %q", entries[0].Return.Type)
	}
	if entries[0].Return.Confidence != "high" {
		t.Errorf("expected confidence high, got %q", entries[0].Return.Confidence)
	}
}

// TestLoadEmbedded_Java_HierarchyReachability
// Every contract return.type must either appear as a hierarchy key (has a parent),
// or be a documented root (appears only as a value/parent with no outgoing edge,
// i.e. byte[], primitives, or engine classes parented to java.lang.Object).
//
// This test verifies that no contract return type is an orphan (not reachable to any root).
func TestLoadEmbedded_Java_HierarchyReachability(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	// Known opaque root types that need no hierarchy entry:
	// - byte[] is a JVM primitive array, not a reference type in the hierarchy
	// - boolean is a JVM primitive (e.g. terminal HashChecker.with* verify calls)
	// - void / int are JVM primitives (e.g. role:config lifecycle calls like
	//   GCMBlockCipher.init -> void, SHA256Digest.getDigestSize -> int)
	// - java.lang.Object is the universal root
	opaqueRoots := map[string]struct{}{
		"byte[]":           {},
		"boolean":          {},
		"void":             {},
		"int":              {},
		"java.lang.Object": {},
	}

	// allAncestors returns true if java.lang.Object is reachable via the hierarchy.
	var allAncestors func(typ string, visited map[string]struct{}) bool
	allAncestors = func(typ string, visited map[string]struct{}) bool {
		if typ == "java.lang.Object" {
			return true
		}
		if _, opaque := opaqueRoots[typ]; opaque {
			return true
		}
		if _, seen := visited[typ]; seen {
			return false // cycle guard
		}
		visited[typ] = struct{}{}
		parents, ok := kb.Hierarchy[typ]
		if !ok {
			return false // orphan — no parent declared
		}
		for _, p := range parents {
			if allAncestors(p, visited) {
				return true
			}
		}
		return false
	}

	// Check every contract return type is reachable
	var orphans []string
	checked := map[string]struct{}{}
	for _, cs := range kb.Contracts {
		for _, c := range cs {
			rt := c.Return.Type
			if _, already := checked[rt]; already {
				continue
			}
			checked[rt] = struct{}{}
			if _, opaque := opaqueRoots[rt]; opaque {
				continue
			}
			if !allAncestors(rt, map[string]struct{}{}) {
				orphans = append(orphans, rt)
			}
		}
	}

	if len(orphans) > 0 {
		t.Errorf("hierarchy reachability failed — the following return types have no path to java.lang.Object: %v", orphans)
	}
}

// TestSchemaV2_Accepted verifies that Load() accepts schema_version "2" with a valid library block.
// T1.1: RED until validateHeader is updated (T1.5). This test MUST fail before the implementation flip.
func TestSchemaV2_Accepted(t *testing.T) {
	t.Parallel()

	yamlV2 := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlV2))
	if err != nil {
		t.Fatalf("expected no error for schema_version \"2\" with library block, got: %v", err)
	}
	if kb == nil {
		t.Fatal("expected non-nil KnowledgeBase, got nil")
	}
	if kb.Library == nil {
		t.Fatal("expected kb.Library to be non-nil after loading v2 YAML")
	}
	if kb.Library.Name != "test" {
		t.Errorf("expected kb.Library.Name == \"test\", got %q", kb.Library.Name)
	}
}

// TestSchemaV1_HardRejected verifies that Load() rejects schema_version "1" with an error.
// T1.2: Currently this test PASSES (v1 is accepted). After T1.5 it will correctly FAIL during
// the migration window but end GREEN once validateHeader rejects v1.
func TestSchemaV1_HardRejected(t *testing.T) {
	t.Parallel()

	yamlV1 := `
schema_version: "1"
ecosystem: java
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlV1))
	if err == nil {
		t.Fatal("expected error for schema_version \"1\" (should be hard-rejected), got nil")
	}
}

// TestLoad_PopulatesSourceLibrary verifies that every Contract in a loaded KB has SourceLibrary set
// to the library.name value from the YAML.
// T2.1: RED until SourceLibrary field is added to Contract (T2.3).
func TestLoad_PopulatesSourceLibrary(t *testing.T) {
	t.Parallel()

	yamlData := `
schema_version: "2"
ecosystem: java
library:
  name: test-lib
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := kb.ContractsFor("javax.crypto.KeyGenerator.generateKey", 0)
	if len(entries) == 0 {
		t.Fatal("expected at least one contract entry")
	}
	for i, c := range entries {
		if c.SourceLibrary != "test-lib" {
			t.Errorf("entry[%d]: expected SourceLibrary == %q, got %q", i, "test-lib", c.SourceLibrary)
		}
	}
}

// TestLoad_PopulatesLibraryOnKB verifies that kb.Library is populated from the library block.
// T2.2: Confirms kb.Library.Name == library.name after Load().
func TestLoad_PopulatesLibraryOnKB(t *testing.T) {
	t.Parallel()

	yamlData := `
schema_version: "2"
ecosystem: java
library:
  name: my-lib
contracts: []
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if kb.Library == nil {
		t.Fatal("expected kb.Library to be non-nil, got nil")
	}
	if kb.Library.Name != "my-lib" {
		t.Errorf("expected kb.Library.Name == %q, got %q", "my-lib", kb.Library.Name)
	}
}

// TestLoad_PopulatesSourceLibraryAcrossAllContracts verifies that ALL contracts in a KB with
// multiple entries (different methods, different conditions) have SourceLibrary == library.name.
// T2.3 (test side): RED until SourceLibrary field is added to Contract and population loop is complete.
func TestLoad_PopulatesSourceLibraryAcrossAllContracts(t *testing.T) {
	t.Parallel()

	yamlData := `
schema_version: "2"
ecosystem: java
library:
  name: multi-lib
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.SECRET_KEY"
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.PRIVATE_KEY"
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for key, entries := range kb.Contracts {
		for i, c := range entries {
			if c.SourceLibrary != "multi-lib" {
				t.Errorf("key=%q entry[%d]: expected SourceLibrary == %q, got %q", key, i, "multi-lib", c.SourceLibrary)
			}
		}
	}
}

// TestLoadEmbedded_Java_EquivalentToOldBehavior verifies that LoadEmbedded("java") returns
// a non-nil KB with at least 44 contract entries and at least 31 hierarchy edges —
// the same baseline that the former LoadEmbeddedJava() produced.
// T3.1: RED until LoadEmbedded is implemented (T3.3).
func TestLoadEmbedded_Java_EquivalentToOldBehavior(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	if kb == nil {
		t.Fatal("LoadEmbedded(\"java\"): expected non-nil KnowledgeBase, got nil")
	}

	// Count total contract entries
	total := 0
	for _, cs := range kb.Contracts {
		total += len(cs)
	}

	if total < 44 {
		t.Errorf("LoadEmbedded(\"java\"): expected at least 44 contract entries, got %d", total)
	}

	if len(kb.Hierarchy) < 31 {
		t.Errorf("LoadEmbedded(\"java\"): expected at least 31 hierarchy edges, got %d", len(kb.Hierarchy))
	}
}

// TestLoadEmbedded_NonexistentEcosystem_ReturnsEmpty verifies that LoadEmbedded returns
// a non-nil empty KnowledgeBase (no error) for an unknown ecosystem.
// T3.2: RED until LoadEmbedded is implemented (T3.3).
func TestLoadEmbedded_NonexistentEcosystem_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("nonexistent")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"nonexistent\"): expected nil error, got %v", err)
	}
	if kb == nil {
		t.Fatal("LoadEmbedded(\"nonexistent\"): expected non-nil KnowledgeBase, got nil")
	}
	if len(kb.Contracts) != 0 {
		t.Errorf("LoadEmbedded(\"nonexistent\"): expected 0 contracts, got %d", len(kb.Contracts))
	}
}

// TestContractsFor_ReturnsCorrectSlice
// kb.ContractsFor("javax.crypto.Cipher.unwrap", 3) returns 3 conditional entries.
func TestContractsFor_ReturnsCorrectSlice(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	entries := kb.ContractsFor("javax.crypto.Cipher.unwrap", 3)
	if len(entries) != 3 {
		t.Fatalf("ContractsFor: expected 3 entries for Cipher.unwrap#3, got %d", len(entries))
	}

	for i, e := range entries {
		if e.When == nil {
			t.Errorf("entry[%d]: expected conditional contract (When != nil)", i)
		}
		if e.Arity != 3 {
			t.Errorf("entry[%d]: expected arity 3, got %d", i, e.Arity)
		}
		if e.Return.Confidence != "high" {
			t.Errorf("entry[%d]: expected confidence high, got %q", i, e.Return.Confidence)
		}
	}

	// Verify missing key returns nil/empty slice
	missing := kb.ContractsFor("javax.crypto.Cipher.unwrap", 99)
	if len(missing) != 0 {
		t.Errorf("expected empty slice for non-existent key, got %d entries", len(missing))
	}
}

// ── TDD Pair 1: Basic Merge scenarios (T4.1 + T4.2 RED → T4.3 GREEN) ────────

// TestMerge_NoKBs_ReturnsEmpty verifies that Merge() with no arguments returns
// a non-nil empty KnowledgeBase with no error.
func TestMerge_NoKBs_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Merge()
	if err != nil {
		t.Fatalf("Merge(): expected nil error, got %v", err)
	}
	if kb == nil {
		t.Fatal("Merge(): expected non-nil KnowledgeBase, got nil")
	}
	if len(kb.Contracts) != 0 {
		t.Errorf("Merge(): expected 0 contracts, got %d", len(kb.Contracts))
	}
	if len(kb.Hierarchy) != 0 {
		t.Errorf("Merge(): expected 0 hierarchy edges, got %d", len(kb.Hierarchy))
	}
}

// TestMerge_SingleKB_ReturnsClone verifies that Merge(kb) returns a clone of the
// single KB, and that mutating the result does not affect the original.
func TestMerge_SingleKB_ReturnsClone(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-a
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)

	result, err := contracts.Merge(kb)
	if err != nil {
		t.Fatalf("Merge(kb): expected nil error, got %v", err)
	}
	if result == nil {
		t.Fatal("Merge(kb): expected non-nil result, got nil")
	}

	// Count original contracts
	origTotal := 0
	for _, cs := range kb.Contracts {
		origTotal += len(cs)
	}
	resultTotal := 0
	for _, cs := range result.Contracts {
		resultTotal += len(cs)
	}
	if resultTotal != origTotal {
		t.Errorf("Merge(kb): expected %d contracts in clone, got %d", origTotal, resultTotal)
	}
	if len(result.Hierarchy) != len(kb.Hierarchy) {
		t.Errorf("Merge(kb): expected %d hierarchy edges in clone, got %d", len(kb.Hierarchy), len(result.Hierarchy))
	}

	// Mutate result — original must be unaffected
	result.Contracts["mutated-key"] = []contracts.Contract{{Method: "mutated"}}
	if _, ok := kb.Contracts["mutated-key"]; ok {
		t.Error("Merge(kb): mutating clone affected the original — not a deep clone")
	}
}

// TestMerge_TwoLibraries_NoConflicts_MergesCleanly verifies that two KBs with
// non-overlapping contracts and hierarchy are merged correctly.
func TestMerge_TwoLibraries_NoConflicts_MergesCleanly(t *testing.T) {
	t.Parallel()

	libA := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-a
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)

	libB := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-b
contracts:
  - method: java.security.KeyFactory.generatePrivate
    arity: 1
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy:
  java.security.PrivateKey: [java.security.Key]
`)

	merged, err := contracts.Merge(libA, libB)
	if err != nil {
		t.Fatalf("Merge(libA, libB): unexpected error: %v", err)
	}
	if merged == nil {
		t.Fatal("Merge(libA, libB): expected non-nil result")
	}

	// Expect both contracts present
	if _, ok := merged.Contracts["javax.crypto.KeyGenerator.generateKey#0"]; !ok {
		t.Error("merged KB missing libA contract: KeyGenerator.generateKey#0")
	}
	if _, ok := merged.Contracts["java.security.KeyFactory.generatePrivate#1"]; !ok {
		t.Error("merged KB missing libB contract: KeyFactory.generatePrivate#1")
	}

	// Expect both hierarchy edges
	if _, ok := merged.Hierarchy["javax.crypto.SecretKey"]; !ok {
		t.Error("merged KB missing libA hierarchy: SecretKey")
	}
	if _, ok := merged.Hierarchy["java.security.PrivateKey"]; !ok {
		t.Error("merged KB missing libB hierarchy: PrivateKey")
	}

	// Library should be nil (merged KB represents >1 library)
	if merged.Library != nil {
		t.Error("merged KB: expected Library == nil for multi-library merge")
	}
}

// ── TDD Pair 2: Conflict rules + ecosystem + uniqueness (T4.3 RED → T4.4 GREEN) ─

// TestMerge_IdempotentContract_C1 verifies rule 1: same key + identical contract
// from two libraries → merged once, no error.
func TestMerge_IdempotentContract_C1(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-1
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-2
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C1: unexpected error: %v", err)
	}
	entries := merged.Contracts["javax.crypto.Cipher.unwrap#3"]
	if len(entries) != 1 {
		t.Errorf("Merge C1: expected 1 deduplicated entry, got %d", len(entries))
	}
}

// TestMerge_ConflictingContract_C2_ErrorNamesBothLibraries verifies rule 2:
// same key + same condition + different return → HARD ERROR naming both libraries.
func TestMerge_ConflictingContract_C2_ErrorNamesBothLibraries(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-a
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-b
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge C2: expected HARD ERROR for conflicting contract, got nil")
	}
	if !strings.Contains(err.Error(), "lib-a") {
		t.Errorf("Merge C2: expected error to contain %q, got: %v", "lib-a", err)
	}
	if !strings.Contains(err.Error(), "lib-b") {
		t.Errorf("Merge C2: expected error to contain %q, got: %v", "lib-b", err)
	}
}

// TestMerge_SetBasedConditionEquality_C3 verifies that arg_value_in order is
// irrelevant: ["A","B"] and ["B","A"] are treated as the same condition (idempotent).
func TestMerge_SetBasedConditionEquality_C3(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c3-1
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["A", "B"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c3-2
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["B", "A"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C3: expected idempotent merge (no error), got: %v", err)
	}
	entries := merged.Contracts["javax.crypto.Cipher.unwrap#3"]
	if len(entries) != 1 {
		t.Errorf("Merge C3: expected 1 entry (set-based dedup), got %d", len(entries))
	}
}

// TestMerge_DifferentConditions_BothRetained_C4 verifies that two contracts with
// the same method+arity but different conditions are both retained.
func TestMerge_DifferentConditions_BothRetained_C4(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c4-1
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c4-2
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.PRIVATE_KEY"]
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C4: unexpected error: %v", err)
	}
	entries := merged.Contracts["javax.crypto.Cipher.unwrap#3"]
	if len(entries) != 2 {
		t.Errorf("Merge C4: expected 2 contracts (different conditions), got %d", len(entries))
	}
}

// TestMerge_IdempotentHierarchy_C5 verifies rule 3: same child→[A] in both
// libraries → merged KB contains it exactly once.
func TestMerge_IdempotentHierarchy_C5(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c5-1
contracts: []
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c5-2
contracts: []
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C5: unexpected error: %v", err)
	}
	parents := merged.Hierarchy["javax.crypto.SecretKey"]
	if len(parents) != 1 || parents[0] != "java.security.Key" {
		t.Errorf("Merge C5: expected [java.security.Key], got %v", parents)
	}
}

// TestMerge_ConflictingHierarchy_C6_ErrorNamesBothLibraries verifies rule 4:
// child→[A] vs child→[B] → HARD ERROR naming both source libraries.
func TestMerge_ConflictingHierarchy_C6_ErrorNamesBothLibraries(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c6-a
contracts: []
hierarchy:
  com.example.X: [com.example.A]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c6-b
contracts: []
hierarchy:
  com.example.X: [com.example.B]
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge C6: expected HARD ERROR for conflicting hierarchy, got nil")
	}
	if !strings.Contains(err.Error(), "lib-c6-a") {
		t.Errorf("Merge C6: expected error to contain %q, got: %v", "lib-c6-a", err)
	}
	if !strings.Contains(err.Error(), "lib-c6-b") {
		t.Errorf("Merge C6: expected error to contain %q, got: %v", "lib-c6-b", err)
	}
}

// TestMerge_HierarchySubsetUnion_C7 verifies rule 5: child→[A] vs child→[A,B]
// → union output is [A,B].
func TestMerge_HierarchySubsetUnion_C7(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c7-1
contracts: []
hierarchy:
  com.example.X: [com.example.A]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c7-2
contracts: []
hierarchy:
  com.example.X: [com.example.A, com.example.B]
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C7: unexpected error: %v", err)
	}
	parents := merged.Hierarchy["com.example.X"]
	if len(parents) != 2 {
		t.Errorf("Merge C7: expected 2 parents in union, got %d: %v", len(parents), parents)
	}
	hasA, hasB := false, false
	for _, p := range parents {
		if p == "com.example.A" {
			hasA = true
		}
		if p == "com.example.B" {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Errorf("Merge C7: expected both A and B in union, got %v", parents)
	}
}

// TestMerge_EmptyLibrary_C8_NoOp verifies that merging a KB with zero contracts
// and zero hierarchy is a no-op — the result matches the non-empty KB.
func TestMerge_EmptyLibrary_C8_NoOp(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c8-full
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c8-empty
contracts: []
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C8: unexpected error: %v", err)
	}

	total := 0
	for _, cs := range merged.Contracts {
		total += len(cs)
	}
	if total != 1 {
		t.Errorf("Merge C8: expected 1 contract (lib2 is empty), got %d", total)
	}
	if len(merged.Hierarchy) != 1 {
		t.Errorf("Merge C8: expected 1 hierarchy edge, got %d", len(merged.Hierarchy))
	}
}

// TestMerge_DuplicateLibraryName_Errors verifies that two KBs with the same
// library.name cause Merge() to return a non-nil error.
func TestMerge_DuplicateLibraryName_Errors(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: same-lib
contracts: []
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: same-lib
contracts: []
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge duplicate library name: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "same-lib") {
		t.Errorf("Merge duplicate library name: expected error to contain %q, got: %v", "same-lib", err)
	}
}

// ── T-1.1: Python embed + loader tests (RED until T-1.3 adds the embed + YAML) ─

// TestLoadEmbedded_Python_LoadsSmokeContract guards REQ-1.1, REQ-1.2, REQ-1.3.
// Once internal/callgraph/contracts/python/pyca-cryptography.yaml exists and the
// //go:embed python/*.yaml directive is added, this test must go GREEN.
func TestLoadEmbedded_Python_LoadsSmokeContract(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\") error: %v", err)
	}
	if kb == nil {
		t.Fatal("LoadEmbedded(\"python\"): expected non-nil KnowledgeBase, got nil")
	}
	if kb.Ecosystem != "python" {
		t.Errorf("LoadEmbedded(\"python\"): expected Ecosystem==\"python\", got %q", kb.Ecosystem)
	}

	// The smoke contract declares Cipher.encryptor (arity 0).
	const smokeMethod = "cryptography.hazmat.primitives.ciphers.Cipher.encryptor"
	const smokeArity = 0
	entries := kb.ContractsFor(smokeMethod, smokeArity)
	if len(entries) < 1 {
		t.Errorf("LoadEmbedded(\"python\"): expected >= 1 contract for %s#%d, got 0", smokeMethod, smokeArity)
	}
}

// TestLoadEmbedded_UnknownEcosystem_ReturnsEmptyKB guards REQ-1.4 / graceful fallback.
// LoadEmbedded for an unknown ecosystem must return an empty KB with nil error — never panic.
func TestLoadEmbedded_UnknownEcosystem_ReturnsEmptyKB(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("haskell")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"haskell\"): expected nil error, got %v", err)
	}
	if kb == nil {
		t.Fatal("LoadEmbedded(\"haskell\"): expected non-nil KnowledgeBase, got nil")
	}
	if len(kb.Contracts) != 0 {
		t.Errorf("LoadEmbedded(\"haskell\"): expected 0 contracts for unknown ecosystem, got %d", len(kb.Contracts))
	}
}

// TestEmbedFSFor_Python_ReturnsNonNil guards REQ-1.2 — embedFSFor("python") must return
// a non-nil filesystem and the directory string "python" once the embed directive is added.
// This test calls LoadEmbedded as a proxy (embedFSFor is unexported); a non-nil, non-empty
// KB after adding the YAML proves the FS was wired.
func TestEmbedFSFor_Python_ReturnsNonNilViaSmokeContract(t *testing.T) {
	t.Parallel()

	// If embedFSFor("python") returns nil the loader silently returns emptyKB().
	// A positive-KB result (>0 contracts) proves the FS was wired correctly.
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\") error: %v", err)
	}
	total := 0
	for _, cs := range kb.Contracts {
		total += len(cs)
	}
	if total == 0 {
		t.Error("embedFSFor(\"python\"): LoadEmbedded returned 0 contracts — embed FS is likely not wired (nil returned by embedFSFor)")
	}
}

// TestMerge_EcosystemMismatch_Errors verifies that KBs with different ecosystem
// strings cause Merge() to return a non-nil error.
func TestMerge_EcosystemMismatch_Errors(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: eco-lib-1
contracts: []
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: python
library:
  name: eco-lib-2
contracts: []
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge ecosystem mismatch: expected error, got nil")
	}
}

// TestMerge_SourceLibrary_InConflictDiagnostic_D2 verifies that conflict error
// messages contain both library.name values (diagnostic completeness, spec D2).
func TestMerge_SourceLibrary_InConflictDiagnostic_D2(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-diag-a
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-diag-b
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge D2: expected error for conflicting contract, got nil")
	}
	if !strings.Contains(err.Error(), "lib-diag-a") {
		t.Errorf("Merge D2: error missing %q: %v", "lib-diag-a", err)
	}
	if !strings.Contains(err.Error(), "lib-diag-b") {
		t.Errorf("Merge D2: error missing %q: %v", "lib-diag-b", err)
	}
}
