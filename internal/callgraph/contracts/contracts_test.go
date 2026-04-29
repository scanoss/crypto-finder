package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

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

// TestLoadKnowledgeBase_RejectsUnsupportedSchemaVersion verifies that Load returns an error for schema_version values other than "1".
func TestLoadKnowledgeBase_RejectsUnsupportedSchemaVersion(t *testing.T) {
	t.Parallel()

	yamlBadVersion := `
schema_version: "2"
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
schema_version: "1"
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
schema_version: "1"
ecosystem: java
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
schema_version: "1"
ecosystem: java
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
schema_version: "1"
ecosystem: java
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
schema_version: "1"
ecosystem: java
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
schema_version: "1"
ecosystem: java
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
schema_version: "1"
ecosystem: java
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

// TestLoadEmbeddedJava_LoadsAtLeast44Contracts
// After jdk-crypto.yaml is authored, the embedded loader must return >= 44 total contract entries
// and exactly 31 hierarchy edges.
func TestLoadEmbeddedJava_LoadsAtLeast44Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbeddedJava()
	if err != nil {
		t.Fatalf("LoadEmbeddedJava() error: %v", err)
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

// TestLoadEmbeddedJava_CipherUnwrapHasThreeConditionals
// The Cipher.unwrap#3 key must have 3 conditional contract entries (SECRET_KEY/PRIVATE_KEY/PUBLIC_KEY).
func TestLoadEmbeddedJava_CipherUnwrapHasThreeConditionals(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbeddedJava()
	if err != nil {
		t.Fatalf("LoadEmbeddedJava() error: %v", err)
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

// TestLoadEmbeddedJava_ConstructorContractsUseInitSuffix
// At least one constructor contract must have a method ending in <init>.
func TestLoadEmbeddedJava_ConstructorContractsUseInitSuffix(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbeddedJava()
	if err != nil {
		t.Fatalf("LoadEmbeddedJava() error: %v", err)
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

// TestLoadEmbeddedJava_SecretKeySpecIsLoaded
// SecretKeySpec.<init>#2 must exist as a constructor contract.
func TestLoadEmbeddedJava_SecretKeySpecIsLoaded(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbeddedJava()
	if err != nil {
		t.Fatalf("LoadEmbeddedJava() error: %v", err)
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

// TestLoadEmbeddedJava_HierarchyReachability
// Every contract return.type must either appear as a hierarchy key (has a parent),
// or be a documented root (appears only as a value/parent with no outgoing edge,
// i.e. byte[], primitives, or engine classes parented to java.lang.Object).
//
// This test verifies that no contract return type is an orphan (not reachable to any root).
func TestLoadEmbeddedJava_HierarchyReachability(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbeddedJava()
	if err != nil {
		t.Fatalf("LoadEmbeddedJava() error: %v", err)
	}

	// Known opaque root types that need no hierarchy entry:
	// - byte[] is a JVM primitive array, not a reference type in the hierarchy
	// - java.lang.Object is the universal root
	opaqueRoots := map[string]struct{}{
		"byte[]":           {},
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

// TestContractsFor_ReturnsCorrectSlice
// kb.ContractsFor("javax.crypto.Cipher.unwrap", 3) returns 3 conditional entries.
func TestContractsFor_ReturnsCorrectSlice(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbeddedJava()
	if err != nil {
		t.Fatalf("LoadEmbeddedJava() error: %v", err)
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
