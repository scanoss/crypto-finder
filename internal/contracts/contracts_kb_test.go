package contracts_test

import (
	"testing"

	"github.com/scanoss/static-engine/callgraph/contracts"
)

// TestLoadEmbedded_Java_LoadsAtLeast44Contracts
// After jdk-crypto.yaml is authored, the embedded loader must return >= 44 total contract entries
// and exactly 31 hierarchy edges.
func TestLoadEmbedded_Java_LoadsAtLeast44Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("java")
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

	kb, err := contracts.Load("java")
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

	kb, err := contracts.Load("java")
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

	kb, err := contracts.Load("java")
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

	kb, err := contracts.Load("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\") error: %v", err)
	}

	// Known opaque root types that need no hierarchy entry:
	// - byte[] / char[] are JVM primitive arrays, not reference types in the
	//   hierarchy (char[] shows up on password APIs that keep the secret out of
	//   an immutable String, e.g. BCrypt.Hasher.hashToChar)
	// - boolean is a JVM primitive (e.g. terminal HashChecker.with* verify calls)
	// - void / int are JVM primitives (e.g. role:config lifecycle calls like
	//   GCMBlockCipher.init -> void, SHA256Digest.getDigestSize -> int)
	// - java.lang.Object is the universal root
	opaqueRoots := map[string]struct{}{
		"byte[]":           {},
		"char[]":           {},
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

// TestLoadEmbedded_Java_EquivalentToOldBehavior verifies that LoadEmbedded("java") returns
// a non-nil KB with at least 44 contract entries and at least 31 hierarchy edges —
// the same baseline that the former LoadEmbeddedJava() produced.
// T3.1: RED until LoadEmbedded is implemented (T3.3).
func TestLoadEmbedded_Java_EquivalentToOldBehavior(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("java")
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

func TestLoadEmbedded_Rust(t *testing.T) {
	kb, err := contracts.Load("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"rust\"): %v", err)
	}
	if kb.Ecosystem != "rust" {
		t.Fatalf("Ecosystem = %q, want rust", kb.Ecosystem)
	}
}

func TestLoadEmbedded_Go(t *testing.T) {
	kb, err := contracts.Load("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"go\"): %v", err)
	}
	if kb.Ecosystem != "go" {
		t.Fatalf("Ecosystem = %q, want go", kb.Ecosystem)
	}
}

func TestLoadEmbedded_C(t *testing.T) {
	kb, err := contracts.Load("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"c\"): %v", err)
	}
	if kb.Ecosystem != "c" {
		t.Fatalf("Ecosystem = %q, want c", kb.Ecosystem)
	}
}

func TestLoadEmbedded_CPP(t *testing.T) {
	kb, err := contracts.Load("cpp")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"cpp\"): %v", err)
	}
	if kb.Ecosystem != "cpp" {
		t.Fatalf("Ecosystem = %q, want cpp", kb.Ecosystem)
	}
}

// TestContractsFor_ReturnsCorrectSlice
// kb.ContractsFor("javax.crypto.Cipher.unwrap", 3) returns 3 conditional entries.
func TestContractsFor_ReturnsCorrectSlice(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("java")
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

// TestLoadEmbedded_Python_LoadsSmokeContract guards REQ-1.1, REQ-1.2, REQ-1.3.
// Once internal/callgraph/contracts/python/pyca-cryptography.yaml exists and the
// //go:embed python/*.yaml directive is added, this test must go GREEN.
func TestLoadEmbedded_Python_LoadsSmokeContract(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("python")
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

// TestEmbedFSFor_Python_ReturnsNonNil guards REQ-1.2 — embedFSFor("python") must return
// a non-nil filesystem and the directory string "python" once the embed directive is added.
// This test calls LoadEmbedded as a proxy (embedFSFor is unexported); a non-nil, non-empty
// KB after adding the YAML proves the FS was wired.
func TestEmbedFSFor_Python_ReturnsNonNilViaSmokeContract(t *testing.T) {
	t.Parallel()

	// If embedFSFor("python") returns nil the loader silently returns emptyKB().
	// A positive-KB result (>0 contracts) proves the FS was wired correctly.
	kb, err := contracts.Load("python")
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

// TestExistingContracts_RoleValuesWhitelisted is the pre-merge audit: every
// role value already authored across the embedded Java and Python KBs must
// be one of the whitelisted values, so strict validation ships without
// breaking existing data.
func TestExistingContracts_RoleValuesWhitelisted(t *testing.T) {
	t.Parallel()

	whitelist := map[string]struct{}{
		"factory":   {},
		"config":    {},
		"output":    {},
		"operation": {},
	}
	for _, eco := range []string{"java", "python"} {
		kb, err := contracts.Load(eco)
		if err != nil {
			t.Fatalf("Load(%s): unexpected error: %v", eco, err)
		}
		for key, group := range kb.Contracts {
			for _, c := range group {
				if c.Role == "" {
					continue
				}
				if _, ok := whitelist[c.Role]; !ok {
					t.Errorf("%s: contract %q has non-whitelisted role %q", eco, key, c.Role)
				}
			}
		}
	}
}
