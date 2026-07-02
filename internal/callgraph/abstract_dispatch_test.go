// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"path/filepath"
	"testing"
)

// TestBuilder_ExpandsAbstractClassDispatchToSubclassOverrides reproduces the
// exact shape of the password4j "shallow call chain" bug: HashBuilder.with
// invokes HashingFunction.hash#3 through the interface, but the interface's
// only concrete body lives on an ABSTRACT intermediate class
// (AbstractHashingFunction), which itself calls unqualified this.hash(...)
// overloads that are only implemented in leaf subclasses (PBKDF2Function).
//
// Two virtual-dispatch hops must both resolve for the backward chain trace
// from PBKDF2Function.internalHash to ever reach HashBuilder.with:
//
//  1. interface -> abstract class: HashBuilder.with calls
//     HashingFunction.hash#3; the concrete body is on AbstractHashingFunction
//     (a class, not a leaf). expandInterfaceDispatch must fan this out
//     regardless of whether the concrete owner is abstract or leaf.
//  2. abstract class -> subclass override: AbstractHashingFunction.hash#3
//     calls hash#1/hash#2 on itself (unqualified this-calls), but
//     AbstractHashingFunction never defines hash#1/hash#2 bodies -- only
//     PBKDF2Function does. The dispatch-expansion must also fan out FROM a
//     class-owned (non-interface) call site to same-name+arity overrides
//     declared on other classes in the same namespace root, not only from
//     interface-owned call sites.
func TestBuilder_ExpandsAbstractClassDispatchToSubclassOverrides(t *testing.T) {
	root := t.TempDir()

	// interface HashingFunction { hash(a); hash(a,b); hash(a,b,c); }
	ifaceHash1 := FunctionDecl{
		ID:         FunctionID{Package: "com.password4j", Type: "HashingFunction", Name: "hash#1"},
		FilePath:   filepath.Join(root, "HashingFunction.java"),
		StartLine:  1,
		EndLine:    2,
		OwnerType:  "interface",
		OwnerName:  "HashingFunction",
		Parameters: []FunctionParameter{{Type: "byte[]"}},
	}
	ifaceHash2 := FunctionDecl{
		ID:         FunctionID{Package: "com.password4j", Type: "HashingFunction", Name: "hash#2"},
		FilePath:   filepath.Join(root, "HashingFunction.java"),
		StartLine:  3,
		EndLine:    4,
		OwnerType:  "interface",
		OwnerName:  "HashingFunction",
		Parameters: []FunctionParameter{{Type: "byte[]"}, {Type: "byte[]"}},
	}
	ifaceHash3 := FunctionDecl{
		ID:         FunctionID{Package: "com.password4j", Type: "HashingFunction", Name: "hash#3"},
		FilePath:   filepath.Join(root, "HashingFunction.java"),
		StartLine:  5,
		EndLine:    6,
		OwnerType:  "interface",
		OwnerName:  "HashingFunction",
		Parameters: []FunctionParameter{{Type: "byte[]"}, {Type: "byte[]"}, {Type: "byte[]"}},
	}

	// abstract class AbstractHashingFunction implements HashingFunction {
	//   public Hash hash(byte[] plain, byte[] salt, byte[] pepper) {
	//     byte[] peppered = ...;
	//     if (salt == null) { result = hash(peppered); }        // hop 2 -> hash#1
	//     else { result = hash(peppered, salt); }                // hop 2 -> hash#2
	//   }
	// }
	// hash#1/hash#2 are NOT implemented here -- only declared abstractly. Both
	// unqualified this-calls live in the SAME hash#3 method body, mirroring the
	// real AbstractHashingFunction.hash(byte[], byte[], CharSequence) shape.
	abstractHash3 := FunctionDecl{
		ID:        FunctionID{Package: "com.password4j", Type: "AbstractHashingFunction", Name: "hash#3"},
		FilePath:  filepath.Join(root, "AbstractHashingFunction.java"),
		StartLine: 81,
		EndLine:   97,
		OwnerType: "class",
		OwnerName: "AbstractHashingFunction",
		Parameters: []FunctionParameter{
			{Type: "byte[]"}, {Type: "byte[]"}, {Type: "byte[]"},
		},
		Calls: []FunctionCall{
			{
				Callee:    FunctionID{Package: "com.password4j", Type: "AbstractHashingFunction", Name: "hash#1"},
				Raw:       "this.hash",
				FilePath:  filepath.Join(root, "AbstractHashingFunction.java"),
				Line:      88,
				Arguments: []string{"peppered"},
			},
			{
				Callee:    FunctionID{Package: "com.password4j", Type: "AbstractHashingFunction", Name: "hash#2"},
				Raw:       "this.hash",
				FilePath:  filepath.Join(root, "AbstractHashingFunction.java"),
				Line:      92,
				Arguments: []string{"peppered", "salt"},
			},
		},
	}

	// class PBKDF2Function extends AbstractHashingFunction {
	//   public Hash hash(byte[] plain) { return internalHash(...); }        // hash#1
	//   public Hash hash(byte[] plain, byte[] salt) { return internalHash(...); } // hash#2
	// }
	pbkdf2Hash1 := FunctionDecl{
		ID:         FunctionID{Package: "com.password4j", Type: "PBKDF2Function", Name: "hash#1"},
		FilePath:   filepath.Join(root, "PBKDF2Function.java"),
		StartLine:  145,
		EndLine:    150,
		OwnerType:  "class",
		OwnerName:  "PBKDF2Function",
		Parameters: []FunctionParameter{{Type: "byte[]"}},
		Calls: []FunctionCall{
			{
				Callee:    FunctionID{Package: "com.password4j", Type: "PBKDF2Function", Name: "internalHash#2"},
				Raw:       "internalHash",
				FilePath:  filepath.Join(root, "PBKDF2Function.java"),
				Line:      147,
				Arguments: []string{"plain", "salt"},
			},
		},
	}
	pbkdf2Hash2 := FunctionDecl{
		ID:        FunctionID{Package: "com.password4j", Type: "PBKDF2Function", Name: "hash#2"},
		FilePath:  filepath.Join(root, "PBKDF2Function.java"),
		StartLine: 159,
		EndLine:   167,
		OwnerType: "class",
		OwnerName: "PBKDF2Function",
		Parameters: []FunctionParameter{
			{Type: "byte[]"}, {Type: "byte[]"},
		},
		Calls: []FunctionCall{
			{
				Callee:    FunctionID{Package: "com.password4j", Type: "PBKDF2Function", Name: "internalHash#2"},
				Raw:       "internalHash",
				FilePath:  filepath.Join(root, "PBKDF2Function.java"),
				Line:      165,
				Arguments: []string{"plain", "salt"},
			},
		},
	}
	internalHash := FunctionDecl{
		ID:         FunctionID{Package: "com.password4j", Type: "PBKDF2Function", Name: "internalHash#2"},
		FilePath:   filepath.Join(root, "PBKDF2Function.java"),
		StartLine:  130,
		EndLine:    140,
		OwnerType:  "class",
		OwnerName:  "PBKDF2Function",
		Parameters: []FunctionParameter{{Type: "byte[]"}, {Type: "byte[]"}},
	}

	// class HashBuilder {
	//   public Hash with(HashingFunction hashingFunction) {
	//     return hashingFunction.hash(plainTextPassword, salt, pepper); // hop 1
	//   }
	// }
	hashBuilderWith := FunctionDecl{
		ID:        FunctionID{Package: "com.password4j", Type: "HashBuilder", Name: "with#1"},
		FilePath:  filepath.Join(root, "HashBuilder.java"),
		StartLine: 160,
		EndLine:   165,
		OwnerType: "class",
		OwnerName: "HashBuilder",
		Parameters: []FunctionParameter{
			{Type: "HashingFunction"},
		},
		Calls: []FunctionCall{
			{
				Callee:    FunctionID{Package: "com.password4j", Type: "HashingFunction", Name: "hash#3"},
				Raw:       "hashingFunction.hash",
				FilePath:  filepath.Join(root, "HashBuilder.java"),
				Line:      162,
				Arguments: []string{"plainTextPassword", "salt", "pepper"},
			},
		},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {
				{
					Functions: []FunctionDecl{
						ifaceHash1, ifaceHash2, ifaceHash3,
						abstractHash3,
						pbkdf2Hash1, pbkdf2Hash2, internalHash,
						hashBuilderWith,
					},
				},
			},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.password4j"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	hashBuilderWithKey := hashBuilderWith.ID.String()
	abstractHash3Key := abstractHash3.ID.String()
	pbkdf2Hash1Key := pbkdf2Hash1.ID.String()
	pbkdf2Hash2Key := pbkdf2Hash2.ID.String()

	// Hop 1: interface fan-out must reach the ABSTRACT class's concrete body,
	// not just leaf concrete classes.
	t.Run("hop1_interface_fans_out_to_abstract_class_body", func(t *testing.T) {
		callers := graph.Callers[abstractHash3Key]
		if !sliceContainsAbstractDispatchKey(callers, hashBuilderWithKey) {
			t.Fatalf("Callers[%s] = %v, want to include %s (interface fan-out to abstract class)",
				abstractHash3Key, callers, hashBuilderWithKey)
		}
	})

	// Hop 2: abstract class's unqualified this-calls must fan out to the
	// concrete subclass overrides that actually implement them.
	t.Run("hop2_abstract_this_call_fans_out_to_subclass_override_hash1", func(t *testing.T) {
		callers := graph.Callers[pbkdf2Hash1Key]
		if !sliceContainsAbstractDispatchKey(callers, abstractHash3Key) {
			t.Fatalf("Callers[%s] = %v, want to include %s (abstract-to-subclass dispatch)",
				pbkdf2Hash1Key, callers, abstractHash3Key)
		}
	})

	t.Run("hop2_abstract_this_call_fans_out_to_subclass_override_hash2", func(t *testing.T) {
		callers := graph.Callers[pbkdf2Hash2Key]
		if !sliceContainsAbstractDispatchKey(callers, abstractHash3Key) {
			t.Fatalf("Callers[%s] = %v, want to include %s (abstract-to-subclass dispatch)",
				pbkdf2Hash2Key, callers, abstractHash3Key)
		}
	})
}

func sliceContainsAbstractDispatchKey(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
