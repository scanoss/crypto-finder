// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const inheritedContractTotpSrc = `package com.example;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;

public class Totp {
    public String code(String secret) throws Exception {
        DefaultCodeGenerator generator = new DefaultCodeGenerator(HashingAlgorithm.SHA256, 8);
        return generator.generate(secret, 1L);
    }
}
`

const inheritedContractPasswordsSrc = `package com.example;

import org.springframework.security.crypto.password.LdapShaPasswordEncoder;

public class Passwords {
    public boolean roundTrip(String raw) {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder();
        String hash = encoder.encode(raw);
        return encoder.matches(raw, hash);
    }
}
`

// A consumer holds the concrete class, while the knowledge base declares the
// operation once on the interface the class implements. The call site must
// reach that contract through the hierarchy, as a scan of the library does.
func TestJavaConcreteReceiverCallCategorizedByInterfaceContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for name, src := range map[string]string{
		"Totp.java":      inheritedContractTotpSrc,
		"Passwords.java": inheritedContractPasswordsSrc,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.example:consumer"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	report := &entities.InterimReport{Findings: []entities.Finding{
		javaConstructorFinding("Totp.java", 8,
			"new DefaultCodeGenerator(HashingAlgorithm.SHA256, 8)", "dev.samstevens.totp.code.HashingAlgorithm"),
		javaConstructorFinding("Passwords.java", 7,
			"new LdapShaPasswordEncoder()", "org.springframework.security.crypto.password.LdapShaPasswordEncoder.<init>"),
	}}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	export := buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.example:consumer", Ecosystem: "java",
	})

	got := map[string]string{}
	for _, s := range export.SupportingCalls {
		if s.SupportingCall != nil {
			got[s.SupportingCall.FunctionName] = s.Category
		}
	}
	for symbol, want := range map[string]string{
		"dev.samstevens.totp.code.DefaultCodeGenerator.generate":                      "operation",
		"org.springframework.security.crypto.password.LdapShaPasswordEncoder.encode":  "operation",
		"org.springframework.security.crypto.password.LdapShaPasswordEncoder.matches": "operation",
	} {
		category, ok := got[symbol]
		if !ok {
			t.Errorf("no supporting call for %s; got %v", symbol, got)
			continue
		}
		if category != want {
			t.Errorf("%s: category = %q, want %q", symbol, category, want)
		}
	}
}

func javaConstructorFinding(file string, line int, match, api string) entities.Finding {
	return entities.Finding{
		FilePath: file,
		Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: line,
			EndLine:   line,
			Match:     match,
			Rules:     []entities.RuleInfo{{ID: "test.rule"}},
			Metadata:  map[string]string{"api": api, "assetType": "algorithm"},
		}},
	}
}

const inheritedContractKB = `
schema_version: "2"
ecosystem: %s
library:
  name: test-hierarchy
contracts:
  - method: lib.Base.run
    arity: 1
    return: {type: java.lang.String, confidence: high}
    role: config
  - method: lib.Mid.run
    arity: 1
    return: {type: java.lang.String, confidence: high}
    role: operation
  - method: lib.Leaf.run
    arity: 1
    return: {type: java.lang.String, confidence: high}
    role: output
  - method: lib.Base.<init>
    arity: 0
    return: {type: lib.Base, confidence: high}
    role: factory
hierarchy:
  lib.Leaf:
    - lib.Base
  lib.Child:
    - lib.Mid
  lib.Mid:
    - lib.Base
  lib.Base:
    - java.lang.Object
`

// The most specific declaration wins: a contract on the called class beats any
// ancestor's, and the nearest ancestor beats a farther one. Constructors are
// not inherited, and ecosystems whose hierarchy is not class inheritance keep
// the exact lookup.
func TestContractMatchesForCallWalksJavaHierarchyNearestFirst(t *testing.T) {
	t.Parallel()

	load := func(ecosystem string) *contracts.KnowledgeBase {
		kb, err := contracts.Load([]byte(fmt.Sprintf(inheritedContractKB, ecosystem)))
		if err != nil {
			t.Fatalf("load %s KB: %v", ecosystem, err)
		}
		return kb
	}
	java := &exportBuildContext{kb: load("java")}
	python := &exportBuildContext{kb: load("python")}

	tests := []struct {
		name     string
		ctx      *exportBuildContext
		callee   callgraph.FunctionID
		arity    int
		wantRole string
	}{
		{name: "own contract beats ancestor", ctx: java, callee: callgraph.FunctionID{Package: "lib", Type: "Leaf", Name: "run#1"}, arity: 1, wantRole: "output"},
		{name: "nearest ancestor beats farther", ctx: java, callee: callgraph.FunctionID{Package: "lib", Type: "Child", Name: "run#1"}, arity: 1, wantRole: "operation"},
		{name: "arity must match", ctx: java, callee: callgraph.FunctionID{Package: "lib", Type: "Child", Name: "run#2"}, arity: 2},
		{name: "constructor not inherited", ctx: java, callee: callgraph.FunctionID{Package: "lib", Type: "Mid", Name: "<init>#0"}, arity: 0},
		{name: "unknown class", ctx: java, callee: callgraph.FunctionID{Package: "lib", Type: "Stranger", Name: "run#1"}, arity: 1},
		{name: "python keeps exact lookup", ctx: python, callee: callgraph.FunctionID{Package: "lib", Type: "Child", Name: "run#1"}, arity: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matches := contractMatchesForCall(tt.ctx, &callgraph.FunctionCall{Callee: tt.callee}, tt.arity)
			if tt.wantRole == "" {
				if len(matches) != 0 {
					t.Fatalf("matches = %#v, want none", matches)
				}
				return
			}
			if len(matches) != 1 || matches[0].Role != tt.wantRole {
				t.Fatalf("matches = %#v, want one %q contract", matches, tt.wantRole)
			}
		})
	}
}
