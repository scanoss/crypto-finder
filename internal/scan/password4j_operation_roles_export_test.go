// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// Every Password4J with<Algorithm>() terminal delegates to with(HashingFunction),
// and the ruleset anchors each finding on the terminal. The finding for one
// algorithm must therefore carry with() as its operation, and must not list the
// terminals of the other algorithms, which share its receiver type but are not
// part of its lifecycle.
func TestPassword4jTerminalFindingsCarryTheSharedOperationOnly(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const pkg = "com.password4j"
	decl := func(typ, name, file string, line int, ret string) *callgraph.FunctionDecl {
		return &callgraph.FunctionDecl{
			ID:         callgraph.FunctionID{Package: pkg, Type: typ, Name: name},
			FilePath:   file,
			StartLine:  line,
			ReturnType: ret,
		}
	}
	decls := []*callgraph.FunctionDecl{
		decl("Password", "hash#1", "Password.java", 57, pkg+".HashBuilder"),
		decl("Password", "check#2", "Password.java", 102, pkg+".HashChecker"),
		decl("HashBuilder", "addRandomSalt#0", "HashBuilder.java", 94, pkg+".HashBuilder"),
		decl("HashBuilder", "with#1", "HashBuilder.java", 160, pkg+".Hash"),
		decl("HashBuilder", "withBcrypt#0", "HashBuilder.java", 217, pkg+".Hash"),
		decl("HashBuilder", "withArgon2#0", "HashBuilder.java", 274, pkg+".Hash"),
		decl("HashChecker", "addPepper#1", "HashChecker.java", 70, pkg+".HashChecker"),
		decl("HashChecker", "with#1", "HashChecker.java", 141, "boolean"),
		decl("HashChecker", "withBcrypt#0", "HashChecker.java", 213, "boolean"),
		decl("HashChecker", "withScrypt#0", "HashChecker.java", 196, "boolean"),
		decl("Hash", "getResult#0", "Hash.java", 195, "java.lang.String"),
	}
	graph := &callgraph.CallGraph{Functions: make(map[string]*callgraph.FunctionDecl, len(decls))}
	for _, d := range decls {
		graph.Functions[d.ID.String()] = d
	}
	ctx := newExportBuildContext(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})
	ctx.kb = kb

	for _, tc := range []struct {
		api       string
		want      map[string]string
		forbidden []string
	}{
		{
			api: pkg + ".HashBuilder.withBcrypt",
			want: map[string]string{
				pkg + ".Password.hash":             "factory",
				pkg + ".HashBuilder.addRandomSalt": "config",
				pkg + ".HashBuilder.with":          "operation",
				pkg + ".Hash.getResult":            "output",
			},
			forbidden: []string{pkg + ".HashBuilder.withBcrypt", pkg + ".HashBuilder.withArgon2"},
		},
		{
			api: pkg + ".HashChecker.withBcrypt",
			want: map[string]string{
				pkg + ".Password.check":        "factory",
				pkg + ".HashChecker.addPepper": "config",
				pkg + ".HashChecker.with":      "operation",
			},
			forbidden: []string{pkg + ".HashChecker.withBcrypt", pkg + ".HashChecker.withScrypt"},
		},
	} {
		asset := entities.CryptographicAsset{
			Rules:    []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
			Metadata: map[string]string{"api": tc.api},
		}
		got := map[string]string{}
		for _, call := range deriveContractSupportingCalls(ctx, asset) {
			got[call.SupportingCall.FunctionName] = call.Category
		}
		for name, category := range tc.want {
			if got[name] != category {
				t.Errorf("%s: supporting call %s category = %q, want %q (got %v)", tc.api, name, got[name], category, got)
			}
		}
		for _, name := range tc.forbidden {
			if category, ok := got[name]; ok {
				t.Errorf("%s: supporting calls include terminal %s (%s)", tc.api, name, category)
			}
		}
	}
}
