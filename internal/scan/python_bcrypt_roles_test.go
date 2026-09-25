// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// bcryptModule is bcrypt 3.1.0's src/bcrypt/__init__.py reduced to its public
// signatures. Every bcrypt call a consumer writes is itself a rule terminal,
// so the contract role surfaces where the library is MINED: the synthesized
// entry point's definition-derived supporting call carries it.
const bcryptModule = `def gensalt(rounds=12, prefix=b"2b"):
    pass


def hashpw(password, salt):
    pass


def checkpw(password, hashed_password):
    pass


def kdf(password, salt, desired_key_bytes, rounds):
    pass
`

func TestPythonBcrypt_MinedSupportingCallsCarryTheirLifecycleRole(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "__init__.py"), []byte(bcryptModule), 0o600); err != nil {
		t.Fatal(err)
	}
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewParserForEcosystem("python"))
	b.SetTypeResolver(callgraph.NewTypeResolverForEcosystem("python", javaruntime.Config{}))
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "bcrypt"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	ruleBody := "rules:\n"
	for _, api := range []string{"bcrypt.gensalt", "bcrypt.hashpw", "bcrypt.checkpw", "bcrypt.kdf"} {
		ruleBody += "  - id: python.bcrypt.algorithm.kdf.bcrypt." + api[len("bcrypt."):] + "\n" +
			"    metadata:\n" +
			"      crypto:\n" +
			"        assetType: algorithm\n" +
			"        algorithmFamily: bcrypt\n" +
			"        api: " + api + "\n"
	}
	rulePath := filepath.Join(t.TempDir(), "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}
	report := &entities.InterimReport{}
	if n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python"); n != 4 {
		t.Fatalf("synthesized %d entry points, want 4 (gensalt, hashpw, checkpw, kdf)", n)
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	export := buildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "bcrypt", Ecosystem: "python",
	})

	got := map[string]string{}
	for _, s := range export.SupportingCalls {
		if s.SupportingCall != nil {
			got[s.SupportingCall.FunctionName] = s.Category
		}
	}
	for symbol, want := range map[string]string{
		"bcrypt.hashpw":  "operation",
		"bcrypt.checkpw": "operation",
		"bcrypt.kdf":     "operation",
		// Encodes a cost and random bytes into the salt hashpw consumes.
		"bcrypt.gensalt": "factory",
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

	var kdfRoles []string
	for _, ep := range export.CryptoEntryPoints {
		if ep.FunctionKey != "bcrypt.kdf" {
			continue
		}
		for _, p := range ep.ParameterRoles {
			if p.Contributes != nil {
				kdfRoles = append(kdfRoles, p.Name+"="+p.Contributes.Property)
			}
		}
	}
	if want := "desired_key_bytes=keySize rounds=iterations"; strings.Join(kdfRoles, " ") != want {
		t.Errorf("bcrypt.kdf entry point parameter roles = %q, want %q", strings.Join(kdfRoles, " "), want)
	}
}
