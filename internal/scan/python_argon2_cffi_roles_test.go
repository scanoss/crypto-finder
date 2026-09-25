// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// argon2Consumer is written the way the library's own tests/typing/api.py
// writes it: the attribute spelling `argon2.PasswordHasher()` and the
// from_parameters classmethod. Both used to leave the receiver keyed on the
// consumer's variable (`mypkg.ph.hash`), which no contract joins, so the
// supporting call shipped with no category at all.
const argon2Consumer = `import argon2
from argon2 import PasswordHasher, profiles


def attr_style(pw):
    ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    h = ph.hash(pw)
    ph.verify(h, pw)
    return ph.check_needs_rehash(h)


def from_params(pw):
    ph = PasswordHasher.from_parameters(profiles.RFC_9106_LOW_MEMORY)
    return ph.hash(pw)
`

func argon2Finding(line int, match string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: line,
		EndLine:   line,
		Match:     match,
		Rules:     []entities.RuleInfo{{ID: "python.argon2-cffi.algorithm.kdf.argon2.password-hasher"}},
		Metadata: map[string]string{
			"api":             "argon2.PasswordHasher",
			"assetType":       "algorithm",
			"algorithmFamily": "Argon2",
			"operation":       "keyderive",
		},
	}
}

func TestPythonArgon2Cffi_SupportingCallsCarryTheirLifecycleRole(t *testing.T) {
	t.Parallel()

	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "app.py",
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{
				argon2Finding(6, "argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)"),
				argon2Finding(13, "PasswordHasher.from_parameters(profiles.RFC_9106_LOW_MEMORY)"),
			},
		}},
	}
	// The production python resolver chain, as `scan` wires it. The
	// contract-only resolver behind buildPythonModuleFragment does not rekey a
	// receiver bound from a factory, so it cannot observe this contract.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(argon2Consumer), 0o600); err != nil {
		t.Fatal(err)
	}
	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewParserForEcosystem("python"))
	b.SetTypeResolver(callgraph.NewTypeResolverForEcosystem("python", javaruntime.Config{}))
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "mypkg"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	export := buildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "mypkg", Ecosystem: "python",
	})

	type site struct {
		line   int
		symbol string
	}
	got := map[site]string{}
	for _, s := range export.SupportingCalls {
		if s.SupportingCall == nil {
			continue
		}
		got[site{s.StartLine, s.SupportingCall.FunctionName}] = s.Category
	}

	for _, want := range []struct {
		site     site
		category string
	}{
		{site{7, "argon2.PasswordHasher.hash"}, "operation"},
		{site{8, "argon2.PasswordHasher.verify"}, "operation"},
		// Decodes the parameters of an existing hash; runs no Argon2.
		{site{9, "argon2.PasswordHasher.check_needs_rehash"}, "output"},
		{site{14, "argon2.PasswordHasher.hash"}, "operation"},
	} {
		category, ok := got[want.site]
		if !ok {
			t.Errorf("no supporting call %s at line %d; got %v", want.site.symbol, want.site.line, got)
			continue
		}
		if category != want.category {
			t.Errorf("%s at line %d: category = %q, want %q", want.site.symbol, want.site.line, category, want.category)
		}
	}
}
