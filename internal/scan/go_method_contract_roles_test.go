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
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// Go KBs key a method as pkg.(Type).Method. The exporter used to look
// supporting calls up by their display name, pkg.Type.Method, so every Go
// method call (an AEAD Seal, a stream XORKeyStream, a hash Write) shipped
// without a category while package-level functions carried theirs.
const chachaConsumer = `package main

import "golang.org/x/crypto/chacha20poly1305"

func encrypt(key, nonce, msg []byte) []byte {
	aead, _ := chacha20poly1305.NewX(key)
	return aead.Seal(nil, nonce, msg, nil)
}
`

func TestGoMethodSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	finding := func(line int, match string) entities.CryptographicAsset {
		return entities.CryptographicAsset{
			StartLine: line,
			EndLine:   line,
			Match:     match,
			Rules:     []entities.RuleInfo{{ID: "go.xcrypto.chacha20poly1305.aead-x"}},
			Metadata: map[string]string{
				"api":           "chacha20poly1305.NewX",
				"assetType":     "algorithm",
				"algorithmName": "XChaCha20-Poly1305",
			},
		}
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "main.go",
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{
				finding(6, "aead, _ := chacha20poly1305.NewX(key)"),
				finding(7, "aead.Seal(nil, nonce, msg, nil)"),
			},
		}},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(chachaConsumer), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("go", callgraph.NewGoParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "example.com/app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	export := buildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "example.com/app", Ecosystem: "go",
	})

	got := map[string]*graphfrag.GraphFragmentSupporting{}
	for i := range export.SupportingCalls {
		s := &export.SupportingCalls[i]
		if s.SupportingCall != nil {
			got[s.SupportingCall.FunctionName] = s
		}
	}
	for symbol, category := range map[string]string{
		"golang.org/x/crypto/chacha20poly1305.NewX": "factory",
		"crypto/cipher.AEAD.Seal":                   "operation",
	} {
		s, ok := got[symbol]
		if !ok {
			t.Errorf("no supporting call %s; got %v", symbol, keysOfSupporting(got))
			continue
		}
		if s.Category != category {
			t.Errorf("%s: category %q, want %q", symbol, s.Category, category)
		}
	}
	if s := got["crypto/cipher.AEAD.Seal"]; s != nil {
		roles := map[int]string{}
		for _, r := range s.SupportingCall.ParameterRoles {
			if r.Contributes != nil {
				roles[r.Index] = r.Contributes.Property
			}
		}
		if roles[1] != "nonce" || roles[2] != "plaintext" || roles[3] != "associatedData" {
			t.Errorf("crypto/cipher.AEAD.Seal parameter roles = %v, want nonce, plaintext and associatedData at 1-3", roles)
		}
	}
}

func keysOfSupporting(m map[string]*graphfrag.GraphFragmentSupporting) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
