// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// A Rust rule writes its api with dots ("rsa.pkcs1v15.SigningKey.new") and the
// Rust call graph joins a declaration's module, type and name with dots too,
// while the KB keys both as "rsa::pkcs1v15::SigningKey.new". The finding must
// still pick up the lifecycle methods its contract roles name, for a method api
// and for a type-only api, and must not pick up a same-named type from another
// module.
func TestRustDottedAPIFindingCarriesItsContractRoles(t *testing.T) {
	t.Parallel()

	decl := func(pkg, typ, name, file string, line int) *callgraph.FunctionDecl {
		return &callgraph.FunctionDecl{
			ID:        callgraph.FunctionID{Package: pkg, Type: typ, Name: name},
			FilePath:  file,
			StartLine: line,
		}
	}
	pkcs1New := decl("rsa::pkcs1v15", "SigningKey", "new", "src/pkcs1v15.rs", 40)
	pkcs1Random := decl("rsa::pkcs1v15", "SigningKey", "random", "src/pkcs1v15.rs", 60)
	pssNew := decl("rsa::pss", "SigningKey", "new", "src/pss.rs", 40)
	sivNew := decl("aes_gcm_siv", "AesGcmSiv", "new", "src/lib.rs", 120)
	sivEncrypt := decl("aes_gcm_siv", "AesGcmSiv", "encrypt", "src/lib.rs", 150)
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}
	for _, d := range []*callgraph.FunctionDecl{pkcs1New, pkcs1Random, pssNew, sivNew, sivEncrypt} {
		graph.Functions[d.ID.String()] = d
	}
	ctx := newExportBuildContext(&engine.DepScanResult{CallGraph: graph, Ecosystem: "rust"})

	for _, tc := range []struct {
		api       string
		want      map[string]string
		forbidden []string
	}{
		{
			api: "rsa.pkcs1v15.SigningKey.new",
			want: map[string]string{
				pkcs1New.ID.String():    "factory",
				pkcs1Random.ID.String(): "factory",
			},
			forbidden: []string{pssNew.ID.String()},
		},
		{
			api: "aes_gcm_siv.AesGcmSiv",
			want: map[string]string{
				sivNew.ID.String():     "factory",
				sivEncrypt.ID.String(): "operation",
			},
		},
	} {
		asset := entities.CryptographicAsset{
			Rules:    []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
			Metadata: map[string]string{"api": tc.api},
		}
		got := map[string]string{}
		for _, call := range deriveContractSupportingCalls(ctx, asset) {
			got[call.FunctionKey] = call.Category
		}
		for key, category := range tc.want {
			if got[key] != category {
				t.Errorf("%s: supporting call %s category = %q, want %q (got %v)", tc.api, key, got[key], category, got)
			}
		}
		for _, key := range tc.forbidden {
			if category, ok := got[key]; ok {
				t.Errorf("%s: supporting calls include %s (%s) from another module", tc.api, key, category)
			}
		}
	}
}
