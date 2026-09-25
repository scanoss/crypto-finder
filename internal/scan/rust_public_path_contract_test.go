// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// The Rust KBs name a type by the path a consumer imports
// (rsa::pkcs1v15::SigningKey), while its declarations are keyed by the private
// module that defines it (rsa::pkcs1v15::signing_key). A finding must still pick
// up the lifecycle methods declared there, through the public paths the graph
// records, and only those of the type the public path names.
func TestRustReExportedTypeCarriesItsContractRoles(t *testing.T) {
	t.Parallel()

	decl := func(pkg, typ, name, file string, line int) *callgraph.FunctionDecl {
		return &callgraph.FunctionDecl{
			ID:        callgraph.FunctionID{Package: pkg, Type: typ, Name: name},
			FilePath:  file,
			StartLine: line,
		}
	}
	pkcs1New := decl("rsa::pkcs1v15::signing_key", "SigningKey", "new", "src/pkcs1v15/signing_key.rs", 40)
	pssNew := decl("rsa::pss::signing_key", "SigningKey", "new", "src/pss/signing_key.rs", 40)
	lessSafeNew := decl("ring::aead::less_safe_key", "LessSafeKey", "new", "src/aead/less_safe_key.rs", 30)
	lessSafeSeal := decl("ring::aead::less_safe_key", "LessSafeKey", "seal_in_place_append_tag", "src/aead/less_safe_key.rs", 80)
	publicPaths := map[string][]string{
		"rsa::pkcs1v15::signing_key::SigningKey": {"rsa::pkcs1v15::SigningKey"},
		"rsa::pss::signing_key::SigningKey":      {"rsa::pss::SigningKey"},
		"ring::aead::less_safe_key::LessSafeKey": {"ring::aead::LessSafeKey"},
	}
	newCtx := func(paths map[string][]string) *exportBuildContext {
		graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}, PublicTypePaths: paths}
		for _, d := range []*callgraph.FunctionDecl{pkcs1New, pssNew, lessSafeNew, lessSafeSeal} {
			graph.Functions[d.ID.String()] = d
		}
		return newExportBuildContext(&engine.DepScanResult{CallGraph: graph, Ecosystem: "rust"})
	}
	supporting := func(ctx *exportBuildContext, api string) map[string]string {
		asset := entities.CryptographicAsset{
			Rules:    []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
			Metadata: map[string]string{"api": api},
		}
		got := map[string]string{}
		for _, call := range deriveContractSupportingCalls(ctx, asset) {
			got[call.FunctionKey] = call.Category
		}
		return got
	}

	for _, tc := range []struct {
		api       string
		want      map[string]string
		forbidden []string
	}{
		{
			api:       "rsa.pkcs1v15.SigningKey.new",
			want:      map[string]string{pkcs1New.ID.String(): "factory"},
			forbidden: []string{pssNew.ID.String()},
		},
		{
			api: "ring.aead.LessSafeKey.new",
			want: map[string]string{
				lessSafeNew.ID.String():  "factory",
				lessSafeSeal.ID.String(): "operation",
			},
		},
	} {
		got := supporting(newCtx(publicPaths), tc.api)
		for key, category := range tc.want {
			if got[key] != category {
				t.Errorf("%s: supporting call %s category = %q, want %q (got %v)", tc.api, key, got[key], category, got)
			}
		}
		for _, key := range tc.forbidden {
			if category, ok := got[key]; ok {
				t.Errorf("%s: supporting calls include %s (%s) from another type", tc.api, key, category)
			}
		}
		if without := supporting(newCtx(nil), tc.api); len(without) != 0 {
			t.Errorf("%s: without public paths the declaring module joined anyway: %v", tc.api, without)
		}
	}
}
