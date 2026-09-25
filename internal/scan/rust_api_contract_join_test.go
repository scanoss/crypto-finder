// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestRustContractMethodKey(t *testing.T) {
	t.Parallel()

	for api, want := range map[string]string{
		"rsa.pkcs1v15.SigningKey.new":  "rsa::pkcs1v15::SigningKey.new",
		"aes.Aes128.decrypt_block":     "aes::Aes128.decrypt_block",
		"ring::aead.UnboundKey.new":    "ring::aead::UnboundKey.new",
		"cmac::Cmac::new_from_slice":   "cmac::Cmac.new_from_slice",
		"openssl_sys::EVP_aes_256_gcm": "openssl_sys.EVP_aes_256_gcm",
		"boring_sys.EVP_sha256":        "boring_sys.EVP_sha256",
		"aes_gcm_siv.AesGcmSiv":        "aes_gcm_siv.AesGcmSiv",
		"Aes128":                       "Aes128",
	} {
		if got := rustContractMethodKey(api); got != want {
			t.Errorf("rustContractMethodKey(%q) = %q, want %q", api, got, want)
		}
	}
}

// A Rust rule api joins the KB in its "::" spelling: as a contract method when
// the KB declares one, as a known type otherwise. An api the KB knows in neither
// form, and every non-Rust api, keeps the spelling it was written in.
func TestContractTerminalTypes(t *testing.T) {
	t.Parallel()

	rust := newExportBuildContext(&engine.DepScanResult{CallGraph: &callgraph.CallGraph{}, Ecosystem: "rust"})
	if rust.kb == nil {
		t.Fatal("rust knowledge base not loaded into the export context")
	}
	java := newExportBuildContext(&engine.DepScanResult{CallGraph: &callgraph.CallGraph{}, Ecosystem: "java"})
	if java.kb == nil {
		t.Fatal("java knowledge base not loaded into the export context")
	}

	for _, tc := range []struct {
		name        string
		ctx         *exportBuildContext
		api         string
		wantBuilder string
		wantReturn  string
	}{
		{"dotted rust method", rust, "rsa.pkcs1v15.SigningKey.new", "rsa::pkcs1v15::SigningKey", "rsa::pkcs1v15::SigningKey"},
		{"colon rust method", rust, "cmac::Cmac::new_from_slice", "cmac::Cmac", "cmac::Cmac"},
		{"rust type-only api", rust, "aes_gcm_siv.AesGcmSiv", "aes_gcm_siv::AesGcmSiv", ""},
		{"unknown rust api", rust, "nocrate.nomod.Thing.make", "nocrate.nomod.Thing", ""},
		{"single-segment rust api", rust, "Aes128", "", ""},
		{"java method", java, "javax.crypto.Cipher.getInstance", "javax.crypto.Cipher", "javax.crypto.Cipher"},
		{"rust-shaped api on java", java, "rsa.pkcs1v15.SigningKey.new", "rsa.pkcs1v15.SigningKey", ""},
	} {
		builder, ret := tc.ctx.contractTerminalTypes(tc.api)
		if builder != tc.wantBuilder || ret != tc.wantReturn {
			t.Errorf("%s: contractTerminalTypes(%q) = (%q, %q), want (%q, %q)", tc.name, tc.api, builder, ret, tc.wantBuilder, tc.wantReturn)
		}
	}
}

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
