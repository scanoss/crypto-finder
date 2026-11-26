// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"testing"

	"github.com/scanoss/reach/callgraph"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// A Rust rule writes its api with dots and names the path a consumer imports,
// while the Rust call graph renders a declaration "ring::digest.Context.new"
// and keys a re-exported type by the private module that defines it. Scanning
// the crate itself must still surface the declaration as an entry point, and
// only the declaration of the type the api names.
func TestSynthesize_RustAPIFindsItsDeclaration(t *testing.T) {
	decl := func(pkg, typ, name, file string) *callgraph.FunctionDecl {
		return &callgraph.FunctionDecl{
			ID:        callgraph.FunctionID{Package: pkg, Type: typ, Name: name},
			FilePath:  file,
			StartLine: 10,
			EndLine:   12,
		}
	}
	contextNew := decl("ring::digest", "Context", "new", "src/digest.rs")
	pkcs1New := decl("rsa::pkcs1v15::signing_key", "SigningKey", "new", "src/pkcs1v15/signing_key.rs")
	pssNew := decl("rsa::pss::signing_key", "SigningKey", "new", "src/pss/signing_key.rs")
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{},
		PublicTypePaths: map[string][]string{
			"rsa::pkcs1v15::signing_key::SigningKey": {"rsa::pkcs1v15::SigningKey"},
			"rsa::pss::signing_key::SigningKey":      {"rsa::pss::SigningKey"},
		},
	}
	for _, d := range []*callgraph.FunctionDecl{contextNew, pkcs1New, pssNew} {
		graph.Functions[d.ID.String()] = d
	}

	for _, tc := range []struct {
		api       string
		ecosystem string
		wantFile  string
	}{
		{"ring.digest.Context.new", "rust", "src/digest.rs"},
		{"ring::digest::Context::new", "rust", "src/digest.rs"},
		{"rsa.pkcs1v15.SigningKey.new", "rust", "src/pkcs1v15/signing_key.rs"},
		{"rsa.pss.SigningKey.new", "rust", "src/pss/signing_key.rs"},
		{"ring.digest.Context.new", "", ""},
		{"rsa.pkcs1v15.signing_key.SigningKey.new", "rust", "src/pkcs1v15/signing_key.rs"},
	} {
		rule := writeRule(t, t.TempDir(), tc.api, "SHA-2")
		report := &entities.InterimReport{}
		SynthesizeRuleCryptoEntryPoints(report, graph, []string{rule}, tc.ecosystem)
		files := make([]string, 0, len(report.Findings))
		for _, f := range report.Findings {
			files = append(files, f.FilePath)
		}
		if tc.wantFile == "" {
			if len(files) != 0 {
				t.Errorf("%s (ecosystem %q): synthesized at %v, want nothing", tc.api, tc.ecosystem, files)
			}
			continue
		}
		if len(files) != 1 || files[0] != tc.wantFile {
			t.Errorf("%s: synthesized at %v, want only %s", tc.api, files, tc.wantFile)
		}
	}
}

// A trait's required method is an abstract declaration with no body: it runs
// nothing, so a rule naming the trait's method surfaces no entry point at the
// trait's signature, only at an implementation the api names.
func TestSynthesize_RustSkipsAbstractTraitMethods(t *testing.T) {
	required := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "acme::traits", Type: "DecodeKey", Name: "from_der"},
		FilePath:  "src/traits.rs",
		StartLine: 34,
		EndLine:   34,
		Abstract:  true,
	}
	impl := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "acme::key", Type: "Key", Name: "from_der"},
		FilePath:  "src/key.rs",
		StartLine: 10,
		EndLine:   12,
	}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		required.ID.String(): required,
		impl.ID.String():     impl,
	}}
	for api, want := range map[string]int{"acme.traits.DecodeKey.from_der": 0, "acme.key.Key.from_der": 1} {
		report := &entities.InterimReport{}
		SynthesizeRuleCryptoEntryPoints(report, graph, []string{writeRule(t, t.TempDir(), api, "RSA")}, "rust")
		if len(report.Findings) != want {
			t.Errorf("%s: %d findings, want %d", api, len(report.Findings), want)
		}
	}
}
