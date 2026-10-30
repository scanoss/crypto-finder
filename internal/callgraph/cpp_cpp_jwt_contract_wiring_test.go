// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// parseCPPJWTSource parses one C++ translation unit with the cpp-jwt include.
func parseCPPJWTSource(t *testing.T, body string) []*FileAnalysis {
	t.Helper()
	dir := t.TempDir()
	src := "#include <jwt/jwt.hpp>\n#include <string>\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	return analyses
}

// The cpp-jwt contracts key on the namespace or receiver type the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the JSON, claim and base64 helpers listed
// resolve to no cpp-jwt contract.
func TestCPPJWTContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	decodes := make([]string, 0, 10)
	for arity := 2; arity <= 11; arity++ {
		decodes = append(decodes, "    jwt::decode("+strings.Repeat("x, ", arity-1)+"x);")
	}
	analyses := parseCPPJWTSource(t, `void flows(jwt::jwt_object& obj, jwt::jwt_header& hdr, jwt::jwt_signature& sig, int x) {
    jwt::params::algorithm(x);
    jwt::params::algorithms(x);
    jwt::params::secret(x);
    jwt::params::verify(x);
`+strings.Join(decodes, "\n")+`
    obj.secret(x);
    obj.signature();
    obj.signature(x);
    obj.verify(x, x);
    obj.header();
    hdr.algo(x);
    sig.encode(x, x, x);
    sig.verify(x, x, x);
    jwt::base64_encode(x, x);
    jwt::base64_decode(x, x);
    jwt::base64_uri_encode(x, x);
    jwt::base64_uri_decode(x, x);
    jwt::str_to_alg(x);
    jwt::alg_to_str(x);
    jwt::params::payload(x);
    jwt::params::headers(x);
    jwt::params::issuer(x);
    jwt::params::leeway(x);
    obj.add_claim(x, x);
    obj.payload();
    obj.secret();
    hdr.algo();
    hdr.add_header(x, x);
    jwt::decode(x);
}
`)

	want := map[string]string{
		"jwt::params.algorithm#1":     "factory",
		"jwt::params.algorithms#1":    "factory",
		"jwt::params.secret#1":        "factory",
		"jwt::params.verify#1":        "factory",
		"jwt::jwt_object.secret#1":    "config",
		"jwt::jwt_object.signature#0": "operation",
		"jwt::jwt_object.signature#1": "operation",
		"jwt::jwt_object.verify#2":    "operation",
		"jwt::jwt_object.header#0":    "",
		"jwt::jwt_header.algo#1":      "config",
		"jwt::jwt_signature.encode#3": "operation",
		"jwt::jwt_signature.verify#3": "operation",
	}
	for arity := 2; arity <= 11; arity++ {
		want["jwt.decode#"+strconv.Itoa(arity)] = "operation"
	}
	negative := map[string]bool{}
	for _, key := range []string{
		"jwt.base64_encode#2", "jwt.base64_decode#2", "jwt.base64_uri_encode#2", "jwt.base64_uri_decode#2",
		"jwt.str_to_alg#1", "jwt.alg_to_str#1", "jwt::params.payload#1", "jwt::params.headers#1",
		"jwt::params.issuer#1", "jwt::params.leeway#1", "jwt::jwt_object.add_claim#2", "jwt::jwt_object.payload#0",
		"jwt::jwt_object.secret#0", "jwt::jwt_header.algo#0", "jwt::jwt_header.add_header#2", "jwt.decode#1",
	} {
		negative[key] = true
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method := cppContractMethod(&callee)
				if method == "" {
					continue
				}
				arity := len(call.Arguments)
				key := method + "#" + strconv.Itoa(arity)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					// Scoped to cpp-jwt: jwt-cpp shares the jwt namespace and
					// contracts its own jwt::decode(token) at arity 1.
					for i := range got {
						if got[i].SourceLibrary == "cpp-jwt" {
							t.Fatalf("%s resolved to a cpp-jwt contract, want none", key)
						}
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					t.Fatalf("parsed call produced unexpected key %q (raw=%q)", key, call.Raw)
				}
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one cpp-jwt contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "cpp-jwt" {
					t.Fatalf("contract for %q = role %q library %q, want cpp-jwt %q", key, got[0].Role, got[0].SourceLibrary, role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover negative %q", key)
		}
	}
}

// The algorithm, the accepted algorithms and the header algorithm are the
// operation-determining arguments, at the index each call takes them.
func TestCPPJWTAlgorithmArgumentsAreOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}
	cases := map[string]int{
		"jwt::params.algorithm#1":  0,
		"jwt::params.algorithms#1": 0,
		"jwt::jwt_header.algo#1":   0,
		"jwt::jwt_object.verify#2": 1,
	}
	for arity := 2; arity <= 11; arity++ {
		cases["jwt.decode#"+strconv.Itoa(arity)] = 1
	}
	for key, index := range cases {
		method, arityText, _ := strings.Cut(key, "#")
		arity, _ := strconv.Atoi(arityText)
		got := kb.ContractsFor(method, arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, arity, len(got))
		}
		params := got[0].Parameters
		if len(params) != 1 || params[0].Index == nil || *params[0].Index != index ||
			params[0].Role != "operation-determining" || params[0].Contributes == nil ||
			params[0].Contributes.Property != "algorithm" {
			t.Fatalf("%s parameters = %+v, want index %d operation-determining algorithm", key, params, index)
		}
	}
}

// obj.header().algo(...) is a chain on the header reference; header()'s
// return type is what resolves the algo link to jwt::jwt_header.algo.
func TestCPPJWTHeaderAlgoChainResolves(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}
	analyses := parseCPPJWTSource(t, `void set_alg(jwt::jwt_object& obj) {
    obj.header().algo(jwt::algorithm::HS384);
}
`)
	fns := make([]*FunctionDecl, 0)
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fns = append(fns, &analysis.Functions[i])
		}
	}
	resolveFluentChainCalleesByContract(buildTestCallGraph(fns...), kb)

	for _, fn := range fns {
		for _, call := range fn.Calls {
			if BaseFunctionName(call.Callee.Name) != "algo" {
				continue
			}
			got := kb.ContractsFor(cppContractMethod(&call.Callee), len(call.Arguments))
			if len(got) != 1 || got[0].Role != "config" || got[0].SourceLibrary != "cpp-jwt" {
				t.Fatalf("algo link %+v resolved to %+v, want the cpp-jwt jwt_header.algo config contract", call.Callee, got)
			}
			return
		}
	}
	t.Fatal("parsed calls did not include the algo link")
}
