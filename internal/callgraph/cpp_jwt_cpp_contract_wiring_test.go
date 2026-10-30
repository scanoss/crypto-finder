// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// parseJWTCPPSource parses one C++ translation unit with the jwt-cpp include.
func parseJWTCPPSource(t *testing.T, body string) []*FileAnalysis {
	t.Helper()
	dir := t.TempDir()
	src := "#include <jwt-cpp/jwt.h>\n#include <string>\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	return analyses
}

// The jwt-cpp contracts key on the namespace or receiver type the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the parse-only, claim and base64 calls listed
// resolve to no jwt-cpp contract.
func TestJWTCPPContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	analyses := parseJWTCPPSource(t, `void flows(jwt::builder& b, jwt::verifier& v, jwt::decoded_jwt& d,
           jwt::algorithm::hmacsha& h, jwt::algorithm::rsa& r, jwt::algorithm::ecdsa& e,
           jwt::algorithm::pss& p, jwt::algorithm::eddsa& ed, int x) {
    jwt::create();
    jwt::verify();
    jwt::verify(x);
    jwt::decode(x);
    b.sign(x);
    b.sign(x, x);
    b.sign(x, x, x);
    v.allow_algorithm(x);
    v.verify(x);
    v.verify(x, x);
    jwt::algorithm::hs256(x);
    jwt::algorithm::hs384(x);
    jwt::algorithm::hs512(x);
    jwt::algorithm::rs256(x); jwt::algorithm::rs256(x, x); jwt::algorithm::rs256(x, x, x); jwt::algorithm::rs256(x, x, x, x);
    jwt::algorithm::rs384(x); jwt::algorithm::rs384(x, x); jwt::algorithm::rs384(x, x, x); jwt::algorithm::rs384(x, x, x, x);
    jwt::algorithm::rs512(x); jwt::algorithm::rs512(x, x); jwt::algorithm::rs512(x, x, x); jwt::algorithm::rs512(x, x, x, x);
    jwt::algorithm::ps256(x); jwt::algorithm::ps256(x, x); jwt::algorithm::ps256(x, x, x); jwt::algorithm::ps256(x, x, x, x);
    jwt::algorithm::ps384(x); jwt::algorithm::ps384(x, x); jwt::algorithm::ps384(x, x, x); jwt::algorithm::ps384(x, x, x, x);
    jwt::algorithm::ps512(x); jwt::algorithm::ps512(x, x); jwt::algorithm::ps512(x, x, x); jwt::algorithm::ps512(x, x, x, x);
    jwt::algorithm::es256(x); jwt::algorithm::es256(x, x); jwt::algorithm::es256(x, x, x); jwt::algorithm::es256(x, x, x, x);
    jwt::algorithm::es384(x); jwt::algorithm::es384(x, x); jwt::algorithm::es384(x, x, x); jwt::algorithm::es384(x, x, x, x);
    jwt::algorithm::es512(x); jwt::algorithm::es512(x, x); jwt::algorithm::es512(x, x, x); jwt::algorithm::es512(x, x, x, x);
    jwt::algorithm::es256k(x); jwt::algorithm::es256k(x, x); jwt::algorithm::es256k(x, x, x); jwt::algorithm::es256k(x, x, x, x);
    jwt::algorithm::ed25519(x); jwt::algorithm::ed25519(x, x); jwt::algorithm::ed25519(x, x, x); jwt::algorithm::ed25519(x, x, x, x);
    jwt::algorithm::ed448(x); jwt::algorithm::ed448(x, x); jwt::algorithm::ed448(x, x, x); jwt::algorithm::ed448(x, x, x, x);
    h.sign(x); h.sign(x, x); h.verify(x, x); h.verify(x, x, x);
    r.sign(x); r.sign(x, x); r.verify(x, x); r.verify(x, x, x);
    e.sign(x); e.sign(x, x); e.verify(x, x); e.verify(x, x, x);
    p.sign(x); p.sign(x, x); p.verify(x, x); p.verify(x, x, x);
    ed.sign(x, x); ed.verify(x, x, x);
    jwt::decode(x, x);
    jwt::base::encode(x);
    jwt::base::decode(x);
    jwt::parse_jwk(x);
    jwt::parse_jwks(x);
    b.set_issuer(x);
    b.set_algorithm(x);
    v.with_issuer(x);
    d.get_payload_claim(x);
    h.name();
}
`)

	want := map[string]string{
		"jwt.create#0":                    "factory",
		"jwt.verify#0":                    "factory",
		"jwt.verify#1":                    "factory",
		"jwt.decode#1":                    "factory",
		"jwt::builder.sign#1":             "operation",
		"jwt::builder.sign#2":             "operation",
		"jwt::builder.sign#3":             "operation",
		"jwt::verifier.allow_algorithm#1": "config",
		"jwt::verifier.verify#1":          "operation",
		"jwt::verifier.verify#2":          "operation",
		"jwt::algorithm.hs256#1":          "factory",
		"jwt::algorithm.hs384#1":          "factory",
		"jwt::algorithm.hs512#1":          "factory",
		"jwt::algorithm::eddsa.sign#2":    "operation",
		"jwt::algorithm::eddsa.verify#3":  "operation",
	}
	for _, alg := range []string{"rs256", "rs384", "rs512", "ps256", "ps384", "ps512", "es256", "es384", "es512", "es256k", "ed25519", "ed448"} {
		for arity := 1; arity <= 4; arity++ {
			want["jwt::algorithm."+alg+"#"+strconv.Itoa(arity)] = "factory"
		}
	}
	for _, base := range []string{"hmacsha", "rsa", "ecdsa", "pss"} {
		for _, key := range []string{"sign#1", "sign#2", "verify#2", "verify#3"} {
			want["jwt::algorithm::"+base+"."+key] = "operation"
		}
	}
	negative := map[string]bool{}
	for _, key := range []string{
		"jwt.decode#2", "jwt::base.encode#1", "jwt::base.decode#1", "jwt.parse_jwk#1", "jwt.parse_jwks#1",
		"jwt::builder.set_issuer#1", "jwt::builder.set_algorithm#1", "jwt::verifier.with_issuer#1",
		"jwt::decoded_jwt.get_payload_claim#1", "jwt::algorithm::hmacsha.name#0",
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
					// Scoped to jwt-cpp: cpp-jwt shares the jwt namespace and
					// contracts its own jwt::decode at arity 2 and above.
					for i := range got {
						if got[i].SourceLibrary == "jwt-cpp" {
							t.Fatalf("%s resolved to a jwt-cpp contract, want none", key)
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
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one jwt-cpp contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "jwt-cpp" {
					t.Fatalf("contract for %q = role %q library %q, want jwt-cpp %s", key, got[0].Role, got[0].SourceLibrary, role)
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

// jwt-cpp is used as fluent chains on the temporaries jwt::create() and
// jwt::verify() return, so the parser gives the later links no receiver type.
// The chain resolver types them from the root contract, carrying the type past
// the claim calls that are not contracted, and the algorithm argument of sign
// and allow_algorithm stays operation-determining.
func TestJWTCPPFluentChainsResolveThroughRootContract(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	analyses := parseJWTCPPSource(t, `void flows(const std::string& token, const std::string& pub) {
    auto t = jwt::create().set_issuer("auth0").set_type("JWS").sign(jwt::algorithm::hs256{"secret"});
    jwt::verify().allow_algorithm(jwt::algorithm::rs256(pub)).with_issuer("auth0").verify(jwt::decode(token));
}
`)
	fns := make([]*FunctionDecl, 0)
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fns = append(fns, &analysis.Functions[i])
		}
	}
	graph := buildTestCallGraph(fns...)
	resolveFluentChainCalleesByContract(graph, kb)

	want := map[string]string{
		"jwt.create#0":                    "factory",
		"jwt::builder.sign#1":             "operation",
		"jwt.verify#0":                    "factory",
		"jwt::verifier.allow_algorithm#1": "config",
		"jwt::verifier.verify#1":          "operation",
	}
	algorithmArgument := map[string]bool{"jwt::builder.sign#1": true, "jwt::verifier.allow_algorithm#1": true}
	seen := map[string]bool{}
	for _, fn := range fns {
		for _, call := range fn.Calls {
			method := cppContractMethod(&call.Callee)
			key := method + "#" + strconv.Itoa(len(call.Arguments))
			role, ok := want[key]
			if !ok {
				continue
			}
			got := kb.ContractsFor(method, len(call.Arguments))
			if len(got) != 1 || got[0].Role != role {
				t.Fatalf("chain link %q (raw=%q) = %+v, want one %s contract", key, call.Raw, got, role)
			}
			if algorithmArgument[key] {
				params := got[0].Parameters
				if len(params) != 1 || params[0].Index == nil || *params[0].Index != 0 ||
					params[0].Role != "operation-determining" || params[0].Contributes == nil ||
					params[0].Contributes.Property != "algorithm" || params[0].Contributes.Derivation != "argument_type" {
					t.Fatalf("%s parameters = %+v, want index 0 operation-determining algorithm by argument_type", key, params)
				}
			}
			seen[key] = true
		}
	}
	for key := range want {
		if !seen[key] {
			t.Fatalf("chain resolution did not produce %q", key)
		}
	}
}
