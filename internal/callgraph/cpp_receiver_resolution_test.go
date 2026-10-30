// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// parseCPPCalls parses one C++ file and returns each function's calls by name.
func parseCPPCalls(t *testing.T, src string) map[string][]FunctionCall {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string][]FunctionCall{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			calls[fn.ID.Name] = append(calls[fn.ID.Name], fn.Calls...)
		}
	}
	return calls
}

func findCPPCall(calls []FunctionCall, raw string) (FunctionCall, bool) {
	for i := range calls {
		if calls[i].Raw == raw {
			return calls[i], true
		}
	}
	return FunctionCall{}, false
}

// A call that is the sole element of a direct initializer binds the declared
// variable, as `T v = f()` does; a multi-argument constructor and a nested
// call argument bind nothing.
func TestCPPParser_DirectInitializationBindsVariable(t *testing.T) {
	t.Parallel()

	calls := parseCPPCalls(t, `void f(int n) {
    std::unique_ptr<Botan::HashFunction> paren(Botan::HashFunction::create("SHA-384"));
    auto brace{Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)")};
    Botan::KDF typed{Botan::KDF::create_or_throw("HKDF(SHA-256)")};
    const auto& ref = Botan::Cipher_Mode::create("AES-256/GCM", n);
    Wrapper two(Botan::StreamCipher::create("ChaCha20"), n);
    consume(Botan::BlockCipher::create("AES-128"));
    ref->set_key(n);
}
`)["f"]

	for raw, want := range map[string]string{
		"Botan::HashFunction::create":                       "paren",
		"Botan::MessageAuthenticationCode::create_or_throw": "brace",
		"Botan::KDF::create_or_throw":                       "typed",
		"Botan::Cipher_Mode::create":                        "ref",
		"Botan::StreamCipher::create":                       "",
		"Botan::BlockCipher::create":                        "",
	} {
		call, ok := findCPPCall(calls, raw)
		if !ok {
			t.Fatalf("no call %s in %#v", raw, calls)
		}
		if call.AssignedVar != want {
			t.Errorf("%s: AssignedVar = %q, want %q", raw, call.AssignedVar, want)
		}
	}
	// `const auto& ref` records ref's declared type, so the call on it is an
	// auto receiver the KB pass can type.
	if call, _ := findCPPCall(calls, "ref->set_key"); call.Callee.Type != "auto" {
		t.Errorf("ref->set_key type = %q, want auto", call.Callee.Type)
	}
}

// A templated callee is recorded under its name without the template
// arguments, and a `::` inside those arguments never splits the scope.
func TestCPPParser_TemplatedCallNames(t *testing.T) {
	t.Parallel()

	calls := parseCPPCalls(t, `void f(int s) {
    auto w = derive_free<32>(s);
    auto z = Botan::some_free<32>(s);
    auto p = libsnark::r1cs_ppzksnark_generator<libff::alt_bn128_pp>(s);
    auto c = Foo<libff::Fr>::create(s);
}
`)["f"]

	for raw, want := range map[string]FunctionID{
		"derive_free<32>":      {Package: "app", Name: "derive_free"},
		"Botan::some_free<32>": {Package: "app", Type: "Botan", Name: "some_free"},
		"libsnark::r1cs_ppzksnark_generator<libff::alt_bn128_pp>": {Package: "app", Type: "libsnark", Name: "r1cs_ppzksnark_generator"},
		"Foo<libff::Fr>::create":                                  {Package: "app", Type: "Foo<libff::Fr>", Name: "create"},
	} {
		call, ok := findCPPCall(calls, raw)
		if !ok {
			t.Errorf("no call %s in %#v", raw, calls)
			continue
		}
		if call.Callee != want {
			t.Errorf("%s: callee = %#v, want %#v", raw, call.Callee, want)
		}
	}
}

// Expressions that read like template calls are not calls. tree-sitter-cpp
// parses a cast and `a < b > (c)` as template_function calls; a is a variable.
// And `obj->m<N>(x)` is a known gap: the grammar parses it as
// `(obj->m < N) > (x)`, so no call is recorded for m at all.
func TestCPPParser_TemplateLookalikesAreNotCalls(t *testing.T) {
	t.Parallel()

	calls := parseCPPCalls(t, `void f(int a, int b, int c, Botan::KDF* kdf) {
    bool r1 = a < b > c;
    bool r2 = a < b > (c);
    auto k = kdf->derive_key<32>(c);
    long p = reinterpret_cast<long>(kdf) + static_cast<long>(a) + dynamic_cast<long>(b) + const_cast<long>(c);
}
`)["f"]
	if len(calls) != 0 {
		t.Fatalf("calls = %#v, want none", calls)
	}
}

// botanShapedKB is a test-local KB in the shape of Botan's contracts: factories
// keyed on the class, methods keyed on the declared smart pointer.
func botanShapedKB(t *testing.T) *contracts.KnowledgeBase {
	t.Helper()
	kb, err := contracts.Load([]byte(`schema_version: "2"
ecosystem: cpp
library:
  name: botan-test
contracts:
  - method: Botan::HashFunction.create
    arity: 1
    return: {type: "std::unique_ptr<Botan::HashFunction>", confidence: high}
    role: factory
  - method: Botan::MessageAuthenticationCode.create_or_throw
    arity: 1
    return: {type: "std::unique_ptr<Botan::MessageAuthenticationCode>", confidence: high}
    role: factory
  - method: Botan::PasswordHashFamily.create
    arity: 1
    return: {type: "std::unique_ptr<Botan::PasswordHashFamily>", confidence: high}
    role: factory
  - method: std::unique_ptr<Botan::PasswordHashFamily>.from_params
    arity: 3
    return: {type: "std::unique_ptr<Botan::PasswordHash>", confidence: high}
    role: factory
  - method: std::unique_ptr<Botan::PasswordHash>.derive_key
    arity: 6
    return: {type: "void", confidence: high}
    role: operation
  - method: Botan.get_cipher_mode
    arity: 2
    return: {type: "Botan::Cipher_Mode*", confidence: high}
    role: factory
  - method: Botan.secret_of
    arity: 1
    return: {type: "const Botan::SymmetricKey&", confidence: high}
`))
	if err != nil {
		t.Fatal(err)
	}
	return kb
}

func TestCPPDeducedReceiversTakeTheProducerKBType(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `void digest(int in) {
    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update(in);
}

void chain(int out) {
    auto fam = Botan::PasswordHashFamily::create("Argon2id");
    auto ph = fam->from_params(65536, 3, 1);
    ph->derive_key(out, 32, out, out, out, 16);
}

void forms(int n) {
    const auto& ref = Botan::HashFunction::create("SHA-512");
    ref->update(n);
    auto brace{Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)")};
    brace->set_key(n);
    auto* raw = Botan::get_cipher_mode("AES-128/CBC", n);
    raw->start(n);
    auto key = Botan::secret_of(n);
    key.length();
}

void shadowed(int n) {
    if (n) {
        auto h = Botan::HashFunction::create("SHA-256");
        h->update(n);
    } else {
        auto h = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
        h->update(n);
    }
}

void explicit_type(int n) {
    std::shared_ptr<Botan::HashFunction> held = Botan::HashFunction::create("SHA-256");
    held->update(n);
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystemCPP, NewCPPParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resolveCPPDeducedReceiverCallees(graph, botanShapedKB(t), ecosystemCPP)

	types := map[string]map[string][]string{}
	for _, fn := range graph.Functions {
		for _, call := range fn.Calls {
			if types[fn.ID.Name] == nil {
				types[fn.ID.Name] = map[string][]string{}
			}
			types[fn.ID.Name][call.Raw] = append(types[fn.ID.Name][call.Raw], call.Callee.Type)
		}
	}
	for _, tc := range []struct{ fn, raw, want string }{
		{"digest", "hash->update", "std::unique_ptr<Botan::HashFunction>"},
		{"chain", "fam->from_params", "std::unique_ptr<Botan::PasswordHashFamily>"},
		{"chain", "ph->derive_key", "std::unique_ptr<Botan::PasswordHash>"},
		{"forms", "ref->update", "std::unique_ptr<Botan::HashFunction>"},
		{"forms", "brace->set_key", "std::unique_ptr<Botan::MessageAuthenticationCode>"},
		{"forms", "raw->start", "Botan::Cipher_Mode"},
		{"forms", "key.length", "Botan::SymmetricKey"},
		{"explicit_type", "held->update", "std::shared_ptr<Botan::HashFunction>"},
	} {
		got := types[tc.fn][tc.raw]
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s %s: type %v, want %q", tc.fn, tc.raw, got, tc.want)
		}
	}
	// h is bound to two different factories in two blocks; the per-function
	// map cannot tell which binding a call sees, so both stay auto.
	if got := types["shadowed"]["h->update"]; !slices.Equal(got, []string{"auto", "auto"}) {
		t.Errorf("shadowed h->update types = %v, want both auto", got)
	}

	// The caller index follows the rewrite.
	digestKey := FunctionID{Package: "app", Name: "digest"}.String()
	resolvedKey := FunctionID{Package: "app", Type: "std::unique_ptr<Botan::HashFunction>", Name: "update"}.String()
	if !slices.Contains(graph.Callers[resolvedKey], digestKey) {
		t.Errorf("callers[%s] = %v, want %s", resolvedKey, graph.Callers[resolvedKey], digestKey)
	}
	autoKey := FunctionID{Package: "app", Type: "auto", Name: "update"}.String()
	if slices.Contains(graph.Callers[autoKey], digestKey) {
		t.Errorf("callers[%s] still holds %s", autoKey, digestKey)
	}
}
