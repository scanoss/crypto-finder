// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

type botanCall struct {
	method string
	arity  int
	role   string
}

func botanCalls(role, method string, arities ...int) []botanCall {
	out := make([]botanCall, 0, len(arities))
	for _, arity := range arities {
		out = append(out, botanCall{method: method, arity: arity, role: role})
	}
	return out
}

func botanJoin(groups ...[]botanCall) []botanCall {
	size := 0
	for _, group := range groups {
		size += len(group)
	}
	out := make([]botanCall, 0, size)
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

// The Botan object methods, by base class, at every arity a call site can use
// in Botan 2.19.5 or 3.12.0.
var (
	botanBufferedComputation = botanJoin(
		botanCalls("operation", "update", 1, 2),
		botanCalls("operation", "update_be", 1),
		botanCalls("operation", "update_le", 1),
		botanCalls("operation", "final", 0, 1),
		botanCalls("operation", "final_stdvec", 0),
		botanCalls("operation", "process", 1, 2),
	)
	botanSetKey      = botanCalls("config", "set_key", 1, 2)
	botanStart       = botanCalls("config", "start", 0, 1, 2)
	botanMAC         = botanJoin(botanSetKey, botanStart, botanBufferedComputation, botanCalls("operation", "verify_mac", 1, 2))
	botanCipherMode  = botanJoin(botanSetKey, botanStart, botanCalls("operation", "update", 1, 2), botanCalls("operation", "process", 1, 2), botanCalls("operation", "finish", 1, 2))
	botanAEADMode    = botanJoin(botanCipherMode, botanCalls("config", "set_associated_data", 1, 2), botanCalls("config", "set_associated_data_vec", 1), botanCalls("config", "set_ad", 1), botanCalls("config", "set_associated_data_n", 2, 3))
	botanBlockCipher = botanJoin(botanSetKey, botanCalls("operation", "encrypt", 1, 2), botanCalls("operation", "decrypt", 1, 2), botanCalls("operation", "encrypt_n", 3), botanCalls("operation", "decrypt_n", 3))
	botanStream      = botanJoin(
		botanSetKey,
		botanCalls("config", "set_iv", 1, 2),
		botanCalls("config", "seek", 1),
		botanCalls("operation", "cipher", 2, 3),
		botanCalls("operation", "cipher1", 1, 2),
		botanCalls("operation", "encipher", 1),
		botanCalls("operation", "encrypt", 1),
		botanCalls("operation", "decrypt", 1),
		botanCalls("operation", "write_keystream", 1, 2),
		botanCalls("operation", "keystream_bytes", 1),
	)
	botanKDF   = botanJoin(botanCalls("operation", "derive_key", 2, 3, 4, 5, 6, 7), botanCalls("operation", "kdf", 8))
	botanPBKDF = botanJoin(
		botanCalls("operation", "pbkdf", 7),
		botanCalls("operation", "pbkdf_iterations", 5, 6),
		botanCalls("operation", "pbkdf_timed", 6, 7),
		botanCalls("operation", "derive_key", 4, 5, 6),
	)
	botanPasswordHashFamily = botanJoin(
		botanCalls("factory", "tune", 2, 3, 4),
		botanCalls("factory", "tune_params", 2, 3, 4),
		botanCalls("factory", "default_params", 0),
		botanCalls("factory", "from_iterations", 1),
		botanCalls("factory", "from_params", 1, 2, 3),
	)
	botanPasswordHash = botanJoin(botanCalls("operation", "derive_key", 6, 10), botanCalls("operation", "hash", 3, 5))
)

// The receivers the C++ parser emits for Botan objects: the std::unique_ptr
// the create() factories return, and the raw pointers Botan 2's
// get_cipher_mode, get_kdf and get_pbkdf return.
var botanReceivers = []struct {
	declared string
	calls    []botanCall
}{
	{"std::unique_ptr<Botan::HashFunction>", botanBufferedComputation},
	{"std::unique_ptr<Botan::MessageAuthenticationCode>", botanMAC},
	{"std::unique_ptr<Botan::Cipher_Mode>", botanCipherMode},
	{"Botan::Cipher_Mode*", botanCipherMode},
	{"std::unique_ptr<Botan::AEAD_Mode>", botanAEADMode},
	{"std::unique_ptr<Botan::BlockCipher>", botanBlockCipher},
	{"std::unique_ptr<Botan::StreamCipher>", botanStream},
	{"std::unique_ptr<Botan::KDF>", botanKDF},
	{"Botan::KDF*", botanKDF},
	{"std::unique_ptr<Botan::PBKDF>", botanPBKDF},
	{"Botan::PBKDF*", botanPBKDF},
	{"std::unique_ptr<Botan::PasswordHashFamily>", botanPasswordHashFamily},
	{"std::unique_ptr<Botan::PasswordHash>", botanPasswordHash},
}

// The static and free factories the detection rules anchor on.
var botanFactories = botanJoin(
	botanCalls("factory", "Botan::HashFunction::create", 1, 2),
	botanCalls("factory", "Botan::HashFunction::create_or_throw", 1, 2),
	botanCalls("factory", "Botan::MessageAuthenticationCode::create", 1, 2),
	botanCalls("factory", "Botan::MessageAuthenticationCode::create_or_throw", 1, 2),
	botanCalls("factory", "Botan::BlockCipher::create", 1, 2),
	botanCalls("factory", "Botan::BlockCipher::create_or_throw", 1, 2),
	botanCalls("factory", "Botan::StreamCipher::create", 1, 2),
	botanCalls("factory", "Botan::StreamCipher::create_or_throw", 1, 2),
	botanCalls("factory", "Botan::KDF::create", 1, 2),
	botanCalls("factory", "Botan::KDF::create_or_throw", 1, 2),
	botanCalls("factory", "Botan::PBKDF::create", 1, 2),
	botanCalls("factory", "Botan::PBKDF::create_or_throw", 1, 2),
	botanCalls("factory", "Botan::PasswordHashFamily::create", 1, 2),
	botanCalls("factory", "Botan::PasswordHashFamily::create_or_throw", 1, 2),
	botanCalls("factory", "Botan::Cipher_Mode::create", 2, 3),
	botanCalls("factory", "Botan::Cipher_Mode::create_or_throw", 2, 3),
	botanCalls("factory", "Botan::AEAD_Mode::create", 2, 3),
	botanCalls("factory", "Botan::AEAD_Mode::create_or_throw", 2, 3),
	botanCalls("factory", "Botan::get_cipher_mode", 2, 3),
	botanCalls("factory", "Botan::get_kdf", 1),
	botanCalls("factory", "Botan::get_pbkdf", 1, 2),
)

func botanArgs(arity int) string {
	return strings.TrimSuffix(strings.Repeat("x, ", arity), ", ")
}

func botanContractKey(call *FunctionCall) string {
	callee := call.Callee
	method := cppContractMethod(&callee)
	if method == "" {
		return ""
	}
	return method + "#" + strconv.Itoa(len(call.Arguments))
}

// The botan contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This writes one call per contracted method
// and arity on a receiver declared the way consumer code declares it, and pins
// that each resolves to exactly one botan contract with its lifecycle role. The
// negative half pins the getters left out and the receiver spellings that do
// not resolve (auto, the bare HashFunction).
func TestBotanContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	want := map[string]string{}
	var body strings.Builder
	for _, factory := range botanFactories {
		fmt.Fprintf(&body, "    %s(%s);\n", factory.method, botanArgs(factory.arity))
		owner := factory.method[:strings.LastIndex(factory.method, "::")]
		name := factory.method[strings.LastIndex(factory.method, "::")+2:]
		want[owner+"."+name+"#"+strconv.Itoa(factory.arity)] = factory.role
	}
	params := make([]string, 0, 2+len(botanReceivers))
	params = append(params, "int x", "Botan::HashFunction& bare_hash")
	for i, receiver := range botanReceivers {
		variable := fmt.Sprintf("r%d", i)
		params = append(params, receiver.declared+" "+variable)
		emitted := strings.TrimSuffix(receiver.declared, "*")
		for _, call := range receiver.calls {
			fmt.Fprintf(&body, "    %s->%s(%s);\n", variable, call.method, botanArgs(call.arity))
			want[emitted+"."+call.method+"#"+strconv.Itoa(call.arity)] = call.role
		}
	}
	negative := map[string]bool{
		"std::unique_ptr<Botan::HashFunction>.output_length#0":   true,
		"std::unique_ptr<Botan::HashFunction>.copy_state#0":      true,
		"std::unique_ptr<Botan::Cipher_Mode>.tag_size#0":         true,
		"std::unique_ptr<Botan::PasswordHashFamily>.providers#1": true,
		"auto.update#1":                true,
		"Botan::HashFunction.update#1": true,
		"Botan.generate_bcrypt#3":      true,
		"std::unique_ptr<Botan::MessageAuthenticationCode>.name#0": true,
	}
	src := "#include <botan/hash.h>\n\nvoid flows(" + strings.Join(params, ", ") + ") {\n" + body.String() +
		`    r0->output_length();
    r0->copy_state();
    r2->tag_size();
    r11->providers(x);
    r1->name();
    auto hash = Botan::HashFunction::create_or_throw(x);
    hash->update(x);
    bare_hash.update(x);
    Botan::generate_bcrypt(x, x, x);
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for i := range fn.Calls {
				call := &fn.Calls[i]
				key := botanContractKey(call)
				if key == "" {
					continue
				}
				method, arity := key[:strings.LastIndex(key, "#")], len(call.Arguments)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					if len(got) != 0 {
						t.Errorf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					continue
				}
				if len(got) != 1 {
					t.Errorf("ContractsFor(%q, %d) = %d, want exactly one botan contract", method, arity, len(got))
					continue
				}
				if got[0].Role != role || got[0].SourceLibrary != "botan" {
					t.Errorf("contract for %q = role %q library %q, want botan %s", key, got[0].Role, got[0].SourceLibrary, role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Errorf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Errorf("parsed calls did not cover negative %q", key)
		}
	}
}

// The algorithm spec names the primitive, a cipher mode's direction decides
// encryption or decryption, and the byte lengths contribute the key size.
func TestBotanParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}
	type role struct {
		index      int
		role       string
		property   string
		derivation string
	}
	algorithm := role{0, "operation-determining", "algorithm", "argument_value"}
	cases := []struct {
		method string
		arity  int
		want   []role
	}{
		{"Botan::HashFunction.create", 1, []role{algorithm}},
		{"Botan::MessageAuthenticationCode.create_or_throw", 2, []role{algorithm}},
		{"Botan::Cipher_Mode.create", 2, []role{algorithm, {1, "operation-determining", "operation", "argument_value"}}},
		{"Botan.get_cipher_mode", 3, []role{algorithm, {1, "operation-determining", "operation", "argument_value"}}},
		{"Botan::PasswordHashFamily.create", 1, []role{algorithm}},
		{"std::unique_ptr<Botan::AEAD_Mode>.set_key", 2, []role{{1, "metadata-contributing", "keySize", "argument_byte_length"}}},
		{"std::unique_ptr<Botan::MessageAuthenticationCode>.start", 2, []role{{1, "metadata-contributing", "nonceSize", "argument_value"}}},
		{"std::unique_ptr<Botan::StreamCipher>.set_iv", 2, []role{{1, "metadata-contributing", "ivSize", "argument_value"}}},
		{"std::unique_ptr<Botan::KDF>.derive_key", 4, []role{{0, "metadata-contributing", "keySize", "argument_byte_length"}}},
		{"Botan::PBKDF.pbkdf_iterations", 6, []role{{1, "metadata-contributing", "keySize", "argument_byte_length"}, {5, "metadata-contributing", "iterations", "argument_value"}}},
		{"std::unique_ptr<Botan::PasswordHashFamily>.from_iterations", 1, []role{{0, "metadata-contributing", "iterations", "argument_value"}}},
		{"std::unique_ptr<Botan::PasswordHash>.derive_key", 6, []role{{1, "metadata-contributing", "keySize", "argument_byte_length"}}},
	}
	for _, tc := range cases {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		params := got[0].Parameters
		if len(params) != len(tc.want) {
			t.Errorf("%s#%d parameters = %+v, want %+v", tc.method, tc.arity, params, tc.want)
			continue
		}
		for i, w := range tc.want {
			p := params[i]
			if p.Index == nil || *p.Index != w.index || p.Role != w.role || p.Contributes == nil ||
				p.Contributes.Property != w.property || p.Contributes.Derivation != w.derivation {
				t.Errorf("%s#%d parameters[%d] = %+v, want %+v", tc.method, tc.arity, i, p, w)
			}
		}
	}
}
