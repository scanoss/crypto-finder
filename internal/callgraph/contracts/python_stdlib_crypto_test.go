// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"
)

func TestLoadEmbeddedPythonIncludesStdlibCryptoContracts(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	total := 0
	roles := make(map[string]int)
	for _, candidates := range kb.Contracts {
		for _, contract := range candidates {
			if contract.SourceLibrary != "python-stdlib-crypto" {
				continue
			}
			total++
			roles[contract.Role]++
		}
	}
	if total != 106 || roles["factory"] != 36 || roles["operation"] != 34 || roles["output"] != 28 || roles["config"] != 8 {
		t.Fatalf("stdlib inventory = %d contracts, roles %#v", total, roles)
	}

	tests := []struct {
		method, returnType, role, property string
		arity                              int
	}{
		{"hashlib.sha256", "_hashlib.HASH", "factory", "", 3},
		{"hashlib.shake_128", "_hashlib.HASHXOF", "factory", "", 3},
		{"hashlib.blake2b", "_blake2.blake2b", "factory", "outputLength", 14},
		{"hashlib.file_digest", "_hashlib.HASH", "operation", "algorithm", 2},
		{"_hashlib.HASH.update", "builtins.NoneType", "operation", "", 1},
		{"_hashlib.HASH.hexdigest", "builtins.str", "output", "", 0},
		{"_hashlib.HASHXOF.digest", "builtins.bytes", "output", "outputLength", 1},
		{"_blake2.blake2s.digest", "builtins.bytes", "output", "", 0},
		{"hmac.new", "hmac.HMAC", "factory", "algorithm", 3},
		{"hmac.HMAC.<init>", "hmac.HMAC", "factory", "keySize", 3},
		{"hmac.digest", "builtins.bytes", "operation", "algorithm", 3},
		{"hmac.HMAC.digest", "builtins.bytes", "output", "", 0},
		{"secrets.compare_digest", "builtins.bool", "operation", "authenticationTag", 2},
		{"ssl.create_default_context", "ssl.SSLContext", "factory", "", 4},
		{"ssl.SSLContext.set_ciphers", "builtins.NoneType", "config", "", 1},
		{"ssl.SSLContext.load_cert_chain", "builtins.NoneType", "config", "", 3},
		{"ssl.SSLContext.wrap_socket", "ssl.SSLSocket", "factory", "", 6},
		{"ssl.SSLContext.wrap_bio", "ssl.SSLObject", "factory", "", 5},
		{"ssl.SSLSocket.do_handshake", "builtins.NoneType", "operation", "", 1},
		{"ssl.SSLObject.getpeercert", "builtins.object", "output", "", 1},
		{"secrets.token_bytes", "builtins.bytes", "operation", "outputLength", 1},
		{"os.urandom", "builtins.bytes", "operation", "outputLength", 1},
		{"secrets.SystemRandom", "random.SystemRandom", "factory", "", 1},
		{"random.SystemRandom.randbytes", "builtins.bytes", "operation", "outputLength", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 || got[0].SourceLibrary != "python-stdlib-crypto" || got[0].Return.Type != tt.returnType || got[0].Role != tt.role {
				t.Fatalf("ContractsFor(%q, %d) = %#v, want python-stdlib-crypto %s returning %s", tt.method, tt.arity, got, tt.role, tt.returnType)
			}
			if tt.property == "" {
				return
			}
			for _, parameter := range got[0].Parameters {
				if parameter.Contributes != nil && parameter.Contributes.Property == tt.property {
					return
				}
			}
			t.Fatalf("contract parameters = %#v, want contribution for %q", got[0].Parameters, tt.property)
		})
	}

	// hashlib.new is conditional on a literal name only: an unconditional
	// entry would win over the BLAKE2 and SHAKE branches.
	returns := make(map[string]bool)
	for _, contract := range kb.ContractsFor("hashlib.new", 2) {
		if contract.When == nil {
			t.Fatalf("hashlib.new has an unconditional contract returning %s", contract.Return.Type)
		}
		returns[contract.Return.Type] = true
	}
	for _, want := range []string{"_hashlib.HASH", "_hashlib.HASHXOF", "_blake2.blake2b", "_blake2.blake2s"} {
		if !returns[want] {
			t.Fatalf("hashlib.new returns = %v, want a branch returning %s", returns, want)
		}
	}

	// Attribute assignments are rule assets, not callable identities.
	if got := kb.ContractsFor("ssl.SSLContext.minimum_version", 0); len(got) != 0 {
		t.Fatalf("ssl.SSLContext.minimum_version contracts = %#v, want none", got)
	}
}
