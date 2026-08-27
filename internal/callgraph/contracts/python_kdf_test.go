// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package contracts_test

import "testing"

// TestLoadEmbeddedPython_KDFKeySizeRoles (T0.9 / row C, python-parser-parity-2)
// pins that every KDF contract this row adds/updates declares a keySize
// parameter role via argument_byte_length, with BOTH the declared Index AND
// Name populated — the keyword-name matching step (3a) needs Name; the
// positional/type-evidence-absent step (3b) needs Index — mirroring how
// jdk-crypto.yaml declares both index and name for its own keySize roles.
//
// Every arity/index value below was verified against the installed
// package's own primary source before authoring (see apply-progress.md):
// pyca-cryptography 50.0.1's own .pyi stub
// (cryptography/hazmat/bindings/_rust/openssl/kdf.pyi) for the
// cryptography.hazmat.primitives.kdf.* entries, and CPython 3.12's
// _hashlib built-in help() text for the hashlib.* entries.
//
// The argon2-cffi/bcrypt/pycryptodome(x) entries below (batch 3) were
// verified against each library's own GitHub source (not installed
// locally, but network access was available for this batch — see
// apply-progress.md for the exact URL/signature/index used for each):
//   - argon2.PasswordHasher.__init__(self, time_cost=..., memory_cost=...,
//     parallelism=..., hash_len=..., salt_len=..., encoding=..., type=...)
//     — all 7 parameters carry defaults; the arity-4 entry below models the
//     common positional-call prefix (time_cost, memory_cost, parallelism,
//     hash_len) and coexists with the pre-existing arity-0 entry (same
//     method, different arity key — no conflict).
//   - argon2.low_level.hash_secret(secret, salt, time_cost, memory_cost,
//     parallelism, hash_len, type, version=ARGON2_VERSION) — 7 required
//     params, hash_len at index 5 (pre-existing arity, role added in place).
//   - bcrypt.kdf(password, salt, desired_key_bytes, rounds,
//     ignore_few_rounds=False) — 4 required params, desired_key_bytes at
//     index 2 (pre-existing arity, role added in place).
//   - Crypto.Protocol.KDF.PBKDF2(password, salt, dkLen=16, count=1000,
//     prf=None, hmac_hash_module=None) — dkLen at index 2 (pre-existing
//     arity 3 kept — matches the common 3-positional-arg call shape; role
//     added in place).
//   - Crypto.Protocol.KDF.scrypt(password, salt, key_len, N, r, p,
//     num_keys=1) — 6 required params, key_len at index 2. The
//     PRE-EXISTING contract declared arity: 4, a latent bug (same class as
//     pyca-cryptography's Scrypt bug found in batch 2) — fixed to 6 here.
//   - Crypto.Protocol.KDF.HKDF(master, key_len, salt, hashmod,
//     num_keys=1, context=None) — 4 required params, key_len at index 1.
//     The PRE-EXISTING contract declared arity: 3, also a latent bug —
//     fixed to 4 here.
//   - Crypto.Protocol.KDF.PBKDF1(password, salt, dkLen, count=1000,
//     hashAlgo=None) — 3 required params, dkLen at index 2 — NEW contract
//     (not previously in the KB), added per this batch's explicit
//     instruction to verify it alongside PBKDF2/scrypt/HKDF.
//   - Cryptodome.Protocol.KDF.* mirrors the Crypto.* namespace identically
//     (pycryptodomex installs the same code under a different prefix).
func TestLoadEmbeddedPython_KDFKeySizeRoles(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)

	tests := []struct {
		method string
		arity  int
		index  int
		name   string
	}{
		{"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.<init>", 4, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.scrypt.Scrypt.<init>", 5, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.hkdf.HKDF.<init>", 4, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.<init>", 3, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.<init>", 3, 1, "length"},
		{"cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.<init>", 3, 1, "length"},
		{"hashlib.pbkdf2_hmac", 5, 4, "dklen"},
		{"hashlib.scrypt", 7, 6, "dklen"},
		{"argon2.PasswordHasher.<init>", 4, 3, "hash_len"},
		{"argon2.low_level.hash_secret", 7, 5, "hash_len"},
		{"bcrypt.kdf", 4, 2, "desired_key_bytes"},
		{"Crypto.Protocol.KDF.PBKDF2.<init>", 3, 2, "dkLen"},
		{"Crypto.Protocol.KDF.scrypt", 6, 2, "key_len"},
		{"Crypto.Protocol.KDF.HKDF.<init>", 4, 1, "key_len"},
		{"Crypto.Protocol.KDF.PBKDF1.<init>", 3, 2, "dkLen"},
		{"Cryptodome.Protocol.KDF.PBKDF2.<init>", 3, 2, "dkLen"},
		{"Cryptodome.Protocol.KDF.scrypt", 6, 2, "key_len"},
		{"Cryptodome.Protocol.KDF.HKDF.<init>", 4, 1, "key_len"},
		{"Cryptodome.Protocol.KDF.PBKDF1.<init>", 3, 2, "dkLen"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
			}
			for _, parameter := range got[0].Parameters {
				if parameter.Index != nil && *parameter.Index == tt.index && parameter.Name == tt.name &&
					parameter.Role == "metadata-contributing" && parameter.Contributes != nil &&
					parameter.Contributes.Property == "keySize" && parameter.Contributes.Derivation == "argument_byte_length" {
					return
				}
			}
			t.Fatalf("contract parameters = %#v, want index %d name %q role metadata-contributing contributing keySize via argument_byte_length", got[0].Parameters, tt.index, tt.name)
		})
	}
}
