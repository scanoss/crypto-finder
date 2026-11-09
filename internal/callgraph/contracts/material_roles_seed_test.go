// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// materialSeed is one argument a seeded consumer receives related crypto
// material at: by position, and by keyword where the API takes one.
type materialSeed struct {
	method   string
	arity    int
	index    int
	keyword  string
	material string
}

// materialSeeds pins the consumers whose material roles the scan follows a
// random draw into. A signature read from each library's own source or
// documentation fixes every position.
var materialSeeds = map[string][]materialSeed{
	"python": {
		// cryptography: hazmat/primitives/kdf/*.pyi, ciphers/modes.py, ciphers/aead.pyi
		{"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.<init>", 4, 2, "salt", "salt"},
		{"cryptography.hazmat.primitives.kdf.hkdf.HKDF.<init>", 4, 2, "salt", "salt"},
		{"cryptography.hazmat.primitives.kdf.scrypt.Scrypt.<init>", 5, 0, "salt", "salt"},
		{"cryptography.hazmat.primitives.ciphers.modes.CBC.<init>", 1, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.CBC", 1, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.CTR", 1, 0, "nonce", "nonce"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM", 1, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM", 2, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM", 3, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.CFB.<init>", 1, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.CFB8.<init>", 1, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.OFB.<init>", 1, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.CTR.<init>", 1, 0, "nonce", "nonce"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM.<init>", 1, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM.<init>", 2, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM.<init>", 3, 0, "initialization_vector", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.aead.AESGCM.encrypt", 3, 0, "nonce", "nonce"},
		{"cryptography.hazmat.primitives.ciphers.aead.AESGCM.decrypt", 3, 0, "nonce", "nonce"},
		{"cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.encrypt", 3, 0, "nonce", "nonce"},
		{"cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.decrypt", 3, 0, "nonce", "nonce"},
		// pycryptodome and pycryptodomex: Cipher/AES.py, Protocol/KDF.py. AES.new's
		// third positional argument is the iv or the nonce by mode, so only its
		// keywords carry a role (index -1: none by position).
		{"Crypto.Cipher.AES.new", 3, -1, "iv", "initialization-vector"},
		{"Crypto.Cipher.AES.new", 4, -1, "iv", "initialization-vector"},
		{"Crypto.Cipher.AES.new", 3, -1, "IV", "initialization-vector"},
		{"Crypto.Cipher.AES.new", 4, -1, "IV", "initialization-vector"},
		{"Crypto.Cipher.AES.new", 3, -1, "nonce", "nonce"},
		{"Crypto.Cipher.AES.new", 4, -1, "nonce", "nonce"},
		{"Cryptodome.Cipher.AES.new", 3, -1, "nonce", "nonce"},
		{"Cryptodome.Cipher.AES.new", 4, -1, "nonce", "nonce"},
		{"Crypto.Protocol.KDF.PBKDF2", 3, 1, "salt", "salt"},
		{"Crypto.Protocol.KDF.PBKDF2.<init>", 3, 1, "salt", "salt"},
		{"Cryptodome.Protocol.KDF.PBKDF2", 3, 1, "salt", "salt"},
		{"Crypto.Protocol.KDF.HKDF", 4, 2, "salt", "salt"},
		{"Crypto.Protocol.KDF.scrypt", 6, 1, "salt", "salt"},
	},
	"go": {
		{"crypto/cipher.NewCBCEncrypter", 2, 1, "", "initialization-vector"},
		{"crypto/cipher.NewCBCDecrypter", 2, 1, "", "initialization-vector"},
		{"crypto/cipher.NewCFBEncrypter", 2, 1, "", "initialization-vector"},
		{"crypto/cipher.NewCFBDecrypter", 2, 1, "", "initialization-vector"},
		{"crypto/cipher.NewCTR", 2, 1, "", "initialization-vector"},
		{"crypto/cipher.NewOFB", 2, 1, "", "initialization-vector"},
		{"crypto/cipher.(AEAD).Seal", 4, 1, "", "nonce"},
		{"crypto/cipher.(AEAD).Open", 4, 1, "", "nonce"},
		{"crypto/pbkdf2.Key", 5, 2, "", "salt"},
		{"crypto/hkdf.Key", 5, 2, "", "salt"},
		{"crypto/hkdf.Extract", 3, 2, "", "salt"},
		{"golang.org/x/crypto/pbkdf2.Key", 5, 1, "", "salt"},
		{"golang.org/x/crypto/scrypt.Key", 6, 1, "", "salt"},
		{"golang.org/x/crypto/argon2.IDKey", 6, 1, "", "salt"},
		{"golang.org/x/crypto/argon2.Key", 6, 1, "", "salt"},
		{"golang.org/x/crypto/hkdf.New", 4, 2, "", "salt"},
		{"golang.org/x/crypto/hkdf.Extract", 3, 2, "", "salt"},
	},
	"java": {
		{"javax.crypto.spec.IvParameterSpec.<init>", 1, 0, "", "initialization-vector"},
		{"javax.crypto.spec.IvParameterSpec.<init>", 3, 0, "", "initialization-vector"},
		{"javax.crypto.spec.GCMParameterSpec.<init>", 2, 1, "", "initialization-vector"},
		{"javax.crypto.spec.GCMParameterSpec.<init>", 4, 1, "", "initialization-vector"},
		{"javax.crypto.spec.PBEKeySpec.<init>", 3, 1, "", "salt"},
		{"javax.crypto.spec.PBEKeySpec.<init>", 4, 1, "", "salt"},
		{"javax.crypto.spec.PBEParameterSpec.<init>", 2, 0, "", "salt"},
		{"javax.crypto.spec.PBEParameterSpec.<init>", 3, 0, "", "salt"},
	},
	"rust": {
		{"openssl::symm.encrypt", 4, 2, "", "initialization-vector"},
		{"openssl::symm.decrypt", 4, 2, "", "initialization-vector"},
		{"openssl::symm.encrypt_aead", 6, 2, "", "initialization-vector"},
		{"openssl::symm.decrypt_aead", 6, 2, "", "initialization-vector"},
		{"openssl::symm::Crypter.new", 4, 3, "", "initialization-vector"},
		{"openssl::pkcs5.pbkdf2_hmac", 5, 1, "", "salt"},
		{"pbkdf2.pbkdf2_hmac", 4, 1, "", "salt"},
		{"pbkdf2.pbkdf2", 4, 1, "", "salt"},
		{"hkdf::Hkdf.new", 2, 0, "", "salt"},
		{"aes_gcm::Nonce.from_slice", 1, 0, "", "nonce"},
		{"aes_gcm::aead::Nonce.from_slice", 1, 0, "", "nonce"},
		{"aes_gcm::Aes256Gcm.encrypt", 2, 0, "", "nonce"},
		{"aes_gcm::Aes128Gcm.decrypt", 2, 0, "", "nonce"},
		{"aes_gcm::AesGcm.encrypt", 2, 0, "", "nonce"},
	},
	"node": {
		{"crypto.createCipheriv", 3, 2, "", "initialization-vector"},
		{"crypto.createCipheriv", 4, 2, "", "initialization-vector"},
		{"crypto.createDecipheriv", 3, 2, "", "initialization-vector"},
		{"node:crypto.createDecipheriv", 4, 2, "", "initialization-vector"},
		{"crypto.pbkdf2", 6, 1, "", "salt"},
		{"crypto.pbkdf2Sync", 5, 1, "", "salt"},
		{"crypto.scrypt", 4, 1, "", "salt"},
		{"crypto.scryptSync", 3, 1, "", "salt"},
		{"node:crypto.scryptSync", 4, 1, "", "salt"},
		{"crypto.hkdf", 6, 2, "", "salt"},
		{"crypto.hkdfSync", 5, 2, "", "salt"},
	},
}

func TestMaterialRoleSeeds(t *testing.T) {
	t.Parallel()

	for ecosystem, seeds := range materialSeeds {
		kb, err := contracts.LoadEmbedded(ecosystem)
		if err != nil {
			t.Fatalf("LoadEmbedded(%s): %v", ecosystem, err)
		}
		for _, s := range seeds {
			ctrs := kb.ContractsFor(s.method, s.arity)
			if len(ctrs) != 1 {
				t.Errorf("%s %s#%d: %d contracts, want 1", ecosystem, s.method, s.arity, len(ctrs))
				continue
			}
			c := ctrs[0]
			if s.index >= 0 {
				if got := c.MaterialAt(s.index, ""); got != s.material {
					t.Errorf("%s#%d argument %d is %q, want %q", s.method, s.arity, s.index, got, s.material)
				}
			}
			if s.keyword != "" {
				if got := c.MaterialAt(-1, s.keyword); got != s.material {
					t.Errorf("%s#%d keyword %s is %q, want %q", s.method, s.arity, s.keyword, got, s.material)
				}
			}
		}
	}
}
