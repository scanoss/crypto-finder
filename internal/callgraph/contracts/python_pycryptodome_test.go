// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// wantPycryptodomeContracts was reviewed line by line against the
// pycryptodome 3.23.0 sources (lib/Crypto); the DES, DES3, Salsa20 and
// PKCS1_OAEP entries also against every release from 3.0. Update returns differ by class:
// SHA-2 and ChaCha20-Poly1305 return None, SHA-3, HMAC and the AES AEAD
// modes return the object. Every verify raises on failure and returns None.
func wantPycryptodomeContracts() []string {
	return []string{
		"Crypto.Cipher.AES.AESCipher.decrypt#1 Crypto.Cipher.AES.AESCipher.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.decrypt_and_verify#2 Crypto.Cipher.AES.AESCipher.decrypt_and_verify/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.digest#0 Crypto.Cipher.AES.AESCipher.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.encrypt#1 Crypto.Cipher.AES.AESCipher.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.encrypt_and_digest#1 Crypto.Cipher.AES.AESCipher.encrypt_and_digest/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.hexdigest#0 Crypto.Cipher.AES.AESCipher.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.hexverify#1 Crypto.Cipher.AES.AESCipher.hexverify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.update#1 Crypto.Cipher.AES.AESCipher.update/config/Crypto.Cipher.AES.AESCipher/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.AESCipher.verify#1 Crypto.Cipher.AES.AESCipher.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.AES.new#2 Crypto.Cipher.AES.new/factory/Crypto.Cipher.AES.AESCipher/high/-/-/params=0:key:metadata-contributing:keySize:argument_byte_length,1:mode:operation-determining:-:-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20.ChaCha20Cipher.decrypt#1 Crypto.Cipher.ChaCha20.ChaCha20Cipher.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20.ChaCha20Cipher.encrypt#1 Crypto.Cipher.ChaCha20.ChaCha20Cipher.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20.new#1 Crypto.Cipher.ChaCha20.new/factory/Crypto.Cipher.ChaCha20.ChaCha20Cipher/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.decrypt#1 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.decrypt_and_verify#2 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.decrypt_and_verify/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.digest#0 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.encrypt#1 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.encrypt_and_digest#1 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.encrypt_and_digest/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.hexdigest#0 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.hexverify#1 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.hexverify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.update#1 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.update/config/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.verify#1 Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.ChaCha20_Poly1305.new#1 Crypto.Cipher.ChaCha20_Poly1305.new/factory/Crypto.Cipher.ChaCha20_Poly1305.ChaCha20Poly1305Cipher/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.DES.DESCipher.decrypt#1 Crypto.Cipher.DES.DESCipher.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.DES.DESCipher.encrypt#1 Crypto.Cipher.DES.DESCipher.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.DES.new#2 Crypto.Cipher.DES.new/factory/Crypto.Cipher.DES.DESCipher/high/-/-/params=0:key:metadata-contributing:keySize:argument_byte_length,1:mode:operation-determining:-:-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.DES3.DES3Cipher.decrypt#1 Crypto.Cipher.DES3.DES3Cipher.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.DES3.DES3Cipher.encrypt#1 Crypto.Cipher.DES3.DES3Cipher.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.DES3.new#2 Crypto.Cipher.DES3.new/factory/Crypto.Cipher.DES3.DES3Cipher/high/-/-/params=0:key:metadata-contributing:keySize:argument_byte_length,1:mode:operation-determining:-:-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.decrypt#1 Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.encrypt#1 Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.PKCS1_OAEP.new#1 Crypto.Cipher.PKCS1_OAEP.new/factory/Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.Salsa20.Salsa20Cipher.decrypt#1 Crypto.Cipher.Salsa20.Salsa20Cipher.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.Salsa20.Salsa20Cipher.encrypt#1 Crypto.Cipher.Salsa20.Salsa20Cipher.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Cipher.Salsa20.new#2 Crypto.Cipher.Salsa20.new/factory/Crypto.Cipher.Salsa20.Salsa20Cipher/high/-/-/params=0:key:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.HMAC.HMAC.digest#0 Crypto.Hash.HMAC.HMAC.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.HMAC.HMAC.hexdigest#0 Crypto.Hash.HMAC.HMAC.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.HMAC.HMAC.hexverify#1 Crypto.Hash.HMAC.HMAC.hexverify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.HMAC.HMAC.update#1 Crypto.Hash.HMAC.HMAC.update/operation/Crypto.Hash.HMAC.HMAC/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.HMAC.HMAC.verify#1 Crypto.Hash.HMAC.HMAC.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.HMAC.new#2 Crypto.Hash.HMAC.new/factory/Crypto.Hash.HMAC.HMAC/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA224.SHA224Hash.digest#0 Crypto.Hash.SHA224.SHA224Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA224.SHA224Hash.hexdigest#0 Crypto.Hash.SHA224.SHA224Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA224.SHA224Hash.update#1 Crypto.Hash.SHA224.SHA224Hash.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA224.new#0 Crypto.Hash.SHA224.new/factory/Crypto.Hash.SHA224.SHA224Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA256.SHA256Hash.digest#0 Crypto.Hash.SHA256.SHA256Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA256.SHA256Hash.hexdigest#0 Crypto.Hash.SHA256.SHA256Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA256.SHA256Hash.update#1 Crypto.Hash.SHA256.SHA256Hash.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA256.new#0 Crypto.Hash.SHA256.new/factory/Crypto.Hash.SHA256.SHA256Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA384.SHA384Hash.digest#0 Crypto.Hash.SHA384.SHA384Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA384.SHA384Hash.hexdigest#0 Crypto.Hash.SHA384.SHA384Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA384.SHA384Hash.update#1 Crypto.Hash.SHA384.SHA384Hash.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA384.new#0 Crypto.Hash.SHA384.new/factory/Crypto.Hash.SHA384.SHA384Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_224.SHA3_224Hash.digest#0 Crypto.Hash.SHA3_224.SHA3_224Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_224.SHA3_224Hash.hexdigest#0 Crypto.Hash.SHA3_224.SHA3_224Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_224.SHA3_224Hash.update#1 Crypto.Hash.SHA3_224.SHA3_224Hash.update/operation/Crypto.Hash.SHA3_224.SHA3_224Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_224.new#0 Crypto.Hash.SHA3_224.new/factory/Crypto.Hash.SHA3_224.SHA3_224Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_256.SHA3_256Hash.digest#0 Crypto.Hash.SHA3_256.SHA3_256Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_256.SHA3_256Hash.hexdigest#0 Crypto.Hash.SHA3_256.SHA3_256Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_256.SHA3_256Hash.update#1 Crypto.Hash.SHA3_256.SHA3_256Hash.update/operation/Crypto.Hash.SHA3_256.SHA3_256Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_256.new#0 Crypto.Hash.SHA3_256.new/factory/Crypto.Hash.SHA3_256.SHA3_256Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_384.SHA3_384Hash.digest#0 Crypto.Hash.SHA3_384.SHA3_384Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_384.SHA3_384Hash.hexdigest#0 Crypto.Hash.SHA3_384.SHA3_384Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_384.SHA3_384Hash.update#1 Crypto.Hash.SHA3_384.SHA3_384Hash.update/operation/Crypto.Hash.SHA3_384.SHA3_384Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_384.new#0 Crypto.Hash.SHA3_384.new/factory/Crypto.Hash.SHA3_384.SHA3_384Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_512.SHA3_512Hash.digest#0 Crypto.Hash.SHA3_512.SHA3_512Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_512.SHA3_512Hash.hexdigest#0 Crypto.Hash.SHA3_512.SHA3_512Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_512.SHA3_512Hash.update#1 Crypto.Hash.SHA3_512.SHA3_512Hash.update/operation/Crypto.Hash.SHA3_512.SHA3_512Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA3_512.new#0 Crypto.Hash.SHA3_512.new/factory/Crypto.Hash.SHA3_512.SHA3_512Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA512.SHA512Hash.digest#0 Crypto.Hash.SHA512.SHA512Hash.digest/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA512.SHA512Hash.hexdigest#0 Crypto.Hash.SHA512.SHA512Hash.hexdigest/output/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA512.SHA512Hash.update#1 Crypto.Hash.SHA512.SHA512Hash.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Hash.SHA512.new#0 Crypto.Hash.SHA512.new/factory/Crypto.Hash.SHA512.SHA512Hash/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Protocol.KDF.HKDF#4 Crypto.Protocol.KDF.HKDF/operation/builtins.bytes/high/builtins.bytes|builtins.int|builtins.bytes|builtins.object/-/params=1:key_len:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Protocol.KDF.HKDF.<init>#4 Crypto.Protocol.KDF.HKDF.<init>/operation/builtins.bytes/high/builtins.bytes|builtins.int|builtins.bytes|builtins.object/-/params=1:key_len:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Protocol.KDF.PBKDF1#3 Crypto.Protocol.KDF.PBKDF1/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int/-/params=2:dkLen:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Protocol.KDF.PBKDF1.<init>#3 Crypto.Protocol.KDF.PBKDF1.<init>/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int/-/params=2:dkLen:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Protocol.KDF.PBKDF2#3 Crypto.Protocol.KDF.PBKDF2/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int/-/params=2:dkLen:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Protocol.KDF.PBKDF2.<init>#3 Crypto.Protocol.KDF.PBKDF2.<init>/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int/-/params=2:dkLen:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Protocol.KDF.scrypt#6 Crypto.Protocol.KDF.scrypt/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int|builtins.int|builtins.int|builtins.int/-/params=2:key_len:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.ECC.EccKey.export_key#0 Crypto.PublicKey.ECC.EccKey.export_key/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.ECC.EccKey.public_key#0 Crypto.PublicKey.ECC.EccKey.public_key/factory/Crypto.PublicKey.ECC.EccKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.ECC.generate#1 Crypto.PublicKey.ECC.generate/factory/Crypto.PublicKey.ECC.EccKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.ECC.import_key#1 Crypto.PublicKey.ECC.import_key/factory/Crypto.PublicKey.ECC.EccKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.RsaKey.exportKey#0 Crypto.PublicKey.RSA.RsaKey.exportKey/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.RsaKey.export_key#0 Crypto.PublicKey.RSA.RsaKey.export_key/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.RsaKey.public_key#0 Crypto.PublicKey.RSA.RsaKey.public_key/factory/Crypto.PublicKey.RSA.RsaKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.RsaKey.publickey#0 Crypto.PublicKey.RSA.RsaKey.publickey/factory/Crypto.PublicKey.RSA.RsaKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.construct#1 Crypto.PublicKey.RSA.construct/factory/Crypto.PublicKey.RSA.RsaKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.generate#1 Crypto.PublicKey.RSA.generate/factory/Crypto.PublicKey.RSA.RsaKey/high/-/-/params=0:bits:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.importKey#1 Crypto.PublicKey.RSA.importKey/factory/Crypto.PublicKey.RSA.RsaKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.PublicKey.RSA.import_key#1 Crypto.PublicKey.RSA.import_key/factory/Crypto.PublicKey.RSA.RsaKey/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.DSS.DssSigScheme.sign#1 Crypto.Signature.DSS.DssSigScheme.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.DSS.DssSigScheme.verify#2 Crypto.Signature.DSS.DssSigScheme.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.DSS.new#2 Crypto.Signature.DSS.new/factory/Crypto.Signature.DSS.DssSigScheme/high/-/-/params=1:mode:operation-determining:-:-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.pkcs1_15.PKCS115_SigScheme.sign#1 Crypto.Signature.pkcs1_15.PKCS115_SigScheme.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.pkcs1_15.PKCS115_SigScheme.verify#2 Crypto.Signature.pkcs1_15.PKCS115_SigScheme.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.pkcs1_15.new#1 Crypto.Signature.pkcs1_15.new/factory/Crypto.Signature.pkcs1_15.PKCS115_SigScheme/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.pss.PSS_SigScheme.sign#1 Crypto.Signature.pss.PSS_SigScheme.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.pss.PSS_SigScheme.verify#2 Crypto.Signature.pss.PSS_SigScheme.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
		"Crypto.Signature.pss.new#1 Crypto.Signature.pss.new/factory/Crypto.Signature.pss.PSS_SigScheme/high/-/-/params=-/varargs=false/when=-/lib=pycryptodome",
	}
}

func loadedLibraryContracts(t *testing.T, library string) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == library {
				got = append(got, renderPyjwtContract(key, list[i]))
			}
		}
	}
	sort.Strings(got)
	return got
}

func diffContractSets(t *testing.T, got, want []string) {
	t.Helper()
	gotSet := map[string]bool{}
	for _, line := range got {
		gotSet[line] = true
	}
	wantSet := map[string]bool{}
	for _, line := range want {
		wantSet[line] = true
		if !gotSet[line] {
			t.Errorf("expected but NOT loaded from the YAML:\n\t%q,", line)
		}
	}
	for _, line := range got {
		if !wantSet[line] {
			t.Errorf("loaded but not expected:\n\t%q,", line)
		}
	}
}

func TestPycryptodomeContract_ExactSet(t *testing.T) {
	t.Parallel()
	diffContractSets(t, loadedLibraryContracts(t, "pycryptodome"), wantPycryptodomeContracts())
}

// pycryptodomex installs the same code under `Cryptodome`, so its contract set
// is pycryptodome's with the namespace and library renamed, entry for entry.
func TestPycryptodomexContract_MirrorsPycryptodome(t *testing.T) {
	t.Parallel()
	want := make([]string, 0, len(wantPycryptodomeContracts()))
	for _, line := range wantPycryptodomeContracts() {
		line = strings.ReplaceAll(line, "Crypto.", "Cryptodome.")
		line = strings.Replace(line, "/lib=pycryptodome", "/lib=pycryptodomex", 1)
		want = append(want, line)
	}
	diffContractSets(t, loadedLibraryContracts(t, "pycryptodomex"), want)
}
