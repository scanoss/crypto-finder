// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// wantPycaCryptographyContracts was reviewed entry by entry against the
// cryptography 50.0.1 sources and stubs. A loaded key's algorithm is unknown
// until run time, so serialization loaders return the asymmetric/types.py
// unions and only the methods every member shares are contracted on them.
func wantPycaCryptographyContracts() []string {
	return []string{
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.sign#2 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify#3 cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key#1 cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey/high/-/-/params=0:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.exchange#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.exchange/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify#3 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.generate_private_key#1 cryptography.hazmat.primitives.asymmetric.ec.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.sign#1 cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.verify#2 cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.sign#1 cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey.verify#2 cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.decrypt#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.sign#3 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.encrypt#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.public_bytes#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify#4 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key#2 cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey/high/-/-/params=1:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.private_bytes#3 cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.public_key#0 cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.public_key/factory/cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.sign#1 cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.public_bytes#2 cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.verify#2 cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.Cipher.<init>#2 cryptography.hazmat.primitives.ciphers.Cipher.<init>/factory/cryptography.hazmat.primitives.ciphers.Cipher/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.Cipher.decryptor#0 cryptography.hazmat.primitives.ciphers.Cipher.decryptor/factory/cryptography.hazmat.primitives.ciphers.CipherContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.Cipher.encryptor#0 cryptography.hazmat.primitives.ciphers.Cipher.encryptor/factory/cryptography.hazmat.primitives.ciphers.CipherContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.CipherContext.authenticate_additional_data#1 cryptography.hazmat.primitives.ciphers.CipherContext.authenticate_additional_data/config/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.CipherContext.finalize#0 cryptography.hazmat.primitives.ciphers.CipherContext.finalize/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.CipherContext.finalize_with_tag#1 cryptography.hazmat.primitives.ciphers.CipherContext.finalize_with_tag/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.CipherContext.update#1 cryptography.hazmat.primitives.ciphers.CipherContext.update/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.AESGCM.<init>#1 cryptography.hazmat.primitives.ciphers.aead.AESGCM.<init>/factory/cryptography.hazmat.primitives.ciphers.aead.AESGCM/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.AESGCM.decrypt#3 cryptography.hazmat.primitives.ciphers.aead.AESGCM.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.AESGCM.encrypt#3 cryptography.hazmat.primitives.ciphers.aead.AESGCM.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.AESGCM.generate_key#1 cryptography.hazmat.primitives.ciphers.aead.AESGCM.generate_key/factory/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.<init>#1 cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.<init>/factory/cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.decrypt#3 cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.encrypt#3 cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.generate_key#0 cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.generate_key/factory/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hashes.Hash#1 cryptography.hazmat.primitives.hashes.Hash/factory/cryptography.hazmat.primitives.hashes.Hash/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hashes.Hash.<init>#1 cryptography.hazmat.primitives.hashes.Hash.<init>/factory/cryptography.hazmat.primitives.hashes.Hash/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hashes.Hash.copy#0 cryptography.hazmat.primitives.hashes.Hash.copy/factory/cryptography.hazmat.primitives.hashes.Hash/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hashes.Hash.finalize#0 cryptography.hazmat.primitives.hashes.Hash.finalize/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hashes.Hash.update#1 cryptography.hazmat.primitives.hashes.Hash.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hmac.HMAC#2 cryptography.hazmat.primitives.hmac.HMAC/factory/cryptography.hazmat.primitives.hmac.HMAC/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hmac.HMAC.<init>#2 cryptography.hazmat.primitives.hmac.HMAC.<init>/factory/cryptography.hazmat.primitives.hmac.HMAC/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hmac.HMAC.copy#0 cryptography.hazmat.primitives.hmac.HMAC.copy/factory/cryptography.hazmat.primitives.hmac.HMAC/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hmac.HMAC.finalize#0 cryptography.hazmat.primitives.hmac.HMAC.finalize/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hmac.HMAC.update#1 cryptography.hazmat.primitives.hmac.HMAC.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.hmac.HMAC.verify#1 cryptography.hazmat.primitives.hmac.HMAC.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.<init>#3 cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.<init>/factory/cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash/high/cryptography.hazmat.primitives.hashes.HashAlgorithm|builtins.int|builtins.bytes/-/params=1:length:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.derive#1 cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.derive/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.verify#2 cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.hkdf.HKDF.<init>#4 cryptography.hazmat.primitives.kdf.hkdf.HKDF.<init>/factory/cryptography.hazmat.primitives.kdf.hkdf.HKDF/high/cryptography.hazmat.primitives.hashes.HashAlgorithm|builtins.int|builtins.bytes|builtins.bytes/-/params=1:length:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.hkdf.HKDF.derive#1 cryptography.hazmat.primitives.kdf.hkdf.HKDF.derive/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.hkdf.HKDF.verify#2 cryptography.hazmat.primitives.kdf.hkdf.HKDF.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.<init>#3 cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.<init>/factory/cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand/high/cryptography.hazmat.primitives.hashes.HashAlgorithm|builtins.int|builtins.bytes/-/params=1:length:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.derive#1 cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.derive/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.verify#2 cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.<init>#4 cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.<init>/factory/cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC/high/cryptography.hazmat.primitives.hashes.HashAlgorithm|builtins.int|builtins.bytes|builtins.int/-/params=1:length:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.derive#1 cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.derive/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.verify#2 cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.scrypt.Scrypt.<init>#5 cryptography.hazmat.primitives.kdf.scrypt.Scrypt.<init>/factory/cryptography.hazmat.primitives.kdf.scrypt.Scrypt/high/builtins.bytes|builtins.int|builtins.int|builtins.int|builtins.int/-/params=1:length:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.scrypt.Scrypt.derive#1 cryptography.hazmat.primitives.kdf.scrypt.Scrypt.derive/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.scrypt.Scrypt.verify#2 cryptography.hazmat.primitives.kdf.scrypt.Scrypt.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.<init>#3 cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.<init>/factory/cryptography.hazmat.primitives.kdf.x963kdf.X963KDF/high/cryptography.hazmat.primitives.hashes.HashAlgorithm|builtins.int|builtins.bytes/-/params=1:length:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.derive#1 cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.derive/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.verify#2 cryptography.hazmat.primitives.kdf.x963kdf.X963KDF.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.padding.PKCS7#1 cryptography.hazmat.primitives.padding.PKCS7/factory/cryptography.hazmat.primitives.padding.PKCS7/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.padding.PKCS7.<init>#1 cryptography.hazmat.primitives.padding.PKCS7.<init>/factory/cryptography.hazmat.primitives.padding.PKCS7/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.padding.PKCS7.padder#0 cryptography.hazmat.primitives.padding.PKCS7.padder/factory/cryptography.hazmat.primitives.padding.PaddingContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.padding.PKCS7.unpadder#0 cryptography.hazmat.primitives.padding.PKCS7.unpadder/factory/cryptography.hazmat.primitives.padding.PaddingContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.padding.PaddingContext.finalize#0 cryptography.hazmat.primitives.padding.PaddingContext.finalize/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.padding.PaddingContext.update#1 cryptography.hazmat.primitives.padding.PaddingContext.update/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.serialization.load_der_private_key#2 cryptography.hazmat.primitives.serialization.load_der_private_key/factory/cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.serialization.load_der_public_key#1 cryptography.hazmat.primitives.serialization.load_der_public_key/factory/cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.serialization.load_pem_private_key#2 cryptography.hazmat.primitives.serialization.load_pem_private_key/factory/cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.serialization.load_pem_public_key#1 cryptography.hazmat.primitives.serialization.load_pem_public_key/factory/cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.Certificate.fingerprint#1 cryptography.x509.Certificate.fingerprint/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.Certificate.public_bytes#1 cryptography.x509.Certificate.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.Certificate.public_key#0 cryptography.x509.Certificate.public_key/factory/cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder#0 cryptography.x509.CertificateBuilder/factory/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.<init>#0 cryptography.x509.CertificateBuilder.<init>/factory/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.add_extension#2 cryptography.x509.CertificateBuilder.add_extension/config/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.issuer_name#1 cryptography.x509.CertificateBuilder.issuer_name/config/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.not_valid_after#1 cryptography.x509.CertificateBuilder.not_valid_after/config/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.not_valid_before#1 cryptography.x509.CertificateBuilder.not_valid_before/config/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.public_key#1 cryptography.x509.CertificateBuilder.public_key/config/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.serial_number#1 cryptography.x509.CertificateBuilder.serial_number/config/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.sign#2 cryptography.x509.CertificateBuilder.sign/operation/cryptography.x509.Certificate/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateBuilder.subject_name#1 cryptography.x509.CertificateBuilder.subject_name/config/cryptography.x509.CertificateBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.load_der_x509_certificate#1 cryptography.x509.load_der_x509_certificate/factory/cryptography.x509.Certificate/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.load_pem_x509_certificate#1 cryptography.x509.load_pem_x509_certificate/factory/cryptography.x509.Certificate/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
	}
}

func TestPycaCryptographyContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == "pyca-cryptography" {
				got = append(got, renderPyjwtContract(key, list[i]))
			}
		}
	}
	want := wantPycaCryptographyContracts()
	sort.Strings(got)
	sort.Strings(want)

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
