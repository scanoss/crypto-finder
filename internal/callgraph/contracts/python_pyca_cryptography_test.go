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
		"cryptography.hazmat.primitives.ciphers.aead.AESCCM.<init>#1 cryptography.hazmat.primitives.ciphers.aead.AESCCM.<init>/factory/cryptography.hazmat.primitives.ciphers.aead.AESCCM/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.AESCCM.encrypt#3 cryptography.hazmat.primitives.ciphers.aead.AESCCM.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.AESCCM.decrypt#3 cryptography.hazmat.primitives.ciphers.aead.AESCCM.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.ciphers.aead.AESCCM.generate_key#1 cryptography.hazmat.primitives.ciphers.aead.AESCCM.generate_key/factory/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.exchange#1 cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.exchange/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.Fernet.<init>#1 cryptography.fernet.Fernet.<init>/factory/cryptography.fernet.Fernet/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.Fernet.generate_key#0 cryptography.fernet.Fernet.generate_key/factory/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.Fernet.encrypt#1 cryptography.fernet.Fernet.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.Fernet.decrypt#1 cryptography.fernet.Fernet.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.Fernet.encrypt_at_time#2 cryptography.fernet.Fernet.encrypt_at_time/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.Fernet.decrypt_at_time#3 cryptography.fernet.Fernet.decrypt_at_time/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.MultiFernet.<init>#1 cryptography.fernet.MultiFernet.<init>/factory/cryptography.fernet.MultiFernet/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.MultiFernet.encrypt#1 cryptography.fernet.MultiFernet.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.MultiFernet.decrypt#1 cryptography.fernet.MultiFernet.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.fernet.MultiFernet.rotate#1 cryptography.fernet.MultiFernet.rotate/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateSigningRequestBuilder#0 cryptography.x509.CertificateSigningRequestBuilder/factory/cryptography.x509.CertificateSigningRequestBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateSigningRequestBuilder.<init>#0 cryptography.x509.CertificateSigningRequestBuilder.<init>/factory/cryptography.x509.CertificateSigningRequestBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateSigningRequestBuilder.subject_name#1 cryptography.x509.CertificateSigningRequestBuilder.subject_name/config/cryptography.x509.CertificateSigningRequestBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateSigningRequestBuilder.add_extension#2 cryptography.x509.CertificateSigningRequestBuilder.add_extension/config/cryptography.x509.CertificateSigningRequestBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateSigningRequestBuilder.add_attribute#2 cryptography.x509.CertificateSigningRequestBuilder.add_attribute/config/cryptography.x509.CertificateSigningRequestBuilder/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.x509.CertificateSigningRequestBuilder.sign#2 cryptography.x509.CertificateSigningRequestBuilder.sign/operation/cryptography.x509.CertificateSigningRequest/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.sign#2 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify#3 cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dh.generate_parameters#2 cryptography.hazmat.primitives.asymmetric.dh.generate_parameters/factory/cryptography.hazmat.primitives.asymmetric.dh.DHParameters/high/builtins.int|builtins.int/-/params=1:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.generate_parameters#1 cryptography.hazmat.primitives.asymmetric.dsa.generate_parameters/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters/high/builtins.int/-/params=0:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dh.generate_parameters#3 cryptography.hazmat.primitives.asymmetric.dh.generate_parameters/factory/cryptography.hazmat.primitives.asymmetric.dh.DHParameters/high/builtins.int|builtins.int|typing.Any/-/params=1:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.generate_parameters#2 cryptography.hazmat.primitives.asymmetric.dsa.generate_parameters/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters/high/builtins.int|typing.Any/-/params=0:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key#2 cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey/high/builtins.int|typing.Any/-/params=0:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key#3 cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey/high/builtins.int|builtins.int|typing.Any/-/params=1:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key#1 cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey/high/builtins.int/-/params=0:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.exchange#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.exchange/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify#3 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.generate_private_key#1 cryptography.hazmat.primitives.asymmetric.ec.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey/high/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve/-/params=0:curve:metadata-contributing:keySize:argument_curve_bits/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.generate_private_key#2 cryptography.hazmat.primitives.asymmetric.ec.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey/high/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve|typing.Any/-/params=0:curve:metadata-contributing:keySize:argument_curve_bits/varargs=false/when=-/lib=pyca-cryptography",
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
		"cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key#2 cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key/factory/cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey/high/builtins.int|builtins.int/-/params=1:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
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
		"cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext.finalize#0 cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext.finalize/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext.update#1 cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext.update#1 cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext.verify#0 cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.signer#1 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.public_key#0 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.public_key/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.sign#2 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.signer#1 cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verifier#2 cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization.verifier#2 cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization.verify#3 cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.signer#1 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.exchange#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.exchange/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.private_bytes#3 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.public_key#0 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.public_key/factory/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.sign#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.signer#1 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verifier#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization.verifier#2 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization.verify#3 cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.generate#3 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey/high/builtins.int|builtins.int|typing.Any/-/params=1:key_size:metadata-contributing:keySize:argument_value/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.signer#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.decrypt#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.private_bytes#3 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.public_key#0 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.public_key/factory/cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.sign#3 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.signer#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verifier#3 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.encrypt#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.public_bytes#2 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.verifier#3 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.verify#4 cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.signer#1 cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.signer#2 cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.verifier#2 cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.verifier#3 cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		// Older names, each checked at its first and last release: interfaces.* (0.1
		// interfaces.py:82, aliases to 0.9.3), *WithSerialization (0.8 rsa.py:45,92),
		// signer/verifier (0.8 to 36.0.2 asymmetric/__init__.py:13), generate (0.2 rsa.py:134)
		// and the PEM loaders (0.5 serialization.py:17,23).
		"cryptography.hazmat.primitives.interfaces.AEADCipherContext.authenticate_additional_data#1 cryptography.hazmat.primitives.interfaces.AEADCipherContext.authenticate_additional_data/config/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext.finalize#0 cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext.finalize/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext.update#1 cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.AsymmetricVerificationContext.update#1 cryptography.hazmat.primitives.interfaces.AsymmetricVerificationContext.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.AsymmetricVerificationContext.verify#0 cryptography.hazmat.primitives.interfaces.AsymmetricVerificationContext.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.CipherContext.finalize#0 cryptography.hazmat.primitives.interfaces.CipherContext.finalize/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.CipherContext.update#1 cryptography.hazmat.primitives.interfaces.CipherContext.update/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.DSAPrivateKey.public_key#0 cryptography.hazmat.primitives.interfaces.DSAPrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.DSAPrivateKey.signer#1 cryptography.hazmat.primitives.interfaces.DSAPrivateKey.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.DSAPublicKey.verifier#2 cryptography.hazmat.primitives.interfaces.DSAPublicKey.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.EllipticCurvePrivateKey.public_key#0 cryptography.hazmat.primitives.interfaces.EllipticCurvePrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.EllipticCurvePrivateKey.signer#1 cryptography.hazmat.primitives.interfaces.EllipticCurvePrivateKey.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.EllipticCurvePublicKey.verifier#2 cryptography.hazmat.primitives.interfaces.EllipticCurvePublicKey.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.PaddingContext.finalize#0 cryptography.hazmat.primitives.interfaces.PaddingContext.finalize/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.PaddingContext.update#1 cryptography.hazmat.primitives.interfaces.PaddingContext.update/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.RSAPrivateKey.decrypt#2 cryptography.hazmat.primitives.interfaces.RSAPrivateKey.decrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.RSAPrivateKey.public_key#0 cryptography.hazmat.primitives.interfaces.RSAPrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.RSAPrivateKey.signer#2 cryptography.hazmat.primitives.interfaces.RSAPrivateKey.signer/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.RSAPublicKey.encrypt#2 cryptography.hazmat.primitives.interfaces.RSAPublicKey.encrypt/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.RSAPublicKey.verifier#3 cryptography.hazmat.primitives.interfaces.RSAPublicKey.verifier/factory/cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.X509Certificate.fingerprint#1 cryptography.hazmat.primitives.interfaces.X509Certificate.fingerprint/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.interfaces.X509Certificate.public_key#0 cryptography.hazmat.primitives.interfaces.X509Certificate.public_key/factory/cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.serialization.load_pem_pkcs8_private_key#3 cryptography.hazmat.primitives.serialization.load_pem_pkcs8_private_key/factory/cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.serialization.load_pem_traditional_openssl_private_key#3 cryptography.hazmat.primitives.serialization.load_pem_traditional_openssl_private_key/factory/cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		// ML-KEM (FIPS 203) and ML-DSA (FIPS 204), asymmetric/mlkem.py and
		// mldsa.py plus the MLDSAMuHasher stub, cryptography main (51.0.0-dev).
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.from_seed_bytes#1 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.from_seed_bytes/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.decapsulate#1 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.decapsulate/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.private_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.private_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.from_public_bytes#1 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.from_public_bytes/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.encapsulate#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.encapsulate/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.public_bytes#2 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.public_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey.public_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.from_seed_bytes#1 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.from_seed_bytes/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.decapsulate#1 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.decapsulate/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.private_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.private_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.from_public_bytes#1 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.from_public_bytes/factory/cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.encapsulate#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.encapsulate/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.public_bytes#2 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.public_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey.public_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.from_seed_bytes#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.from_seed_bytes/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.private_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.private_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.sign#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.sign#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.sign_mu#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.sign_mu/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.from_public_bytes#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.from_public_bytes/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.public_bytes#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.public_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.public_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.verify#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.verify#3 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.verify_mu#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PublicKey.verify_mu/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.from_seed_bytes#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.from_seed_bytes/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.private_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.private_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.sign#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.sign#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.sign_mu#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.sign_mu/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.from_public_bytes#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.from_public_bytes/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.public_bytes#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.public_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.public_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.verify#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.verify#3 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.verify_mu#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PublicKey.verify_mu/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.generate#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.generate/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.from_seed_bytes#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.from_seed_bytes/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.public_key#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.public_key/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.private_bytes#3 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.private_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.private_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.private_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.sign#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.sign#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.sign/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.sign_mu#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.sign_mu/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.from_public_bytes#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.from_public_bytes/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.public_bytes#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.public_bytes/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.public_bytes_raw#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.public_bytes_raw/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.verify#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.verify#3 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.verify/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.verify_mu#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PublicKey.verify_mu/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.<init>#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.<init>/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.<init>#2 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.<init>/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.update#1 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.update/operation/builtins.NoneType/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.copy#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.copy/factory/cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
		"cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.finalize#0 cryptography.hazmat.primitives.asymmetric.mldsa.MLDSAMuHasher.finalize/output/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=pyca-cryptography",
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

// TestPycaCryptographyPQCNegatives pins that lookalike keys resolve to nothing:
// pyca offers no ML-KEM-512, decapsulate lives on the private key only, and
// sign takes at most data and context. Names that exist under no arity must
// also miss the Python name-tolerant lookup; a wrong arity on a real name is
// only an exact-match miss, since ContractsForTolerant falls back by name.
func TestPycaCryptographyPQCNegatives(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	const pfx = "cryptography.hazmat.primitives.asymmetric."
	unknownNames := []struct {
		method string
		arity  int
	}{
		{pfx + "mlkem.MLKEM512PrivateKey.generate", 0},
		{pfx + "mlkem.MLKEM512PublicKey.encapsulate", 0},
		{pfx + "mlkem.MLKEM768PublicKey.decapsulate", 1},
		{pfx + "mlkem.MLKEM768PrivateKey.encapsulate", 0},
		{pfx + "mlkem.MLKEM1024PrivateKey.sign", 1},
		{pfx + "mlkem.MLKEM768PrivateKey.from_public_bytes", 1},
		{pfx + "mlkem.MLKEM768PublicKey.from_seed_bytes", 1},
		{pfx + "mldsa.MLDSA128PrivateKey.generate", 0},
		{pfx + "mldsa.MLDSA65PublicKey.sign", 1},
		{pfx + "mldsa.MLDSA65PrivateKey.verify", 2},
		{pfx + "mldsa.MLDSA65PrivateKey.decapsulate", 1},
	}
	for _, tt := range unknownNames {
		if got := kb.ContractsFor(tt.method, tt.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want none", tt.method, tt.arity, len(got))
		}
		if got := kb.ContractsForTolerant(tt.method, tt.arity); len(got) != 0 {
			t.Errorf("ContractsForTolerant(%q, %d) = %d contracts, want none", tt.method, tt.arity, len(got))
		}
	}
	wrongArity := []struct {
		method string
		arity  int
	}{
		{pfx + "mlkem.MLKEM768PrivateKey.generate", 1},
		{pfx + "mlkem.MLKEM768PublicKey.encapsulate", 1},
		{pfx + "mldsa.MLDSA65PrivateKey.sign", 3},
		{pfx + "mldsa.MLDSA65PrivateKey.sign", 0},
		{pfx + "mldsa.MLDSA65PrivateKey.sign_mu", 2},
		{pfx + "mldsa.MLDSA65PublicKey.verify", 4},
		{pfx + "mldsa.MLDSA65PublicKey.verify", 1},
		{pfx + "mldsa.MLDSAMuHasher.<init>", 0},
		{pfx + "mldsa.MLDSAMuHasher.<init>", 3},
		{pfx + "mldsa.MLDSAMuHasher.update", 0},
	}
	for _, tt := range wrongArity {
		if got := kb.ContractsFor(tt.method, tt.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want none", tt.method, tt.arity, len(got))
		}
	}

	// The positive counterparts of the negatives above do resolve.
	positives := []struct {
		method string
		arity  int
		ret    string
	}{
		{pfx + "mlkem.MLKEM768PrivateKey.generate", 0, pfx + "mlkem.MLKEM768PrivateKey"},
		{pfx + "mlkem.MLKEM768PrivateKey.decapsulate", 1, "builtins.bytes"},
		{pfx + "mlkem.MLKEM768PublicKey.encapsulate", 0, "builtins.tuple"},
		{pfx + "mldsa.MLDSA65PrivateKey.sign", 2, "builtins.bytes"},
		{pfx + "mldsa.MLDSA65PublicKey.verify", 3, "builtins.NoneType"},
		{pfx + "mldsa.MLDSAMuHasher.finalize", 0, "builtins.bytes"},
	}
	for _, tt := range positives {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
			continue
		}
		if got[0].Return.Type != tt.ret {
			t.Errorf("ContractsFor(%q, %d).Return.Type = %q, want %q", tt.method, tt.arity, got[0].Return.Type, tt.ret)
		}
	}
}
