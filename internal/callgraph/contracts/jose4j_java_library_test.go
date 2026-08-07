package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestLoadEmbeddedJava_Jose4jLifecycle verifies the jose4j JOSE lifecycle
// contracts (scanoss/crypto-finder#188): the shared KeyManagementAlgorithm/
// ContentEncryptionAlgorithm operation interfaces, the JWE key-management
// algorithm factories (RsaKeyManagementAlgorithm's RSA-OAEP/RSA1_5 variants,
// AES key wrap, AES-GCM key wrap, PBES2, direct), the hand-rolled
// AesCbcHmacSha2ContentEncryptionAlgorithm encrypt-then-MAC composite, the
// hand-rolled ConcatKDF/PBKDF2 KDFs, and the JWK generators — including the
// return types, lifecycle roles, and the scanoss/crypto_rules#175 rule-anchor
// api FQNs they must resolve through. The P1 verification-side surface
// (JwtConsumerBuilder/JsonWebSignature/JsonWebEncryption/JWKS resolvers) is
// deliberately absent, matching crypto_rules#174's P1 deferral.
func TestLoadEmbeddedJava_Jose4jLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const (
		keyMgmtIface  = "org.jose4j.jwe.KeyManagementAlgorithm"
		contentEncIfc = "org.jose4j.jwe.ContentEncryptionAlgorithm"
		rsaKM         = "org.jose4j.jwe.RsaKeyManagementAlgorithm"
		aesKW         = "org.jose4j.jwe.AesKeyWrapManagementAlgorithm"
		aesGcmKW      = "org.jose4j.jwe.AesGcmKeyEncryptionAlgorithm"
		pbes2         = "org.jose4j.jwe.Pbes2HmacShaWithAesKeyWrapAlgorithm"
		direct        = "org.jose4j.jwe.DirectKeyManagementAlgorithm"
		aesCbcHmac    = "org.jose4j.jwe.AesCbcHmacSha2ContentEncryptionAlgorithm"
		concatKDF     = "org.jose4j.jwe.kdf.ConcatKeyDerivationFunction"
		pbkdf2        = "org.jose4j.jwe.kdf.PasswordBasedKeyDerivationFunction2"
	)

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		// Shared operation interfaces.
		{keyMgmtIface + ".manageForEncrypt", 5, "org.jose4j.jwe.ContentEncryptionKeys", "operation"},
		{keyMgmtIface + ".prepareForDecrypt", 3, "org.jose4j.jwa.CryptoPrimitive", "operation"},
		{keyMgmtIface + ".manageForDecrypt", 5, "java.security.Key", "operation"},
		{contentEncIfc + ".getContentEncryptionKeyDescriptor", 0, "org.jose4j.jwe.ContentEncryptionKeyDescriptor", "output"},
		{contentEncIfc + ".encrypt", 6, "org.jose4j.jwe.ContentEncryptionParts", "operation"},
		{contentEncIfc + ".decrypt", 5, "byte[]", "operation"},

		// RsaKeyManagementAlgorithm family.
		{rsaKM + ".<init>", 2, rsaKM, "factory"},
		{rsaKM + ".RsaOaep.<init>", 0, rsaKM + ".RsaOaep", "factory"},
		{rsaKM + ".RsaOaep256.<init>", 0, rsaKM + ".RsaOaep256", "factory"},
		{rsaKM + ".Rsa1_5.<init>", 0, rsaKM + ".Rsa1_5", "factory"},

		// AES key wrap family.
		{aesKW + ".<init>", 2, aesKW, "factory"},
		{aesKW + ".Aes128.<init>", 0, aesKW + ".Aes128", "factory"},
		{aesKW + ".Aes192.<init>", 0, aesKW + ".Aes192", "factory"},
		{aesKW + ".Aes256.<init>", 0, aesKW + ".Aes256", "factory"},

		// AES-GCM key wrap family.
		{aesGcmKW + ".<init>", 2, aesGcmKW, "factory"},
		{aesGcmKW + ".Aes128Gcm.<init>", 0, aesGcmKW + ".Aes128Gcm", "factory"},
		{aesGcmKW + ".Aes192Gcm.<init>", 0, aesGcmKW + ".Aes192Gcm", "factory"},
		{aesGcmKW + ".Aes256Gcm.<init>", 0, aesGcmKW + ".Aes256Gcm", "factory"},

		// PBES2 family.
		{pbes2 + ".<init>", 3, pbes2, "factory"},
		{pbes2 + ".HmacSha256Aes128.<init>", 0, pbes2 + ".HmacSha256Aes128", "factory"},
		{pbes2 + ".HmacSha384Aes192.<init>", 0, pbes2 + ".HmacSha384Aes192", "factory"},
		{pbes2 + ".HmacSha512Aes256.<init>", 0, pbes2 + ".HmacSha512Aes256", "factory"},
		{pbes2 + ".setDefaultIterationCount", 1, "void", "config"},
		{pbes2 + ".setDefaultSaltByteLength", 1, "void", "config"},
		{pbes2 + ".setMaxIterationCount", 1, "void", "config"},

		// Direct key management.
		{direct + ".<init>", 0, direct, "factory"},

		// Hand-rolled AES-CBC-HMAC content encryption.
		{aesCbcHmac + ".<init>", 4, aesCbcHmac, "factory"},
		{aesCbcHmac + ".Aes128CbcHmacSha256.<init>", 0, aesCbcHmac + ".Aes128CbcHmacSha256", "factory"},
		{aesCbcHmac + ".Aes192CbcHmacSha384.<init>", 0, aesCbcHmac + ".Aes192CbcHmacSha384", "factory"},
		{aesCbcHmac + ".Aes256CbcHmacSha512.<init>", 0, aesCbcHmac + ".Aes256CbcHmacSha512", "factory"},

		// Hand-rolled ConcatKDF.
		{concatKDF + ".<init>", 1, concatKDF, "factory"},
		{concatKDF + ".<init>", 2, concatKDF, "factory"},
		{concatKDF + ".kdf", 3, "byte[]", "operation"},
		{concatKDF + ".kdf", 7, "byte[]", "operation"},

		// Hand-rolled PBKDF2.
		{pbkdf2 + ".<init>", 1, pbkdf2, "factory"},
		{pbkdf2 + ".derive", 4, "byte[]", "operation"},
		{pbkdf2 + ".derive", 5, "byte[]", "operation"},

		// JWK generators.
		{"org.jose4j.jwk.RsaJwkGenerator.generateJwk", 1, "org.jose4j.jwk.RsaJsonWebKey", "factory"},
		{"org.jose4j.jwk.RsaJwkGenerator.generateJwk", 3, "org.jose4j.jwk.RsaJsonWebKey", "factory"},
		{"org.jose4j.jwk.EcJwkGenerator.generateJwk", 1, "org.jose4j.jwk.EllipticCurveJsonWebKey", "factory"},
		{"org.jose4j.jwk.EcJwkGenerator.generateJwk", 3, "org.jose4j.jwk.EllipticCurveJsonWebKey", "factory"},
		{"org.jose4j.jwk.OctJwkGenerator.generateJwk", 1, "org.jose4j.jwk.OctetSequenceJsonWebKey", "factory"},
		{"org.jose4j.jwk.OctJwkGenerator.generateJwk", 2, "org.jose4j.jwk.OctetSequenceJsonWebKey", "factory"},
		{"org.jose4j.jwk.OkpJwkGenerator.generateJwk", 1, "org.jose4j.jwk.OctetKeyPairJsonWebKey", "factory"},
		{"org.jose4j.jwk.OkpJwkGenerator.generateJwk", 3, "org.jose4j.jwk.OctetKeyPairJsonWebKey", "factory"},

		// KeyUtil.generateKeyPair (backing the JWK generators above).
		{"org.jose4j.keys.RsaKeyUtil.generateKeyPair", 1, "java.security.KeyPair", "factory"},
		{"org.jose4j.keys.EcKeyUtil.generateKeyPair", 1, "java.security.KeyPair", "factory"},
		{"org.jose4j.keys.OctetKeyPairUtil.generateKeyPair", 1, "java.security.KeyPair", "factory"},

		// "oct" JWK material.
		{"org.jose4j.jwk.OctetSequenceJsonWebKey.<init>", 1, "org.jose4j.jwk.OctetSequenceJsonWebKey", "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.Return.Type != tt.want || c.Role != tt.role {
				t.Fatalf("%s#%d = %#v, want return %q with role %q", tt.method, tt.arity, c, tt.want, tt.role)
			}
			if c.Return.Confidence != "high" {
				t.Fatalf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
			}
			if c.SourceLibrary != "jose4j" {
				t.Fatalf("%s#%d source library = %q, want jose4j", tt.method, tt.arity, c.SourceLibrary)
			}
		})
	}

	// RsaJwkGenerator.generateJwk's bits argument (index 0) contributes a
	// "keySize" metadata role, mirroring the netty sslProvider/protocols and
	// jwcrypto JWK.generate keyType parameter-derivation pattern.
	rsaGen := kb.ContractsFor("org.jose4j.jwk.RsaJwkGenerator.generateJwk", 1)
	if len(rsaGen) != 1 || len(rsaGen[0].Parameters) != 1 {
		t.Fatalf("RsaJwkGenerator.generateJwk#1 parameters = %#v, want a single keySize parameter role", rsaGen)
	}
	if p := rsaGen[0].Parameters[0]; p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("RsaJwkGenerator.generateJwk#1 parameters[0] = %#v, want index=0 keySize/argument_value", p)
	}

	// EcJwkGenerator.generateJwk's spec argument (index 0) contributes a
	// "curve" metadata role.
	ecGen := kb.ContractsFor("org.jose4j.jwk.EcJwkGenerator.generateJwk", 1)
	if len(ecGen) != 1 || len(ecGen[0].Parameters) != 1 {
		t.Fatalf("EcJwkGenerator.generateJwk#1 parameters = %#v, want a single curve parameter role", ecGen)
	}
	if p := ecGen[0].Parameters[0]; p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "curve" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("EcJwkGenerator.generateJwk#1 parameters[0] = %#v, want index=0 curve/argument_value", p)
	}

	// PasswordBasedKeyDerivationFunction2.derive's iterationCount argument
	// (index 2) contributes an "iterations" metadata role -- the PBES2
	// security-relevant parameter the jose4j-0.9.6 audit flagged.
	pbkdf2Derive := kb.ContractsFor(pbkdf2+".derive", 5)
	if len(pbkdf2Derive) != 1 || len(pbkdf2Derive[0].Parameters) != 1 {
		t.Fatalf("PasswordBasedKeyDerivationFunction2.derive#5 parameters = %#v, want a single iterations parameter role", pbkdf2Derive)
	}
	if p := pbkdf2Derive[0].Parameters[0]; p.Index == nil || *p.Index != 2 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "iterations" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("PasswordBasedKeyDerivationFunction2.derive#5 parameters[0] = %#v, want index=2 iterations/argument_value", p)
	}

	// Pbes2HmacShaWithAesKeyWrapAlgorithm.setDefaultIterationCount's argument
	// (index 0) contributes an "iterations" metadata role too.
	setIter := kb.ContractsFor(pbes2+".setDefaultIterationCount", 1)
	if len(setIter) != 1 || len(setIter[0].Parameters) != 1 {
		t.Fatalf("setDefaultIterationCount#1 parameters = %#v, want a single iterations parameter role", setIter)
	}
	if p := setIter[0].Parameters[0]; p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "iterations" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("setDefaultIterationCount#1 parameters[0] = %#v, want index=0 iterations/argument_value", p)
	}

	// Every return.type this KB introduces must be reachable through the
	// hierarchy the loader validated at LoadEmbedded time; spot-check the
	// family roots and a couple of nested leaves here too.
	for _, typ := range []string{
		keyMgmtIface, contentEncIfc, rsaKM, rsaKM + ".RsaOaep256",
		aesKW, aesGcmKW, pbes2, direct, aesCbcHmac,
		aesCbcHmac + ".Aes256CbcHmacSha512", concatKDF, pbkdf2,
		"org.jose4j.jwk.RsaJsonWebKey", "org.jose4j.jwk.EllipticCurveJsonWebKey",
		"org.jose4j.jwk.OctetKeyPairJsonWebKey", "org.jose4j.jwk.OctetSequenceJsonWebKey",
	} {
		if len(kb.Hierarchy[typ]) == 0 {
			t.Errorf("hierarchy[%q] is empty", typ)
		}
	}
}
