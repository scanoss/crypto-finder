// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// jose4j_e2e_integration_test.go — scanoss/crypto-finder#188 scan-layer proof.
//
// Proves that entry-point synthesis (engine.SynthesizeRuleCryptoEntryPoints)
// JOINS the scanoss/crypto_rules#175 jose4j rule "api" anchors against a
// jose4j-shaped source tree mined with the real Java parser + callgraph
// builder — the same path `crypto-finder scan --export-callgraph` uses when
// mining jose4j itself. This is the public-export proof that the
// jose4j.yaml contract's method+arity keys
// (internal/callgraph/contracts/java/jose4j.yaml) match what the Java parser
// actually emits for the JWE key-management/content-encryption constructors,
// the hand-rolled KDF constructor+operation methods, and the JWK generator
// factories — not just the embedded-contract loader assertions in
// jose4j_java_library_test.go.
package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// jose4jJweSource is a jose4j-shaped stub of org/jose4j/jwe/*.java (0.9.6):
// the RsaKeyManagementAlgorithm/AesKeyWrapManagementAlgorithm/
// AesGcmKeyEncryptionAlgorithm/Pbes2HmacShaWithAesKeyWrapAlgorithm nested-class
// constructor shapes and the AesCbcHmacSha2ContentEncryptionAlgorithm
// encrypt/decrypt method shapes the crypto_rules#175 rules anchor on, at the
// same arities the jose4j.yaml contract keys on. It is a stub (not a full
// compilable copy) because the tree-sitter-based Java parser extracts
// declarations syntactically and does not require the real supporting types
// (Headers, ProviderContext, ContentEncryptionKeyDescriptor, ...) to be
// resolvable.
const jose4jJweSource = `package org.jose4j.jwe;

public class RsaKeyManagementAlgorithm {
    public RsaKeyManagementAlgorithm(String javaAlg, String alg) {
    }

    public static class RsaOaep extends RsaKeyManagementAlgorithm {
        public RsaOaep() {
            super("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RSA-OAEP");
        }
    }

    public static class RsaOaep256 extends RsaKeyManagementAlgorithm {
        public RsaOaep256() {
            super("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA-OAEP-256");
        }
    }

    public static class Rsa1_5 extends RsaKeyManagementAlgorithm {
        public Rsa1_5() {
            super("RSA/ECB/PKCS1Padding", "RSA1_5");
        }
    }
}

class AesKeyWrapManagementAlgorithm {
    public AesKeyWrapManagementAlgorithm(String alg, int keyByteLength) {
    }

    public static class Aes128 extends AesKeyWrapManagementAlgorithm {
        public Aes128() {
            super("A128KW", 16);
        }
    }
}

class AesGcmKeyEncryptionAlgorithm {
    public AesGcmKeyEncryptionAlgorithm(String alg, int keyByteLength) {
    }

    public static class Aes128Gcm extends AesGcmKeyEncryptionAlgorithm {
        public Aes128Gcm() {
            super("A128GCMKW", 16);
        }
    }
}

class Pbes2HmacShaWithAesKeyWrapAlgorithm {
    public Pbes2HmacShaWithAesKeyWrapAlgorithm(String alg, String hmacAlg, AesKeyWrapManagementAlgorithm keyWrapAlg) {
    }

    public static class HmacSha256Aes128 extends Pbes2HmacShaWithAesKeyWrapAlgorithm {
        public HmacSha256Aes128() {
            super("PBES2-HS256+A128KW", "HmacSHA256", new AesKeyWrapManagementAlgorithm.Aes128());
        }
    }
}

class AesCbcHmacSha2ContentEncryptionAlgorithm {
    public AesCbcHmacSha2ContentEncryptionAlgorithm(String alg, int cekByteLen, String javaHmacAlg, int tagTruncationLength) {
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, Headers headers, byte[] ivOverride, ProviderContext providerContext) {
        return null;
    }

    public byte[] decrypt(ContentEncryptionParts contentEncryptionParts, byte[] aad, byte[] contentEncryptionKey, Headers headers, ProviderContext providerContext) {
        return null;
    }

    public static class Aes128CbcHmacSha256 extends AesCbcHmacSha2ContentEncryptionAlgorithm {
        public Aes128CbcHmacSha256() {
            super("A128CBC-HS256", 32, "HmacSHA256", 16);
        }
    }
}

class ContentEncryptionParts {}
class Headers {}
class ProviderContext {}
`

// jose4jKdfSource is a jose4j-shaped stub of org/jose4j/jwe/kdf/*.java: the
// hand-rolled ConcatKeyDerivationFunction (NIST SP 800-56A Concat KDF) and
// PasswordBasedKeyDerivationFunction2 (RFC 2898 PBKDF2) constructor +
// operation method shapes.
const jose4jKdfSource = `package org.jose4j.jwe.kdf;

public class ConcatKeyDerivationFunction {
    public ConcatKeyDerivationFunction(String hashAlgorithm) {
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, byte[] otherInfo) {
        return null;
    }
}

public class PasswordBasedKeyDerivationFunction2 {
    public PasswordBasedKeyDerivationFunction2(String hmacAlgorithm) {
    }

    public byte[] derive(byte[] password, byte[] salt, int iterationCount, int dkLen, String provider) {
        return null;
    }
}
`

// jose4jJwkSource is a jose4j-shaped stub of org/jose4j/jwk/*.java: the four
// JWK generators and the OctetSequenceJsonWebKey AES-labeling constructor.
const jose4jJwkSource = `package org.jose4j.jwk;

public class RsaJwkGenerator {
    public static RsaJsonWebKey generateJwk(int bits) {
        return null;
    }
}

public class EcJwkGenerator {
    public static EllipticCurveJsonWebKey generateJwk(ECParameterSpec spec) {
        return null;
    }
}

public class OctJwkGenerator {
    public static OctetSequenceJsonWebKey generateJwk(int keyLengthInBits) {
        return null;
    }
}

public class OkpJwkGenerator {
    public static OctetKeyPairJsonWebKey generateJwk(String subtype) {
        return null;
    }
}

class OctetSequenceJsonWebKey {
    OctetSequenceJsonWebKey(java.util.Map<String, Object> params) {
    }
}

class RsaJsonWebKey {}
class EllipticCurveJsonWebKey {}
class OctetKeyPairJsonWebKey {}
class ECParameterSpec {}
`

// jose4jKeysSource is a jose4j-shaped stub of org/jose4j/keys/*.java: the
// *KeyUtil.generateKeyPair wrappers backing the JWK generators above.
const jose4jKeysSource = `package org.jose4j.keys;

public class RsaKeyUtil {
    public java.security.KeyPair generateKeyPair(int bits) {
        return null;
    }
}

public class EcKeyUtil {
    public java.security.KeyPair generateKeyPair(java.security.spec.ECParameterSpec spec) {
        return null;
    }
}

public class OctetKeyPairUtil {
    public java.security.KeyPair generateKeyPair(String name) {
        return null;
    }
}
`

// jose4jRulesYAML mirrors the scanoss/crypto_rules#175 rule "api" anchors for
// the P2/P3/hand-rolled jose4j scope: the three RSA key-management variants,
// AES key wrap, AES-GCM key wrap, PBES2, the hand-rolled ConcatKDF/PBKDF2
// constructor + operation pairs, the AES-CBC-HMAC encrypt/decrypt pair, the
// four JWK generators, the three KeyUtil.generateKeyPair wrappers, and the
// "oct" JWK material constructor.
const jose4jRulesYAML = `rules:
  - id: java.jose4j.algorithm.pke.rsa-oaep-sha1-transformation
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: pke
        algorithmName: RSA-OAEP-SHA-1
        library: jose4j
        api: org.jose4j.jwe.RsaKeyManagementAlgorithm.RsaOaep.<init>
  - id: java.jose4j.algorithm.pke.rsa-oaep-sha256-transformation
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: pke
        algorithmName: RSA-OAEP-SHA-256
        library: jose4j
        api: org.jose4j.jwe.RsaKeyManagementAlgorithm.RsaOaep256.<init>
  - id: java.jose4j.algorithm.pke.rsa1_5-transformation
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: pke
        algorithmName: RSAES-PKCS1-v1_5
        library: jose4j
        api: org.jose4j.jwe.RsaKeyManagementAlgorithm.Rsa1_5.<init>
  - id: java.jose4j.algorithm.key-wrap.aes-kw
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: key-wrap
        algorithmFamily: AES
        library: jose4j
        api: org.jose4j.jwe.AesKeyWrapManagementAlgorithm.<init>
  - id: java.jose4j.algorithm.key-wrap.aes-gcm-kw
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: key-wrap
        algorithmFamily: AES
        library: jose4j
        api: org.jose4j.jwe.AesGcmKeyEncryptionAlgorithm.<init>
  - id: java.jose4j.algorithm.kdf.pbes2
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: kdf
        algorithmFamily: PBES2
        library: jose4j
        api: org.jose4j.jwe.Pbes2HmacShaWithAesKeyWrapAlgorithm.<init>
  - id: java.jose4j.algorithm.kdf.concat-kdf
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: kdf
        algorithmFamily: ConcatKDF
        library: jose4j
        api: org.jose4j.jwe.kdf.ConcatKeyDerivationFunction.<init>
  - id: java.jose4j.algorithm.kdf.concat-kdf-derive
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: kdf
        algorithmFamily: ConcatKDF
        operation: keyderive
        library: jose4j
        api: org.jose4j.jwe.kdf.ConcatKeyDerivationFunction.kdf
  - id: java.jose4j.algorithm.kdf.pbkdf2-handrolled
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: kdf
        algorithmFamily: PBKDF2
        library: jose4j
        api: org.jose4j.jwe.kdf.PasswordBasedKeyDerivationFunction2.<init>
  - id: java.jose4j.algorithm.kdf.pbkdf2-handrolled-derive
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: kdf
        algorithmFamily: PBKDF2
        operation: keyderive
        library: jose4j
        api: org.jose4j.jwe.kdf.PasswordBasedKeyDerivationFunction2.derive
  - id: java.jose4j.algorithm.ae.aes-cbc-hmac-encrypt
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: ae
        algorithmFamily: AES
        operation: encrypt
        library: jose4j
        api: org.jose4j.jwe.AesCbcHmacSha2ContentEncryptionAlgorithm.encrypt
  - id: java.jose4j.algorithm.ae.aes-cbc-hmac-decrypt
    metadata:
      crypto:
        assetType: algorithm
        algorithmPrimitive: ae
        algorithmFamily: AES
        operation: decrypt
        library: jose4j
        api: org.jose4j.jwe.AesCbcHmacSha2ContentEncryptionAlgorithm.decrypt
  - id: java.jose4j.related-crypto-material.key.rsa-jwk-keygen
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: key
        materialAlgorithm: RSA
        operation: keygen
        library: jose4j
        api: org.jose4j.jwk.RsaJwkGenerator.generateJwk
  - id: java.jose4j.related-crypto-material.key.ec-jwk-keygen
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: key
        materialAlgorithm: EC
        operation: keygen
        library: jose4j
        api: org.jose4j.jwk.EcJwkGenerator.generateJwk
  - id: java.jose4j.related-crypto-material.key.oct-jwk-keygen
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: secret-key
        materialAlgorithm: AES
        operation: keygen
        library: jose4j
        api: org.jose4j.jwk.OctJwkGenerator.generateJwk
  - id: java.jose4j.related-crypto-material.key.okp-jwk-keygen
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: key
        operation: keygen
        library: jose4j
        api: org.jose4j.jwk.OkpJwkGenerator.generateJwk
  - id: java.jose4j.related-crypto-material.key.rsa-keyutil-keygen
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: key
        materialAlgorithm: RSA
        operation: keygen
        library: jose4j
        api: org.jose4j.keys.RsaKeyUtil.generateKeyPair
  - id: java.jose4j.related-crypto-material.key.ec-keyutil-keygen
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: key
        materialAlgorithm: EC
        operation: keygen
        library: jose4j
        api: org.jose4j.keys.EcKeyUtil.generateKeyPair
  - id: java.jose4j.related-crypto-material.key.octet-keypair-keyutil-keygen
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: key
        operation: keygen
        library: jose4j
        api: org.jose4j.keys.OctetKeyPairUtil.generateKeyPair
  - id: java.jose4j.related-crypto-material.key.octet-sequence-aes-labeling
    metadata:
      crypto:
        assetType: related-crypto-material
        materialType: secret-key
        materialAlgorithm: AES
        library: jose4j
        api: org.jose4j.jwk.OctetSequenceJsonWebKey.<init>
`

// jose4jRuleAPIs is every "api" anchor synthesized above; used both to size
// the expected entry-point count and to assert per-api coverage.
var jose4jRuleAPIs = []string{
	"org.jose4j.jwe.RsaKeyManagementAlgorithm.RsaOaep.<init>",
	"org.jose4j.jwe.RsaKeyManagementAlgorithm.RsaOaep256.<init>",
	"org.jose4j.jwe.RsaKeyManagementAlgorithm.Rsa1_5.<init>",
	"org.jose4j.jwe.AesKeyWrapManagementAlgorithm.<init>",
	"org.jose4j.jwe.AesGcmKeyEncryptionAlgorithm.<init>",
	"org.jose4j.jwe.Pbes2HmacShaWithAesKeyWrapAlgorithm.<init>",
	"org.jose4j.jwe.kdf.ConcatKeyDerivationFunction.<init>",
	"org.jose4j.jwe.kdf.ConcatKeyDerivationFunction.kdf",
	"org.jose4j.jwe.kdf.PasswordBasedKeyDerivationFunction2.<init>",
	"org.jose4j.jwe.kdf.PasswordBasedKeyDerivationFunction2.derive",
	"org.jose4j.jwe.AesCbcHmacSha2ContentEncryptionAlgorithm.encrypt",
	"org.jose4j.jwe.AesCbcHmacSha2ContentEncryptionAlgorithm.decrypt",
	"org.jose4j.jwk.RsaJwkGenerator.generateJwk",
	"org.jose4j.jwk.EcJwkGenerator.generateJwk",
	"org.jose4j.jwk.OctJwkGenerator.generateJwk",
	"org.jose4j.jwk.OkpJwkGenerator.generateJwk",
	"org.jose4j.keys.RsaKeyUtil.generateKeyPair",
	"org.jose4j.keys.EcKeyUtil.generateKeyPair",
	"org.jose4j.keys.OctetKeyPairUtil.generateKeyPair",
	"org.jose4j.jwk.OctetSequenceJsonWebKey.<init>",
}

// TestJose4j_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors proves
// that mining jose4j-shaped source across its jwe/jwe.kdf/jwk/keys packages
// produces a synthesized crypto entry point for every scanoss/crypto_rules#175
// "api" anchor in the P2/P3/hand-rolled scope: the RSA key-management
// variants, AES/AES-GCM key wrap, PBES2, the hand-rolled ConcatKDF/PBKDF2
// constructor+operation pairs, the AES-CBC-HMAC encrypt/decrypt pair, the JWK
// generators, the KeyUtil.generateKeyPair wrappers, and the "oct" JWK
// material constructor.
func TestJose4j_E2E_SynthesizeRuleCryptoEntryPoints_JoinsRuleAPIAnchors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJavaFile(t, root, "jwe", "jwe.java", jose4jJweSource)
	writeJavaFile(t, root, "jwe/kdf", "kdf.java", jose4jKdfSource)
	writeJavaFile(t, root, "jwk", "jwk.java", jose4jJwkSource)
	writeJavaFile(t, root, "keys", "keys.java", jose4jKeysSource)

	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{
			{Dir: filepath.Join(root, "jwe"), ImportPath: "org.jose4j.jwe"},
			{Dir: filepath.Join(root, "jwe", "kdf"), ImportPath: "org.jose4j.jwe.kdf"},
			{Dir: filepath.Join(root, "jwk"), ImportPath: "org.jose4j.jwk"},
			{Dir: filepath.Join(root, "keys"), ImportPath: "org.jose4j.keys"},
		}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(jose4j stub): %v", err)
	}

	ruleDir := t.TempDir()
	rulePath := filepath.Join(ruleDir, "jose4j.yaml")
	if err := os.WriteFile(rulePath, []byte(jose4jRulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "java")

	if n != len(jose4jRuleAPIs) {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Fatalf("synthesized %d entry points, want %d; graph FQNs: %v", n, len(jose4jRuleAPIs), fqns)
	}

	seenAPI := map[string]bool{}
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			seenAPI[asset.Metadata["api"]] = true
		}
	}
	for _, api := range jose4jRuleAPIs {
		if !seenAPI[api] {
			t.Errorf("no synthesized entry point for rule anchor api %q; seen: %v", api, seenAPI)
		}
	}
}

func writeJavaFile(t *testing.T, root, subdir, name, content string) {
	t.Helper()
	dir := filepath.Join(root, subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
