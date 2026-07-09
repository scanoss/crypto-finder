package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedJavaIncludesPassword4JAndBouncyCastleContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	passwordHash := kb.ContractsFor("com.password4j.Password.hash", 1)
	if len(passwordHash) != 1 {
		t.Fatalf("Password.hash#1 contracts = %d, want 1", len(passwordHash))
	}
	if passwordHash[0].Return.Type != "com.password4j.HashBuilder" || passwordHash[0].SourceLibrary != "password4j" {
		t.Fatalf("Password.hash#1 = %#v, want com.password4j.HashBuilder from password4j", passwordHash[0])
	}

	// Casing must match Password4J's real API (withBcrypt/withScrypt, lowercase
	// c/s); contracts match on exact Method#Arity so the casing is load-bearing.
	for _, method := range []string{
		"com.password4j.HashBuilder.withBcrypt",
		"com.password4j.HashBuilder.withScrypt",
		"com.password4j.HashBuilder.withPBKDF2",
		"com.password4j.HashBuilder.withCompressedPBKDF2",
		"com.password4j.HashBuilder.withArgon2",
		"com.password4j.HashBuilder.withMessageDigest",
	} {
		got := kb.ContractsFor(method, 0)
		if len(got) != 1 {
			t.Fatalf("%s#0 contracts = %d, want 1", method, len(got))
		}
		if got[0].Return.Type != "com.password4j.Hash" || got[0].SourceLibrary != "password4j" {
			t.Fatalf("%s#0 = %#v, want com.password4j.Hash from password4j", method, got[0])
		}
	}

	bcKeyPair := kb.ContractsFor("org.bouncycastle.crypto.generators.ECKeyPairGenerator.generateKeyPair", 0)
	if len(bcKeyPair) != 1 {
		t.Fatalf("ECKeyPairGenerator.generateKeyPair#0 contracts = %d, want 1", len(bcKeyPair))
	}
	if bcKeyPair[0].Return.Type != "org.bouncycastle.crypto.AsymmetricCipherKeyPair" || bcKeyPair[0].SourceLibrary != "bouncycastle" {
		t.Fatalf("ECKeyPairGenerator.generateKeyPair#0 = %#v, want AsymmetricCipherKeyPair from bouncycastle", bcKeyPair[0])
	}
}

func TestLoadEmbeddedJavaIncludesTier0GapContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		{"io.jsonwebtoken.Jwts.builder", 0, "io.jsonwebtoken.JwtBuilder", "jjwt"},
		{"io.jsonwebtoken.JwtBuilder.signWith", 1, "io.jsonwebtoken.JwtBuilder", "jjwt"},
		{"io.jsonwebtoken.JwtParserBuilder.build", 0, "io.jsonwebtoken.JwtParser", "jjwt"},
		{"io.jsonwebtoken.JwtParser.parseSignedClaims", 1, "io.jsonwebtoken.Jws", "jjwt"},
		{"com.nimbusds.jose.JWSObject.<init>", 2, "com.nimbusds.jose.JWSObject", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.JWSObject.verify", 1, "boolean", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.RSASSASigner.sign", 2, "com.nimbusds.jose.util.Base64URL", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.DirectEncrypter.<init>", 1, "com.nimbusds.jose.crypto.DirectEncrypter", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.ECDSASigner.<init>", 1, "com.nimbusds.jose.crypto.ECDSASigner", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.MACVerifier.<init>", 1, "com.nimbusds.jose.crypto.MACVerifier", "nimbus-jose-jwt"},
		{"org.apache.sshd.common.config.keys.KeyUtils.generateKeyPair", 2, "java.security.KeyPair", "apache-sshd"},
		{"org.apache.sshd.common.cipher.BuiltinCiphers.resolveFactory", 1, "org.apache.sshd.common.cipher.CipherFactory", "apache-sshd"},
		{"org.apache.sshd.common.mac.BuiltinMacs.create", 0, "org.apache.sshd.common.mac.Mac", "apache-sshd"},
		{"org.apache.sshd.common.signature.BuiltinSignatures.create", 0, "org.apache.sshd.common.signature.Signature", "apache-sshd"},
		{"org.apache.sshd.client.SshClient.setUpDefaultClient", 0, "org.apache.sshd.client.SshClient", "apache-sshd"},
		{"org.apache.sshd.server.SshServer.setUpDefaultServer", 0, "org.apache.sshd.server.SshServer", "apache-sshd"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.wantReturn || got[0].SourceLibrary != tt.wantLib {
				t.Fatalf("%s#%d = %#v, want %s from %s", tt.method, tt.arity, got[0], tt.wantReturn, tt.wantLib)
			}
		})
	}
}

// TestLoadEmbeddedJava_BouncyCastleRoleCoverage is the issue-103 (WU1/BC-YAML)
// acceptance test scoped to what a unit test can verify without a real BC
// corpus (see internal/scan/bcprov_fragment_profile_test.go for the
// env-gated full-corpus harness): every newly-authored role-tagged BC
// contract loads with the expected role, and processBlock/doFinal/update
// resolve as role: operation via the primitive-family interfaces rather
// than per-engine duplication.
func TestLoadEmbeddedJava_BouncyCastleRoleCoverage(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		role   string
	}{
		{"org.bouncycastle.crypto.params.KeyParameter.<init>", 1, "factory"},
		{"org.bouncycastle.crypto.params.ParametersWithIV.<init>", 2, "factory"},
		{"org.bouncycastle.crypto.params.ParametersWithRandom.<init>", 2, "factory"},
		{"org.bouncycastle.crypto.params.AEADParameters.getNonce", 0, "output"},
		{"org.bouncycastle.crypto.params.AEADParameters.getAssociatedText", 0, "output"},
		{"org.bouncycastle.crypto.params.AEADParameters.getMacSize", 0, "output"},
		{"org.bouncycastle.crypto.params.KeyParameter.getKey", 0, "output"},
		{"org.bouncycastle.crypto.BlockCipher.processBlock", 4, "operation"},
		{"org.bouncycastle.crypto.Digest.update", 1, "operation"},
		{"org.bouncycastle.crypto.Digest.update", 3, "operation"},
		{"org.bouncycastle.crypto.Digest.doFinal", 2, "operation"},
		{"org.bouncycastle.crypto.Signer.generateSignature", 0, "operation"},
		{"org.bouncycastle.crypto.Signer.verifySignature", 1, "operation"},
		{"org.bouncycastle.crypto.Mac.doFinal", 2, "operation"},
		{"org.bouncycastle.crypto.DerivationFunction.generateBytes", 3, "operation"},
		// Corrected from role: config (feeding data into a running digest is
		// the operation itself, not object configuration).
		{"org.bouncycastle.crypto.digests.GeneralDigest.update", 3, "operation"},
		{"org.bouncycastle.crypto.digests.KeccakDigest.update", 3, "operation"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Role != tt.role {
				t.Fatalf("%s#%d role = %q, want %q", tt.method, tt.arity, got[0].Role, tt.role)
			}
		})
	}

	// KeyParameter.<init>'s byte[] key argument contributes keySize via
	// argument_bit_length (the WU3 concrete target from the design).
	kp := kb.ContractsFor("org.bouncycastle.crypto.params.KeyParameter.<init>", 1)
	if len(kp) != 1 || len(kp[0].Parameters) != 1 {
		t.Fatalf("KeyParameter.<init>#1 parameters = %#v, want 1 entry", kp)
	}
	p := kp[0].Parameters[0]
	if p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("KeyParameter.<init>#1 parameters[0] = %#v, want index=0 metadata-contributing keySize/argument_bit_length", p)
	}

	// AESEngine implements BlockCipher, so the interface-level processBlock
	// contract is reachable via hierarchy without a per-engine duplicate.
	if parents := kb.Hierarchy["org.bouncycastle.crypto.engines.AESEngine"]; len(parents) != 1 || parents[0] != "org.bouncycastle.crypto.BlockCipher" {
		t.Fatalf("AESEngine hierarchy = %v, want [BlockCipher]", parents)
	}
}
