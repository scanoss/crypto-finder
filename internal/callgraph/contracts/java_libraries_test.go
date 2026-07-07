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
