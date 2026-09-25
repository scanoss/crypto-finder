package callgraph

import (
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// springSecurityCryptoConsumer calls every Spring Security Crypto rule API the
// base, 3.1, 5.5 and 6.3 contract files add, in the shapes the crypto_rules
// fixtures use: receivers typed as the concrete class and fluent new X().m().
const springSecurityCryptoConsumer = `
package app;

import java.security.KeyPair;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.RsaAlgorithm;
import org.springframework.security.crypto.encrypt.RsaRawEncryptor;
import org.springframework.security.crypto.encrypt.RsaSecretEncryptor;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.Md4PasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class App {
    public String text(String password, String salt, String secret) {
        TextEncryptor encryptor = Encryptors.text(password, salt);
        return encryptor.encrypt(secret);
    }

    public String queryable(String password, String salt, String secret) {
        TextEncryptor encryptor = Encryptors.queryableText(password, salt);
        return encryptor.encrypt(secret);
    }

    public String delux(String password, String salt, String secret) {
        TextEncryptor encryptor = Encryptors.delux(password, salt);
        return encryptor.decrypt(encryptor.encrypt(secret));
    }

    public boolean bcrypt(String raw) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        String hash = encoder.encode(raw);
        return encoder.matches(raw, hash);
    }

    public String rawRsa(KeyPair keys, String plain) {
        RsaRawEncryptor encryptor = new RsaRawEncryptor(keys, RsaAlgorithm.OAEP);
        String publicKey = encryptor.getPublicKey();
        return encryptor.decrypt(encryptor.encrypt(plain)) + publicKey;
    }

    public byte[] secretRsa(KeyPair keys, byte[] plain) {
        RsaSecretEncryptor encryptor = new RsaSecretEncryptor(keys, RsaAlgorithm.OAEP, "salt", true);
        return encryptor.decrypt(encryptor.encrypt(plain));
    }

    public String legacy(String raw) {
        String a = new MessageDigestPasswordEncoder("SHA-256").encode(raw);
        String b = new LdapShaPasswordEncoder().encode(raw);
        String c = new Md4PasswordEncoder().encode(raw);
        String d = new StandardPasswordEncoder("secret").encode(raw);
        return a + b + c + d;
    }

    public String removedIn6(String raw) {
        String a = new SCryptPasswordEncoder().encode(raw);
        String b = new Argon2PasswordEncoder().encode(raw);
        String c = new Pbkdf2PasswordEncoder().encode(raw);
        String d = new Pbkdf2PasswordEncoder("secret").encode(raw);
        String e = new Pbkdf2PasswordEncoder("secret", 16).encode(raw);
        String f = new Pbkdf2PasswordEncoder("secret", 185000, 256).encode(raw);
        return a + b + c + d + e + f;
    }
}
`

// Each call keys on the identity the Java parser gives it, and resolves to
// exactly one contract with its lifecycle role in the file that claims the
// versions where the API exists.
func TestSpringSecurityCryptoContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	calls := parseJavaCallArities(t, springSecurityCryptoConsumer)

	const pkg = "org.springframework.security.crypto."
	for _, tc := range []struct {
		method  string
		arity   int
		role    string
		library string
	}{
		{pkg + "encrypt.Encryptors.text", 2, "factory", "spring-security-crypto"},
		{pkg + "encrypt.Encryptors.delux", 2, "factory", "spring-security-crypto"},
		{pkg + "encrypt.Encryptors.queryableText", 2, "factory", "spring-security-crypto-3.1"},
		{pkg + "encrypt.TextEncryptor.encrypt", 1, "operation", "spring-security-crypto"},
		{pkg + "encrypt.TextEncryptor.decrypt", 1, "operation", "spring-security-crypto"},
		{pkg + "bcrypt.BCryptPasswordEncoder.<init>", 1, "factory", "spring-security-crypto"},
		{pkg + "bcrypt.BCryptPasswordEncoder.encode", 1, "operation", "spring-security-crypto"},
		{pkg + "bcrypt.BCryptPasswordEncoder.matches", 2, "operation", "spring-security-crypto"},
		{pkg + "password.MessageDigestPasswordEncoder.<init>", 1, "factory", "spring-security-crypto"},
		{pkg + "password.LdapShaPasswordEncoder.<init>", 0, "factory", "spring-security-crypto"},
		{pkg + "password.Md4PasswordEncoder.<init>", 0, "factory", "spring-security-crypto"},
		{pkg + "password.StandardPasswordEncoder.<init>", 1, "factory", "spring-security-crypto"},
		{pkg + "encrypt.RsaRawEncryptor.<init>", 2, "factory", "spring-security-crypto-6.3"},
		{pkg + "encrypt.RsaRawEncryptor.getPublicKey", 0, "output", "spring-security-crypto-6.3"},
		{pkg + "encrypt.RsaSecretEncryptor.<init>", 4, "factory", "spring-security-crypto-6.3"},
		{pkg + "scrypt.SCryptPasswordEncoder.<init>", 0, "factory", "spring-security-crypto-5.5"},
		{pkg + "argon2.Argon2PasswordEncoder.<init>", 0, "factory", "spring-security-crypto-5.5"},
		{pkg + "password.Pbkdf2PasswordEncoder.<init>", 0, "factory", "spring-security-crypto-5.5"},
		{pkg + "password.Pbkdf2PasswordEncoder.<init>", 1, "factory", "spring-security-crypto-5.5"},
		{pkg + "password.Pbkdf2PasswordEncoder.<init>", 2, "factory", "spring-security-crypto-5.5"},
		{pkg + "password.Pbkdf2PasswordEncoder.<init>", 3, "factory", "spring-security-crypto-5.5"},
	} {
		if !slices.Contains(calls[tc.method], tc.arity) {
			t.Errorf("no parsed call to %s with %d argument(s); parsed %v", tc.method, tc.arity, calls[tc.method])
			continue
		}
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsForTolerant(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		if got[0].Role != tc.role {
			t.Errorf("%s/%d: role = %q, want %q", tc.method, tc.arity, got[0].Role, tc.role)
		}
		if got[0].SourceLibrary != tc.library {
			t.Errorf("%s/%d: library = %q, want %q", tc.method, tc.arity, got[0].SourceLibrary, tc.library)
		}
	}
}

// The RSA encryptors overload encrypt and decrypt at arity 1 as String to
// String and byte[] to byte[], so no single return is true and none is
// declared. RsaSecretEncryptor has no five-argument constructor in any release.
func TestSpringSecurityCryptoContractsLeaveOverloadedRsaCallsUndeclared(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	calls := parseJavaCallArities(t, springSecurityCryptoConsumer)

	const pkg = "org.springframework.security.crypto.encrypt."
	for _, method := range []string{
		pkg + "RsaRawEncryptor.encrypt",
		pkg + "RsaRawEncryptor.decrypt",
		pkg + "RsaSecretEncryptor.encrypt",
		pkg + "RsaSecretEncryptor.decrypt",
	} {
		if !slices.Contains(calls[method], 1) {
			t.Fatalf("no parsed call to %s with 1 argument; the fixture no longer exercises it", method)
		}
		if got := kb.ContractsForTolerant(method, 1); len(got) != 0 {
			t.Errorf("%s#1 resolved to %#v, want no contract", method, got)
		}
	}
	for _, class := range []string{pkg + "RsaRawEncryptor", pkg + "RsaSecretEncryptor"} {
		if parents := kb.Hierarchy[class]; !slices.Equal(parents, []string{pkg + "BytesEncryptor", pkg + "TextEncryptor"}) {
			t.Errorf("%s hierarchy = %v, want BytesEncryptor and TextEncryptor", class, parents)
		}
	}
	if got := kb.ContractsFor(pkg+"RsaSecretEncryptor.<init>", 5); len(got) != 0 {
		t.Errorf("RsaSecretEncryptor.<init>#5 = %#v, want none", got)
	}
}

// MessageDigestPasswordEncoder takes its digest algorithm as the only
// argument, so that argument selects the operation.
func TestSpringSecurityCryptoMessageDigestEncoderReportsAlgorithm(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	got := kb.ContractsFor("org.springframework.security.crypto.password.MessageDigestPasswordEncoder.<init>", 1)
	if len(got) != 1 || len(got[0].Parameters) != 1 {
		t.Fatalf("MessageDigestPasswordEncoder.<init>#1 = %#v, want one contract with one parameter role", got)
	}
	p := got[0].Parameters[0]
	if p.Index == nil || *p.Index != 0 || p.Role != "operation-determining" || p.Contributes == nil ||
		p.Contributes.Property != "algorithm" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("MessageDigestPasswordEncoder.<init>#1 parameter = %#v, want index 0 operation-determining algorithm/argument_value", p)
	}
}
