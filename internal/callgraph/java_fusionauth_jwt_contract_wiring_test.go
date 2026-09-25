package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

type fusionAuthWant struct {
	arity int
	role  string
}

// resolveFusionAuthCalls parses src and checks every call the parser resolves to
// a key in want or in none against the embedded Java knowledge base. It returns
// the keys it saw so the caller can assert full coverage.
func resolveFusionAuthCalls(t *testing.T, src string, want map[string]fusionAuthWant, none map[string]bool) map[string]bool {
	t.Helper()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				call := &fn.Calls[j]
				callee := call.Callee
				key, _ := splitMethodArity(&callee)
				if callee.Package == "" || callee.Type == "" {
					continue
				}
				if none[key] {
					if got := kb.ContractsForTolerant(key, len(call.Arguments)); len(got) != 0 {
						t.Errorf("%q resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				expect, ok := want[key]
				if !ok || len(call.Arguments) != expect.arity {
					continue
				}
				got := kb.ContractsFor(key, expect.arity)
				if len(got) != 1 {
					t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", key, expect.arity, len(got))
					continue
				}
				if got[0].Role != expect.role {
					t.Errorf("%s/%d: role = %q, want %q", key, expect.arity, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "fusionauth-jwt" {
					t.Errorf("%s: library = %q, want fusionauth-jwt", key, got[0].SourceLibrary)
				}
				seen[key] = true
			}
		}
	}
	return seen
}

// The contracts key on the package, owning type and method the Java parser
// resolves an imported call to. This pins that agreement for the HMAC and the
// asymmetric paths end to end: signer and verifier construction, token encoding
// and decoding, and signing and verification called through the library's own
// Signer and Verifier interfaces. The negative half pins that reading a token
// without verifying it, the alg none signer, and clock skew stay uncontracted.
func TestFusionAuthJWTContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	src := `package app;

import io.fusionauth.jwt.JWTDecoder;
import io.fusionauth.jwt.JWTEncoder;
import io.fusionauth.jwt.JWTUtils;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.UnsecuredSigner;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.ec.ECSigner;
import io.fusionauth.jwt.ec.ECVerifier;
import io.fusionauth.jwt.ed.EdDSASigner;
import io.fusionauth.jwt.ed.EdDSAVerifier;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.fusionauth.jwt.rsa.RSAPSSSigner;
import io.fusionauth.jwt.rsa.RSAPSSVerifier;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;
import io.fusionauth.pem.domain.PEM;

public class App {
    public String issueHmac(JWT jwt, String secret) {
        Signer signer = HMACSigner.newSHA256Signer(secret);
        JWTEncoder encoder = JWT.getEncoder();
        return encoder.encode(jwt, signer);
    }

    public JWT readHmac(String token, String secret) {
        Verifier verifier = HMACVerifier.newVerifier(secret);
        JWTDecoder decoder = JWT.getDecoder();
        return decoder.decode(token, verifier);
    }

    public byte[] signRaw(String privatePem, String payload) {
        Signer signer = RSASigner.newSHA256Signer(privatePem, "kid-1");
        return signer.sign(payload);
    }

    public void verifyRaw(String publicPem, byte[] message, byte[] signature) {
        Verifier verifier = RSAVerifier.newVerifier(publicPem);
        verifier.verify(null, message, signature);
    }

    public void asymmetric(String privatePem, String publicPem) {
        Signer pss = RSAPSSSigner.newSHA384Signer(privatePem);
        Signer ec = ECSigner.newSHA512Signer(privatePem);
        Signer ed = EdDSASigner.newSigner(privatePem);
        Verifier pssVerifier = RSAPSSVerifier.newVerifier(publicPem);
        Verifier ecVerifier = ECVerifier.newVerifier(publicPem);
        Verifier edVerifier = EdDSAVerifier.newVerifier(publicPem);
    }

    public String keyMaterial(String pem) {
        PEM decoded = PEM.decode(pem);
        return PEM.encode(decoded.getPublicKey());
    }

    public Object unverified(String token) {
        new UnsecuredSigner();
        JWTDecoder decoder = JWT.getDecoder();
        decoder.withClockSkew(60);
        return JWTUtils.decodeHeader(token);
    }
}
`
	want := map[string]fusionAuthWant{
		"io.fusionauth.jwt.hmac.HMACSigner.newSHA256Signer":  {1, "factory"},
		"io.fusionauth.jwt.hmac.HMACVerifier.newVerifier":    {1, "factory"},
		"io.fusionauth.jwt.rsa.RSASigner.newSHA256Signer":    {2, "factory"},
		"io.fusionauth.jwt.rsa.RSAVerifier.newVerifier":      {1, "factory"},
		"io.fusionauth.jwt.rsa.RSAPSSSigner.newSHA384Signer": {1, "factory"},
		"io.fusionauth.jwt.rsa.RSAPSSVerifier.newVerifier":   {1, "factory"},
		"io.fusionauth.jwt.ec.ECSigner.newSHA512Signer":      {1, "factory"},
		"io.fusionauth.jwt.ec.ECVerifier.newVerifier":        {1, "factory"},
		"io.fusionauth.jwt.ed.EdDSASigner.newSigner":         {1, "factory"},
		"io.fusionauth.jwt.ed.EdDSAVerifier.newVerifier":     {1, "factory"},
		"io.fusionauth.jwt.domain.JWT.getEncoder":            {0, "factory"},
		"io.fusionauth.jwt.domain.JWT.getDecoder":            {0, "factory"},
		"io.fusionauth.jwt.JWTEncoder.encode":                {2, "operation"},
		"io.fusionauth.jwt.JWTDecoder.decode":                {2, "operation"},
		"io.fusionauth.jwt.Signer.sign":                      {1, "operation"},
		"io.fusionauth.jwt.Verifier.verify":                  {3, "operation"},
		"io.fusionauth.pem.domain.PEM.decode":                {1, "factory"},
		"io.fusionauth.pem.domain.PEM.getPublicKey":          {0, "output"},
		"io.fusionauth.pem.domain.PEM.encode":                {1, "output"},
	}
	none := map[string]bool{
		"io.fusionauth.jwt.UnsecuredSigner.<init>":   true,
		"io.fusionauth.jwt.JWTDecoder.withClockSkew": true,
		"io.fusionauth.jwt.JWTUtils.decodeHeader":    true,
	}

	seen := resolveFusionAuthCalls(t, src, want, none)
	for key := range want {
		if !seen[key] {
			t.Errorf("parsed calls did not cover %q", key)
		}
	}
	for key := range none {
		if !seen[key] {
			t.Errorf("parsed calls did not cover negative case %q", key)
		}
	}
}

// 2.0.0 published the same API under org.primeframework.jwt. A consumer pinned
// to it must resolve the same lifecycle as one on the renamed package.
func TestFusionAuthJWTContractsResolveThePrimeframeworkPackage(t *testing.T) {
	t.Parallel()

	src := `package app;

import org.primeframework.jwt.Signer;
import org.primeframework.jwt.Verifier;
import org.primeframework.jwt.domain.JWT;
import org.primeframework.jwt.hmac.HMACSigner;
import org.primeframework.jwt.rsa.RSAVerifier;

public class App {
    public String issue(JWT jwt, String secret) {
        Signer signer = HMACSigner.newSHA512Signer(secret);
        return JWT.getEncoder().encode(jwt, signer);
    }

    public JWT read(String token, String publicPem) {
        Verifier verifier = RSAVerifier.newVerifier(publicPem);
        return JWT.getDecoder().decode(token, verifier);
    }
}
`
	want := map[string]fusionAuthWant{
		"org.primeframework.jwt.hmac.HMACSigner.newSHA512Signer": {1, "factory"},
		"org.primeframework.jwt.rsa.RSAVerifier.newVerifier":     {1, "factory"},
		"org.primeframework.jwt.domain.JWT.getEncoder":           {0, "factory"},
		"org.primeframework.jwt.domain.JWT.getDecoder":           {0, "factory"},
	}
	seen := resolveFusionAuthCalls(t, src, want, nil)
	for key := range want {
		if !seen[key] {
			t.Errorf("parsed calls did not cover %q", key)
		}
	}
}

// The HMAC secret is the whole security of an HS256/384/512 token, so every
// factory that receives one reports its size rather than leaving it opaque, at
// each arity the library ships. The asymmetric factories take a PEM string or
// a key object whose length says nothing about the key size, so they declare no
// parameter role.
func TestFusionAuthJWTContractsReportTheHMACSecret(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
		want   string
	}{
		{"io.fusionauth.jwt.hmac.HMACSigner.newSHA256Signer", 1, "keySize"},
		{"io.fusionauth.jwt.hmac.HMACSigner.newSHA384Signer", 2, "keySize"},
		{"io.fusionauth.jwt.hmac.HMACSigner.newSHA512Signer", 3, "keySize"},
		{"io.fusionauth.jwt.hmac.HMACVerifier.newVerifier", 1, "keySize"},
		{"io.fusionauth.jwt.hmac.HMACVerifier.newVerifier", 2, "keySize"},
		{"org.primeframework.jwt.hmac.HMACSigner.newSHA256Signer", 1, "keySize"},
		{"io.fusionauth.jwt.rsa.RSASigner.newSHA256Signer", 1, ""},
		{"io.fusionauth.jwt.ec.ECVerifier.newVerifier", 1, ""},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		var property string
		for _, p := range got[0].Parameters {
			if p.Index != nil && *p.Index == 0 && p.Contributes != nil {
				property = p.Contributes.Property
			}
		}
		if property != tc.want {
			t.Errorf("%s/%d: parameter 0 contributes %q, want %q", tc.method, tc.arity, property, tc.want)
		}
	}
}
