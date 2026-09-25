package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// resolveJjwtCalls builds a call graph from one Java source, which runs the
// contract-driven fluent-chain pass the parser alone does not, and looks every
// call with a resolved owning type up in the embedded Java KB.
func resolveJjwtCalls(t *testing.T, src string) map[string][]contracts.Contract {
	t.Helper()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem("java", NewJavaParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	resolved := map[string][]contracts.Contract{}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			callee := call.Callee
			name, _ := splitMethodArity(&callee)
			if callee.Package == "" || callee.Type == "" {
				continue
			}
			key := name + "#" + strconv.Itoa(len(call.Arguments))
			resolved[key] = append(resolved[key], kb.ContractsFor(name, len(call.Arguments))...)
		}
	}
	return resolved
}

// JJWT's three API eras, written the way a consumer writes them, parsed through
// the real Java parser. Each fluent link must keep its receiver type, so the
// crypto call at the end of the chain resolves to the era file that owns it.
func TestJjwtContractsResolveBuiltCalls(t *testing.T) {
	t.Parallel()

	resolved := resolveJjwtCalls(t, `package app;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.KeyBuilderSupplier;
import io.jsonwebtoken.security.KeyPairBuilderSupplier;
import java.security.KeyPair;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

public class App {
    public String legacySign(byte[] secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret);
        SecretKey generated = Keys.secretKeyFor(SignatureAlgorithm.HS512);
        KeyPair pair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        return Jwts.builder().setSubject("alice").claim("role", "admin").signWith(key, SignatureAlgorithm.HS256).compact();
    }

    public Object legacyVerify(JwtParser parser, byte[] secret, String token) {
        return parser.setSigningKey(secret).parseClaimsJws(token);
    }

    public Object builderVerify(SecretKey key, String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }

    public String modern(SecretKey kek, PrivateKey signer, KeyBuilderSupplier mac, KeyPairBuilderSupplier sig) {
        SecretKey macKey = mac.key().build();
        KeyPair pair = sig.keyPair().build();
        String jws = Jwts.builder().subject("bob").signWith(signer).compact();
        return Jwts.builder().issuer("me").encryptWith(kek, Jwts.KEY.A256KW, Jwts.ENC.A256GCM).compact();
    }

    public Object modernVerify(SecretKey key, String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }
}
`)

	assertCodecResolution(t, resolved, map[string]codecWant{
		"io.jsonwebtoken.Jwts.builder#0":                            {"factory", "jjwt"},
		"io.jsonwebtoken.JwtBuilder.setSubject#1":                   {"", "jjwt"},
		"io.jsonwebtoken.JwtBuilder.claim#2":                        {"", "jjwt"},
		"io.jsonwebtoken.JwtBuilder.signWith#2":                     {"config", "jjwt"},
		"io.jsonwebtoken.JwtBuilder.signWith#1":                     {"config", "jjwt"},
		"io.jsonwebtoken.JwtBuilder.compact#0":                      {"operation", "jjwt"},
		"io.jsonwebtoken.security.Keys.hmacShaKeyFor#1":             {"factory", "jjwt"},
		"io.jsonwebtoken.security.Keys.secretKeyFor#1":              {"factory", "jjwt"},
		"io.jsonwebtoken.security.Keys.keyPairFor#1":                {"factory", "jjwt"},
		"io.jsonwebtoken.JwtParser.setSigningKey#1":                 {"config", "jjwt-0.10"},
		"io.jsonwebtoken.JwtParser.parseClaimsJws#1":                {"operation", "jjwt"},
		"io.jsonwebtoken.Jwts.parserBuilder#0":                      {"factory", "jjwt-0.11.0"},
		"io.jsonwebtoken.JwtParserBuilder.setSigningKey#1":          {"config", "jjwt-0.11"},
		"io.jsonwebtoken.JwtParserBuilder.build#0":                  {"factory", "jjwt-0.11"},
		"io.jsonwebtoken.security.KeyBuilderSupplier.key#0":         {"factory", "jjwt-0.12"},
		"io.jsonwebtoken.security.KeyBuilder.build#0":               {"factory", "jjwt-0.12"},
		"io.jsonwebtoken.security.KeyPairBuilderSupplier.keyPair#0": {"factory", "jjwt-0.12"},
		"io.jsonwebtoken.security.KeyPairBuilder.build#0":           {"factory", "jjwt-0.12"},
		"io.jsonwebtoken.JwtBuilder.subject#1":                      {"", "jjwt-0.12"},
		"io.jsonwebtoken.JwtBuilder.issuer#1":                       {"", "jjwt-0.12"},
		"io.jsonwebtoken.JwtBuilder.encryptWith#3":                  {"config", "jjwt-0.12"},
		"io.jsonwebtoken.Jwts.parser#0":                             {"factory", "jjwt-0.12"},
		"io.jsonwebtoken.JwtParserBuilder.verifyWith#1":             {"config", "jjwt-0.12"},
		"io.jsonwebtoken.JwtParser.parseSignedClaims#1":             {"operation", "jjwt-0.12"},
	})
}

// Types that only share JJWT's simple names are not JJWT.
func TestJjwtContractsIgnoreForeignLookalikes(t *testing.T) {
	t.Parallel()

	resolved := resolveJjwtCalls(t, `package app;

import com.example.jwt.JwtBuilder;
import com.example.security.Keys;

public class App {
    public String build(JwtBuilder builder, byte[] secret) {
        Keys.hmacShaKeyFor(secret);
        return builder.signWith(secret).compact();
    }
}
`)

	if len(resolved) == 0 {
		t.Fatal("the parser resolved no calls")
	}
	for key, got := range resolved {
		for i := range got {
			if strings.HasPrefix(got[i].SourceLibrary, "jjwt") {
				t.Errorf("%s resolved to JJWT contract %s (%s)", key, got[i].Method, got[i].SourceLibrary)
			}
		}
	}
}
