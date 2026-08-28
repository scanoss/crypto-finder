package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The AeroGear OTP contracts key on the package, owning type and method the Java
// parser resolves an imported call to. This pins that agreement across the whole
// contracted surface: secret generation, both Totp constructors, the time step,
// and generation and verification. It also pins the negative half, since the
// base32 codec sits beside the secret generator in the same class and must not
// resolve.
func TestAeroGearOtpContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	dir := t.TempDir()
	src := `package app;

import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;
import org.jboss.aerogear.security.otp.api.Clock;

public class App {
    public String issue() {
        String secret = Base32.random();
        Totp totp = new Totp(secret);
        return totp.now();
    }

    public boolean check(String secret, String code) {
        Totp totp = new Totp(secret, new Clock(30));
        return totp.verify(code);
    }

    public String provision(String secret, String name) {
        return new Totp(secret).uri(name);
    }

    // A generic base32 codec call. Encoding is not key material handling and
    // must resolve to nothing.
    public String encodeOnly(byte[] raw) {
        return Base32.encode(raw);
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct {
		arity int
		role  string
	}{
		"org.jboss.aerogear.security.otp.api.Base32.random": {0, "factory"},
		"org.jboss.aerogear.security.otp.Totp.<init>":       {1, "factory"},
		"org.jboss.aerogear.security.otp.Totp.now":          {0, "operation"},
		"org.jboss.aerogear.security.otp.Totp.verify":       {1, "operation"},
		"org.jboss.aerogear.security.otp.Totp.uri":          {1, "output"},
		"org.jboss.aerogear.security.otp.api.Clock.<init>":  {1, "config"},
	}
	const encodeKey = "org.jboss.aerogear.security.otp.api.Base32.encode"

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				name, _ := splitMethodArity(&callee)
				if callee.Package == "" || callee.Type == "" {
					continue
				}
				// splitMethodArity already yields the fully-qualified name with the
				// encoded arity removed, which is the shape the KB is keyed on.
				key := name

				if key == encodeKey {
					if got := kb.ContractsForTolerant(key, len(call.Arguments)); len(got) != 0 {
						t.Fatalf("%q resolved to %d contract(s), want none", key, len(got))
					}
					continue
				}

				expect, ok := want[key]
				if !ok || len(call.Arguments) != expect.arity {
					continue
				}
				got := kb.ContractsForTolerant(key, expect.arity)
				if len(got) != 1 {
					t.Fatalf("ContractsForTolerant(%q, %d) = %d, want exactly one",
						key, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", key, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "aerogear-otp-java" {
					t.Fatalf("%s: library = %q, want aerogear-otp-java", key, got[0].SourceLibrary)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
}

// The secret is the whole security of a TOTP scheme, so every constructor that
// receives one has to report it rather than leaving it opaque, and the MAC
// constructor has to name the hash that selects the algorithm.
func TestAeroGearOtpContractsReportSecretAndAlgorithm(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	for _, tc := range []struct {
		method   string
		arity    int
		index    int
		property string
	}{
		{"org.jboss.aerogear.security.otp.Totp.<init>", 1, 0, "secret"},
		{"org.jboss.aerogear.security.otp.Totp.<init>", 2, 0, "secret"},
		{"org.jboss.aerogear.security.otp.api.Hmac.<init>", 3, 0, "algorithm"},
		{"org.jboss.aerogear.security.otp.api.Hmac.<init>", 3, 1, "keySize"},
	} {
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsForTolerant(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != tc.index {
				continue
			}
			found = true
			if p.Contributes == nil || p.Contributes.Property != tc.property {
				t.Errorf("%s arity %d: parameters[%d] contributes %#v, want property %q",
					tc.method, tc.arity, tc.index, p.Contributes, tc.property)
			}
		}
		if !found {
			t.Errorf("%s arity %d: no parameter entry at index %d", tc.method, tc.arity, tc.index)
		}
	}
}
