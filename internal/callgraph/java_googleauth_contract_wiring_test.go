package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// parseJavaCallArities parses one Java source and returns every resolved
// callee name with the argument counts it was called with.
func parseJavaCallArities(t *testing.T, src string) map[string][]int {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string][]int{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				call := &analysis.Functions[i].Calls[j]
				callee := call.Callee
				name, _ := splitMethodArity(&callee)
				calls[name] = append(calls[name], len(call.Arguments))
			}
		}
	}
	return calls
}

// The GoogleAuth contracts key on the identity the Java parser gives each call,
// across the whole lifecycle one enrollment and one login walk through:
// configuration, secret generation, code calculation, authorization and
// provisioning. The configuration builder is written the way the library
// documents it, through its outer class, and the authenticator is reached both
// as the concrete class and as its interface.
func TestGoogleAuthContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseJavaCallArities(t, `package app;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.warrenstrange.googleauth.HmacHashFunction;
import com.warrenstrange.googleauth.IGoogleAuthenticator;

public class App {
    public String enroll() {
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
            .setHmacHashFunction(HmacHashFunction.HmacSHA256)
            .setSecretBits(160)
            .build();
        GoogleAuthenticator gAuth = new GoogleAuthenticator(config);
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();
        int code = gAuth.getTotpPassword(secret);
        gAuth.authorize(secret, code);
        return GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL("acme", "alice", key);
    }

    public boolean login(IGoogleAuthenticator auth, String user, int code) {
        return auth.authorizeUser(user, code);
    }

    public int restore(String stored) {
        GoogleAuthenticatorKey key = new GoogleAuthenticatorKey.Builder(stored).build();
        return new GoogleAuthenticator().getTotpPassword(key.getKey());
    }
}
`)

	const pkg = "com.warrenstrange.googleauth."
	for _, tc := range []struct {
		method string
		arity  int
		role   string
	}{
		{pkg + "GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder.<init>", 0, "factory"},
		{pkg + "GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder.setHmacHashFunction", 1, "config"},
		{pkg + "GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder.setSecretBits", 1, "config"},
		{pkg + "GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder.build", 0, "factory"},
		{pkg + "GoogleAuthenticator.<init>", 0, "factory"},
		{pkg + "GoogleAuthenticator.<init>", 1, "factory"},
		{pkg + "GoogleAuthenticator.createCredentials", 0, "factory"},
		{pkg + "GoogleAuthenticator.getTotpPassword", 1, "operation"},
		{pkg + "GoogleAuthenticator.authorize", 2, "operation"},
		{pkg + "IGoogleAuthenticator.authorizeUser", 2, "operation"},
		{pkg + "GoogleAuthenticatorKey.getKey", 0, "output"},
		{pkg + "GoogleAuthenticatorKey.Builder.<init>", 1, "factory"},
		{pkg + "GoogleAuthenticatorKey.Builder.build", 0, "factory"},
		{pkg + "GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL", 3, "output"},
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
		if got[0].SourceLibrary != "googleauth" {
			t.Errorf("%s/%d: library = %q, want googleauth", tc.method, tc.arity, got[0].SourceLibrary)
		}
	}
}

// Calls that only share a name or a package with the library resolve to
// nothing: the credential repository accessor, which wires storage rather than
// performing cryptography, and an unrelated authorize with the same arity as
// the TOTP one.
func TestGoogleAuthContractsIgnoreNonCryptoCallers(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseJavaCallArities(t, `package app;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.security.authorization.AuthorizationManager;

public class App {
    public Object repository(GoogleAuthenticator gAuth) {
        return gAuth.getCredentialRepository();
    }

    public Object check(AuthorizationManager<Object> manager, Object authentication, Object target) {
        return manager.authorize(authentication, target);
    }
}
`)

	for _, method := range []string{
		"com.warrenstrange.googleauth.GoogleAuthenticator.getCredentialRepository",
		"org.springframework.security.authorization.AuthorizationManager.authorize",
	} {
		arities := calls[method]
		if len(arities) == 0 {
			t.Fatalf("no parsed call to %s; the fixture no longer exercises it", method)
		}
		for _, arity := range arities {
			if got := kb.ContractsForTolerant(method, arity); len(got) != 0 {
				t.Errorf("%s/%d resolved to %d contract(s), want none", method, arity, len(got))
			}
		}
	}
}

// The secret is the whole security of a TOTP scheme, so every entry point that
// receives one reports it, and the configuration names the hash that selects
// the MAC and the secret size that is its key size.
func TestGoogleAuthContractsReportSecretAlgorithmAndKeySize(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const pkg = "com.warrenstrange.googleauth."
	for _, tc := range []struct {
		method   string
		arity    int
		index    int
		property string
	}{
		{pkg + "GoogleAuthenticator.getTotpPassword", 1, 0, "secret"},
		{pkg + "GoogleAuthenticator.getTotpPassword", 2, 0, "secret"},
		{pkg + "GoogleAuthenticator.authorize", 2, 0, "secret"},
		{pkg + "GoogleAuthenticator.authorize", 3, 0, "secret"},
		{pkg + "IGoogleAuthenticator.getTotpPassword", 1, 0, "secret"},
		{pkg + "IGoogleAuthenticator.authorize", 2, 0, "secret"},
		{pkg + "GoogleAuthenticatorKey.Builder.<init>", 1, 0, "secret"},
		{pkg + "GoogleAuthenticatorKey.getQRBarcodeURL", 3, 2, "secret"},
		{pkg + "GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder.setHmacHashFunction", 1, 0, "algorithm"},
		{pkg + "GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder.setSecretBits", 1, 0, "keySize"},
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
				t.Errorf("%s/%d: parameters[%d] contributes %#v, want property %q",
					tc.method, tc.arity, tc.index, p.Contributes, tc.property)
			}
		}
		if !found {
			t.Errorf("%s/%d: no parameter entry at index %d", tc.method, tc.arity, tc.index)
		}
	}
}

// A nested type written through its imported outer type resolves to the outer
// type's package, the identity a direct import of the nested type gives. A
// qualified name whose first segment is not imported keeps its written package.
func TestJavaNestedTypeResolvesThroughImportedOuterType(t *testing.T) {
	t.Parallel()

	calls := parseJavaCallArities(t, `package app;

import java.util.Map;

public class App {
    public Object entries() {
        Map.Entry<String, String> entry = Map.entry("a", "b");
        entry.getKey();
        return Map.Entry.comparingByKey();
    }

    public Object qualified() {
        return new java.util.AbstractMap.SimpleEntry("a", "b");
    }
}
`)

	for _, method := range []string{
		"java.util.Map.Entry.comparingByKey",
		"java.util.Map.Entry.getKey",
		"java.util.AbstractMap.SimpleEntry.<init>",
	} {
		if len(calls[method]) == 0 {
			t.Errorf("no parsed call to %s; parsed %v", method, keysOf(calls))
		}
	}
}
