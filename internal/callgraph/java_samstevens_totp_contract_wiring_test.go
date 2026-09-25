package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

type parsedTotpCall struct {
	key   string
	arity int
}

func parseTotpCalls(t *testing.T, src string) []parsedTotpCall {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	var out []parsedTotpCall
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				call := &fn.Calls[j]
				callee := call.Callee
				name, _ := splitMethodArity(&callee)
				if callee.Package == "" || callee.Type == "" {
					continue
				}
				out = append(out, parsedTotpCall{key: name, arity: len(call.Arguments)})
			}
		}
	}
	return out
}

// The contracts key on the package, owning type and method the Java parser
// resolves an imported call to. Receivers are typed through the library's
// interfaces, as its own documentation writes them, so generation and
// verification must resolve on CodeGenerator and CodeVerifier.
func TestSamstevensTotpContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseTotpCalls(t, `package app;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.NtpTimeProvider;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

public class App {
    public String issueSecret() {
        SecretGenerator secrets = new DefaultSecretGenerator(64);
        return secrets.generate();
    }

    public String code(String secret) throws Exception {
        CodeGenerator generator = new DefaultCodeGenerator(HashingAlgorithm.SHA256, 8);
        return generator.generate(secret, 1L);
    }

    public boolean verify(String secret, String code) throws Exception {
        TimeProvider time = new NtpTimeProvider("pool.ntp.org", 5000);
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(new DefaultCodeGenerator(), time);
        verifier.setTimePeriod(60);
        verifier.setAllowedTimePeriodDiscrepancy(2);
        CodeVerifier checked = verifier;
        return checked.isValidCode(secret, code);
    }

    public TimeProvider clock() {
        return new SystemTimeProvider();
    }

    public String[] recovery() {
        RecoveryCodeGenerator recovery = new RecoveryCodeGenerator();
        return recovery.generateCodes(10);
    }

    public String provision(QrData data) {
        QrDataFactory factory = new QrDataFactory(HashingAlgorithm.SHA1, 6, 30);
        factory.newBuilder();
        return data.getUri() + data.getSecret();
    }
}
`)

	want := map[parsedTotpCall]string{
		{"dev.samstevens.totp.secret.DefaultSecretGenerator.<init>", 1}:                     "factory",
		{"dev.samstevens.totp.secret.SecretGenerator.generate", 0}:                          "factory",
		{"dev.samstevens.totp.code.DefaultCodeGenerator.<init>", 2}:                         "factory",
		{"dev.samstevens.totp.code.DefaultCodeGenerator.<init>", 0}:                         "factory",
		{"dev.samstevens.totp.code.CodeGenerator.generate", 2}:                              "operation",
		{"dev.samstevens.totp.code.DefaultCodeVerifier.<init>", 2}:                          "factory",
		{"dev.samstevens.totp.code.DefaultCodeVerifier.setTimePeriod", 1}:                   "config",
		{"dev.samstevens.totp.code.DefaultCodeVerifier.setAllowedTimePeriodDiscrepancy", 1}: "config",
		{"dev.samstevens.totp.code.CodeVerifier.isValidCode", 2}:                            "operation",
		{"dev.samstevens.totp.time.NtpTimeProvider.<init>", 2}:                              "config",
		{"dev.samstevens.totp.time.SystemTimeProvider.<init>", 0}:                           "config",
		{"dev.samstevens.totp.recovery.RecoveryCodeGenerator.<init>", 0}:                    "factory",
		{"dev.samstevens.totp.recovery.RecoveryCodeGenerator.generateCodes", 1}:             "factory",
		{"dev.samstevens.totp.qr.QrDataFactory.<init>", 3}:                                  "factory",
		{"dev.samstevens.totp.qr.QrDataFactory.newBuilder", 0}:                              "factory",
		{"dev.samstevens.totp.qr.QrData.getUri", 0}:                                         "output",
		{"dev.samstevens.totp.qr.QrData.getSecret", 0}:                                      "output",
	}

	seen := map[parsedTotpCall]bool{}
	for _, call := range calls {
		role, ok := want[call]
		if !ok {
			continue
		}
		got := kb.ContractsForTolerant(call.key, call.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsForTolerant(%q, %d) = %d, want exactly one", call.key, call.arity, len(got))
		}
		if got[0].Role != role {
			t.Errorf("%s/%d: role = %q, want %q", call.key, call.arity, got[0].Role, role)
		}
		if got[0].SourceLibrary != "samstevens-totp" {
			t.Errorf("%s/%d: library = %q, want samstevens-totp", call.key, call.arity, got[0].SourceLibrary)
		}
		seen[call] = true
	}
	for call := range want {
		if !seen[call] {
			t.Errorf("parsed calls did not cover %s/%d", call.key, call.arity)
		}
	}
}

// A caller that only touches the library's utilities (the clock read, display
// text, algorithm names, PNG rendering and Base64 image embedding) must resolve
// to no contract at all, so it contributes nothing crypto to the graph.
func TestSamstevensTotpUtilityCallerResolvesNoContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseTotpCalls(t, `package app;

import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;

public class Screen {
    public String render(QrData data, QrGenerator generator, TimeProvider time, HashingAlgorithm algorithm) throws Exception {
        long now = time.getTime();
        String caption = data.getLabel() + data.getIssuer() + algorithm.getFriendlyName() + now;
        byte[] png = generator.generate(data);
        return caption + Utils.getDataUriForImage(png, generator.getImageMimeType());
    }
}
`)

	utilities := map[parsedTotpCall]bool{
		{"dev.samstevens.totp.time.TimeProvider.getTime", 0}:             false,
		{"dev.samstevens.totp.qr.QrData.getLabel", 0}:                    false,
		{"dev.samstevens.totp.qr.QrData.getIssuer", 0}:                   false,
		{"dev.samstevens.totp.code.HashingAlgorithm.getFriendlyName", 0}: false,
		{"dev.samstevens.totp.qr.QrGenerator.generate", 1}:               false,
		{"dev.samstevens.totp.qr.QrGenerator.getImageMimeType", 0}:       false,
		{"dev.samstevens.totp.util.Utils.getDataUriForImage", 2}:         false,
	}
	for _, call := range calls {
		if got := kb.ContractsForTolerant(call.key, call.arity); len(got) != 0 {
			t.Errorf("%s/%d resolved to %d contract(s) from %q, want none",
				call.key, call.arity, len(got), got[0].SourceLibrary)
		}
		if _, ok := utilities[call]; ok {
			utilities[call] = true
		}
	}
	for call, parsed := range utilities {
		if !parsed {
			t.Errorf("parsed calls did not cover %s/%d, so its absence proves nothing", call.key, call.arity)
		}
	}
}

// The HMAC algorithm is chosen where the generator or provisioning factory is
// built, and the shared secret is the whole security of the scheme, so each
// must reach the export as a parameter role rather than stay opaque.
func TestSamstevensTotpContractsReportAlgorithmAndSecret(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	cases := []struct {
		method   string
		arity    int
		index    int
		role     string
		property string
	}{
		{"dev.samstevens.totp.code.DefaultCodeGenerator.<init>", 1, 0, "operation-determining", "algorithm"},
		{"dev.samstevens.totp.code.DefaultCodeGenerator.<init>", 2, 0, "operation-determining", "algorithm"},
		{"dev.samstevens.totp.code.DefaultCodeGenerator.<init>", 2, 1, "metadata-contributing", "outputLength"},
		{"dev.samstevens.totp.qr.QrDataFactory.<init>", 3, 0, "operation-determining", "algorithm"},
		{"dev.samstevens.totp.qr.QrData.Builder.algorithm", 1, 0, "operation-determining", "algorithm"},
		{"dev.samstevens.totp.code.CodeGenerator.generate", 2, 0, "metadata-contributing", "secret"},
		{"dev.samstevens.totp.code.CodeVerifier.isValidCode", 2, 0, "metadata-contributing", "secret"},
		{"dev.samstevens.totp.secret.DefaultSecretGenerator.<init>", 1, 0, "metadata-contributing", "outputLength"},
	}
	for _, tc := range cases {
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsForTolerant(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
		}
		found := false
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != tc.index {
				continue
			}
			found = true
			if p.Role != tc.role || p.Contributes == nil || p.Contributes.Property != tc.property {
				t.Errorf("%s/%d parameters[%d] = %s %+v, want %s %q",
					tc.method, tc.arity, tc.index, p.Role, p.Contributes, tc.role, tc.property)
			}
		}
		if !found {
			t.Errorf("%s/%d: no parameter entry at index %d", tc.method, tc.arity, tc.index)
		}
	}
}
