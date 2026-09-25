package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// A consumer reaches Password4J through three shapes: the fluent hash and check
// chains, an algorithm function tuned with its own cost parameters and handed to
// with(), and a function used directly through the HashingFunction interface.
// This builds a real call graph over such a consumer and pins the lifecycle role
// every resolved library call lands on, including the 1.0 to 1.5 spelling of the
// bcrypt checker. A Hash accessor that only reads back the salt must stay
// uncontracted.
func TestPassword4jContractsResolveBuiltCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	dir := t.TempDir()
	src := `package app;

import com.password4j.Argon2Function;
import com.password4j.BcryptFunction;
import com.password4j.Hash;
import com.password4j.HashingFunction;
import com.password4j.Password;
import com.password4j.ScryptFunction;
import com.password4j.types.Argon2;
import com.password4j.types.Bcrypt;

public class App {
    public String store(String pw) {
        return Password.hash(pw).addRandomSalt().withBcrypt().getResult();
    }

    public boolean verify(String pw, String stored) {
        return Password.check(pw, stored).addPepper("pepper").withArgon2();
    }

    public boolean verifyLegacy(String pw, String stored) {
        return Password.check(pw, stored).withBCrypt();
    }

    public String tuned(String pw) {
        Argon2Function argon2 = Argon2Function.getInstance(65536, 3, 2, 32, Argon2.ID, 19);
        return Password.hash(pw).with(argon2).getResult();
    }

    public boolean tunedCheck(String pw, String stored) {
        BcryptFunction bcrypt = BcryptFunction.getInstance(Bcrypt.B, 12);
        return Password.check(pw, stored).with(bcrypt);
    }

    public Hash direct(String pw) {
        HashingFunction fn = ScryptFunction.getInstance(65536, 8, 1, 64);
        return fn.hash(pw);
    }

    public String saltOf(Hash hash) {
        return hash.getSalt();
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem("java", NewJavaParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	type call struct {
		method string
		arity  int
	}
	want := map[call]string{
		{"com.password4j.Password.hash", 1}:              "factory",
		{"com.password4j.Password.check", 2}:             "factory",
		{"com.password4j.HashBuilder.addRandomSalt", 0}:  "config",
		{"com.password4j.HashChecker.addPepper", 1}:      "config",
		{"com.password4j.HashBuilder.with", 1}:           "operation",
		{"com.password4j.HashChecker.with", 1}:           "operation",
		{"com.password4j.HashingFunction.hash", 1}:       "operation",
		{"com.password4j.Hash.getResult", 0}:             "output",
		{"com.password4j.Argon2Function.getInstance", 6}: "factory",
		{"com.password4j.BcryptFunction.getInstance", 2}: "factory",
		{"com.password4j.ScryptFunction.getInstance", 4}: "factory",
		{"com.password4j.HashBuilder.withBcrypt", 0}:     "",
		{"com.password4j.HashChecker.withArgon2", 0}:     "",
		{"com.password4j.HashChecker.withBCrypt", 0}:     "",
	}
	const saltKey = "com.password4j.Hash.getSalt"

	seen := map[call]bool{}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			callee := fn.Calls[i].Callee
			name, _ := splitMethodArity(&callee)
			got := call{name, len(fn.Calls[i].Arguments)}

			if name == saltKey {
				if cs := kb.ContractsForTolerant(name, got.arity); len(cs) != 0 {
					t.Fatalf("%s resolved to %d contract(s), want none", name, len(cs))
				}
				seen[got] = true
				continue
			}
			role, ok := want[got]
			if !ok {
				continue
			}
			cs := kb.ContractsFor(got.method, got.arity)
			if len(cs) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", got.method, got.arity, len(cs))
			}
			if cs[0].Role != role {
				t.Fatalf("%s#%d: role = %q, want %q", got.method, got.arity, cs[0].Role, role)
			}
			if cs[0].SourceLibrary != "password4j" {
				t.Fatalf("%s#%d: library = %q, want password4j", got.method, got.arity, cs[0].SourceLibrary)
			}
			seen[got] = true
		}
	}

	for c := range want {
		if !seen[c] {
			t.Errorf("built call graph did not resolve %s#%d", c.method, c.arity)
		}
	}
	if !seen[call{saltKey, 0}] {
		t.Errorf("built call graph did not resolve %s#0", saltKey)
	}
}

// The cost of a password hash is chosen where the algorithm function is built,
// so each factory has to hand the caller's values to the export rather than
// leave them opaque, and the algorithm-selecting argument has to be marked as
// the one that decides the operation.
func TestPassword4jContractsReportCostParameters(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	for _, tc := range []struct {
		method   string
		arity    int
		index    int
		role     string
		property string
	}{
		{"com.password4j.BcryptFunction.getInstance", 1, 0, "metadata-contributing", "cost"},
		{"com.password4j.BcryptFunction.getInstance", 2, 1, "metadata-contributing", "cost"},
		{"com.password4j.BCryptFunction.getInstance", 1, 0, "metadata-contributing", "cost"},
		{"com.password4j.ScryptFunction.getInstance", 3, 0, "metadata-contributing", "cost"},
		{"com.password4j.ScryptFunction.getInstance", 4, 1, "metadata-contributing", "blockSize"},
		{"com.password4j.ScryptFunction.getInstance", 4, 2, "metadata-contributing", "parallelism"},
		{"com.password4j.ScryptFunction.getInstance", 4, 3, "metadata-contributing", "outputLength"},
		{"com.password4j.SCryptFunction.getInstance", 3, 0, "metadata-contributing", "cost"},
		{"com.password4j.PBKDF2Function.getInstance", 3, 0, "operation-determining", "algorithm"},
		{"com.password4j.PBKDF2Function.getInstance", 3, 1, "metadata-contributing", "iterations"},
		{"com.password4j.PBKDF2Function.getInstance", 3, 2, "metadata-contributing", "keySize"},
		{"com.password4j.CompressedPBKDF2Function.getInstance", 3, 1, "metadata-contributing", "iterations"},
		{"com.password4j.Argon2Function.getInstance", 5, 0, "metadata-contributing", "memoryLimit"},
		{"com.password4j.Argon2Function.getInstance", 5, 1, "metadata-contributing", "iterations"},
		{"com.password4j.Argon2Function.getInstance", 5, 2, "metadata-contributing", "parallelism"},
		{"com.password4j.Argon2Function.getInstance", 5, 4, "operation-determining", "algorithm"},
		{"com.password4j.Argon2Function.getInstance", 6, 5, "metadata-contributing", "version"},
		{"com.password4j.MessageDigestFunction.getInstance", 1, 0, "operation-determining", "algorithm"},
		{"com.password4j.BalloonHashingFunction.getInstance", 4, 1, "metadata-contributing", "spaceCost"},
		{"com.password4j.BalloonHashingFunction.getInstance", 4, 2, "metadata-contributing", "timeCost"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != tc.index {
				continue
			}
			found = true
			if p.Role != tc.role || p.Contributes == nil || p.Contributes.Property != tc.property {
				t.Errorf("%s#%d parameters[%d] = %s %#v, want %s %q",
					tc.method, tc.arity, tc.index, p.Role, p.Contributes, tc.role, tc.property)
			}
		}
		if !found {
			t.Errorf("%s#%d: no parameter entry at index %d", tc.method, tc.arity, tc.index)
		}
	}
}
