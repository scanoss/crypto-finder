package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The picosha2 contracts key on the shape the export path builds for C++, the
// callee's owning type joined to its name. This pins that agreement across the
// whole contracted surface: the namespace-qualified one-shot functions, the
// incremental type's constructor, and its lifecycle and output methods. It also
// pins the negative half, since the hex-formatting helpers sit in the same
// namespace and must not resolve.
func TestPicoSha2ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("cpp")
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "picosha2.h"
#include <string>
#include <vector>

std::string one_shot(const std::string& s) {
    return picosha2::hash256_hex_string(s);
}

void raw(const std::vector<unsigned char>& s, std::vector<unsigned char>& d) {
    picosha2::hash256(s.begin(), s.end(), d.begin(), d.end());
    picosha2::hash256(s, d);
}

void streaming(const std::vector<unsigned char>& data, std::vector<unsigned char>& out) {
    picosha2::hash256_one_by_one hasher;
    hasher.init();
    hasher.process(data.begin(), data.end());
    hasher.finish();
    hasher.get_hash_bytes(out.begin(), out.end());
    std::string hex = picosha2::get_hash_hex_string(hasher);
}

// Hex formatting only. Neither of these is a hashing operation.
std::string formatting(const std::vector<unsigned char>& b) {
    return picosha2::bytes_to_hex_string(b.begin(), b.end());
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct {
		arity int
		role  string
	}{
		"picosha2.hash256_hex_string":                 {1, "operation"},
		"picosha2.hash256":                            {4, "operation"},
		"picosha2.get_hash_hex_string":                {1, "output"},
		"picosha2::hash256_one_by_one.init":           {0, "config"},
		"picosha2::hash256_one_by_one.process":        {2, "operation"},
		"picosha2::hash256_one_by_one.finish":         {0, "operation"},
		"picosha2::hash256_one_by_one.get_hash_bytes": {2, "output"},
	}
	// Same namespace, deliberately uncontracted.
	negative := []string{"picosha2.bytes_to_hex_string"}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				if call.Callee.Type == "" {
					continue
				}
				// The key the export path builds for a C++ callee.
				key := call.Callee.Type + "." + BaseFunctionName(call.Callee.Name)

				for _, n := range negative {
					if key == n {
						if got := kb.ContractsForTolerant(key, len(call.Arguments)); len(got) != 0 {
							t.Fatalf("%q resolved to %d contract(s), want none", key, len(got))
						}
					}
				}

				expect, ok := want[key]
				if !ok {
					continue
				}
				if len(call.Arguments) != expect.arity {
					continue // another overload of the same name
				}
				got := kb.ContractsForTolerant(key, expect.arity)
				if len(got) != 1 {
					t.Fatalf("ContractsForTolerant(%q, %d) = %d, want exactly one",
						key, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", key, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "picosha2" {
					t.Fatalf("%s: library = %q, want picosha2", key, got[0].SourceLibrary)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", key, keys(seen))
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// hash256's iterator overload declares a fifth buffer_size parameter with a
// default, and three further overloads share arity 3, so a consumer reaches the
// same function at four different call-site arities. Every one of them has to
// resolve, or a consumer that omits the buffer size loses its finding.
func TestPicoSha2HashArityCoverage(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("cpp")
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}
	for _, arity := range []int{2, 3, 4, 5} {
		got := kb.ContractsForTolerant("picosha2.hash256", arity)
		if len(got) != 1 {
			t.Errorf("picosha2.hash256 arity %d: %d contracts, want exactly one", arity, len(got))
			continue
		}
		if got[0].Role != "operation" {
			t.Errorf("picosha2.hash256 arity %d: role = %q, want operation", arity, got[0].Role)
		}
	}
	for _, arity := range []int{1, 2, 3} {
		if got := kb.ContractsForTolerant("picosha2.hash256_hex_string", arity); len(got) != 1 {
			t.Errorf("picosha2.hash256_hex_string arity %d: %d contracts, want exactly one", arity, len(got))
		}
	}
}
