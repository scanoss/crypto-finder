package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The RustCrypto hashes family carries three shapes that a KB keyed on one
// spelling silently fails to resolve: a type RENAMED inside the committed
// range (sha2's truncated pair), a crate name shared by TWO UNRELATED UPSTREAM
// PROJECTS (sha1, and sha2's 0.1 line), and the same method name appearing in
// both lineages with DIFFERENT ARITIES.
func TestLoadEmbeddedRustIncludesHashesContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		lib    string
		role   string
	}{
		// One hasher per crate, constructor and one-shot.
		{"md5::Md5.new", 0, "md-5", "factory"},
		{"md5::Md5.digest", 1, "md-5", "output"},
		{"whirlpool::Whirlpool.new", 0, "whirlpool", "factory"},
		{"sha1::Sha1.new", 0, "sha1", "factory"},
		// All four RIPEMD variants, including the one that appears at 0.1.2.
		{"ripemd::Ripemd128.new", 0, "ripemd", "factory"},
		{"ripemd::Ripemd160.new", 0, "ripemd", "factory"},
		{"ripemd::Ripemd256.new", 0, "ripemd", "factory"},
		{"ripemd::Ripemd320.new", 0, "ripemd", "factory"},
		// SHA-2, both sides of the 0.10.0 rename of the truncated pair.
		{"sha2::Sha224.new", 0, "sha2", "factory"},
		{"sha2::Sha512Trunc256.new", 0, "sha2", "factory"},
		{"sha2::Sha512_256.new", 0, "sha2", "factory"},
		{"sha2::Sha512_224.new", 0, "sha2", "factory"},
		// SHA-3, Keccak, and the XOF surface, which is not the Digest trait.
		{"sha3::Sha3_256.new", 0, "sha3", "factory"},
		{"sha3::Keccak256.new", 0, "sha3", "factory"},
		{"sha3::Keccak256Full.new", 0, "sha3", "factory"},
		{"sha3::Shake128.default", 0, "sha3", "factory"},
		{"sha3::Shake128.finalize_xof", 0, "sha3", "output"},
		{"sha3::Shake128Reader.read", 1, "sha3", "output"},
		{"sha3::CShake128Core.new", 1, "sha3", "factory"},
		{"sha3::CShake128Core.new_with_function_name", 2, "sha3", "factory"},
		{"sha3::TurboShake128Core.new", 1, "sha3", "factory"},
		// BLAKE2, both sides of the 0.10.0 concrete/generic swap.
		{"blake2::Blake2b512.new", 0, "blake2", "factory"},
		{"blake2::Blake2b.new", 0, "blake2", "factory"},
		{"blake2::Blake2b128.new", 0, "blake2", "factory"},
		{"blake2::Blake2bVar.new", 1, "blake2", "factory"},
		{"blake2::VarBlake2b.new", 1, "blake2", "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != tt.lib || got[0].Role != tt.role {
				t.Fatalf("%s#%d = %#v, want role %q from %s", tt.method, tt.arity, got[0], tt.role, tt.lib)
			}
		})
	}
}

// `sha1::Sha1.digest` exists in BOTH lineages published under that crate name:
// the pre-0.7 crate's arity-0 instance formatter, and RustCrypto's arity-1
// static one-shot. The arity is the only thing that separates them, so assert
// each resolves to its own shape and neither is answered by the other's.
func TestSha1LineagesDoNotBlurTogether(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		arity      int
		wantReturn string
	}{
		{0, "sha1::Digest"},   // pre-0.7: m.digest() formats the result
		{1, "digest::Output"}, // RustCrypto: Sha1::digest(data) hashes
	} {
		got := kb.ContractsFor("sha1::Sha1.digest", tc.arity)
		if len(got) != 1 {
			t.Fatalf("sha1::Sha1.digest#%d contracts = %d, want 1", tc.arity, len(got))
		}
		if got[0].Return.Type != tc.wantReturn {
			t.Fatalf("sha1::Sha1.digest#%d return = %q, want %q", tc.arity, got[0].Return.Type, tc.wantReturn)
		}
	}

	// The pre-0.7 one-shot constructor exists only in that lineage.
	if got := kb.ContractsFor("sha1::Sha1.from", 1); len(got) != 1 {
		t.Fatalf("sha1::Sha1.from#1 contracts = %d, want 1", len(got))
	}
}

// sha2 0.1.x vendors DaGenix's rust-crypto and re-exports it as a module, so
// the consumer path is doubled (`sha2::sha2::Sha256`) and its `result` takes
// the output buffer as an argument instead of returning the digest. Neither
// lineage may answer for the other.
func TestSha2VendoredModulePathIsSeparate(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	got := kb.ContractsFor("sha2::sha2::Sha256.new", 0)
	if len(got) != 1 || got[0].Return.Type != "sha2::sha2::Sha256" {
		t.Fatalf("sha2::sha2::Sha256.new#0 = %#v, want the vendored module path", got)
	}

	// digest's `result` returns the digest at arity 0; rust-crypto's writes
	// into an out-parameter at arity 1.
	if got := kb.ContractsFor("sha2::Sha256.result", 0); len(got) != 1 || got[0].Return.Type != "digest::Output" {
		t.Fatalf("sha2::Sha256.result#0 = %#v, want digest::Output", got)
	}
	if got := kb.ContractsFor("sha2::sha2::Sha256.result", 1); len(got) != 1 || got[0].Return.Type != "void" {
		t.Fatalf("sha2::sha2::Sha256.result#1 = %#v, want void", got)
	}
}

// The variable-output constructors take their length in BYTES, so the
// parameter must derive bits rather than report the byte count as bits.
func TestVariableOutputLengthIsDerivedFromBytes(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, method := range []string{
		"blake2::Blake2bVar.new",
		"blake2::VarBlake2s.new",
	} {
		got := kb.ContractsFor(method, 1)
		if len(got) != 1 {
			t.Fatalf("%s#1 contracts = %d, want 1", method, len(got))
		}
		params := got[0].Parameters
		if len(params) != 1 || params[0].Contributes == nil {
			t.Fatalf("%s#1 parameters = %#v, want one contributing parameter", method, params)
		}
		if params[0].Contributes.Property != "digestLength" ||
			params[0].Contributes.Derivation != string(contracts.DerivationArgumentByteLength) {
			t.Fatalf("%s#1 contributes = %#v, want digestLength from argument_byte_length",
				method, params[0].Contributes)
		}
	}
}
