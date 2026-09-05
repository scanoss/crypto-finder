package contracts_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// crypto_box ships two AEAD variants behind two type aliases — SalsaBox is
// X25519 + XSalsa20Poly1305 and ChaChaBox is X25519 + XChaCha20Poly1305 — and
// from 0.9.0 both are aliases of one generic type. A contract that merges them,
// drops one, or gets an arity wrong resolves silently and mislabels the served
// variant rather than failing, so this asserts the WHOLE loaded set against a
// literal rather than probing keys one at a time.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. Everything a consumer
// of the KB reads is rendered here: method, arity, role, return type and
// confidence, declared parameter types, the per-parameter role and contribution
// blocks, and the owning library. Corrupting any one of them fails this test.
func TestRustCryptoBoxContractsExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	got := renderCryptoBoxContracts(kb)

	want := []string{
		"crypto_box.generate_nonce#1 lib=crypto_box role=factory ret=crypto_box::Nonce/high params=- roles=-",
		"crypto_box.seal#3 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=- roles=-",
		"crypto_box.seal_open#2 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=&crypto_box::SecretKey|&[u8] roles=-",
		"crypto_box::ChaChaBox.decrypt#2 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=&crypto_box::Nonce|&[u8] roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.decrypt_in_place#3 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut dyn aead::Buffer roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.decrypt_in_place_detached#4 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut [u8]|&crypto_box::Tag roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.decrypt_inout_detached#4 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|aead::inout::InOutBuf<u8>|&crypto_box::Tag roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.encrypt#2 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=&crypto_box::Nonce|&[u8] roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.encrypt_in_place#3 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut dyn aead::Buffer roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.encrypt_in_place_detached#3 lib=crypto_box role=operation ret=Result<crypto_box::Tag, aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut [u8] roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.encrypt_inout_detached#3 lib=crypto_box role=operation ret=Result<crypto_box::Tag, aead::Error>/high params=&crypto_box::Nonce|&[u8]|aead::inout::InOutBuf<u8> roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::ChaChaBox.generate_nonce#0 lib=crypto_box role=factory ret=core::result::Result/high params=- roles=-",
		"crypto_box::ChaChaBox.generate_nonce#1 lib=crypto_box role=factory ret=crypto_box::Nonce/high params=- roles=-",
		"crypto_box::ChaChaBox.generate_nonce_with_rng#1 lib=crypto_box role=factory ret=crypto_box::Nonce/high params=- roles=-",
		"crypto_box::ChaChaBox.new#2 lib=crypto_box role=factory ret=crypto_box::ChaChaBox/high params=&crypto_box::PublicKey|&crypto_box::SecretKey roles=-",
		"crypto_box::ChaChaBox.new_from_clamped#2 lib=crypto_box role=factory ret=crypto_box::ChaChaBox/high params=&crypto_box::PublicKey|&crypto_box::SecretKey roles=-",
		"crypto_box::ChaChaBox.try_generate_nonce_with_rng#1 lib=crypto_box role=factory ret=core::result::Result/high params=- roles=-",
		"crypto_box::PublicKey.as_bytes#0 lib=crypto_box role=output ret=&[u8; 32]/high params=- roles=-",
		"crypto_box::PublicKey.from#1 lib=crypto_box role=factory ret=crypto_box::PublicKey/high params=- roles=-",
		"crypto_box::PublicKey.from_bytes#1 lib=crypto_box role=factory ret=crypto_box::PublicKey/high params=[u8; 32] roles=0:bytes:metadata-contributing:keySize:argument_bit_length",
		"crypto_box::PublicKey.from_slice#1 lib=crypto_box role=factory ret=Result<crypto_box::PublicKey, core::array::TryFromSliceError>/high params=&[u8] roles=-",
		"crypto_box::PublicKey.seal#2 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=- roles=-",
		"crypto_box::PublicKey.to_bytes#0 lib=crypto_box role=output ret=[u8; 32]/high params=- roles=-",
		"crypto_box::PublicKey.try_from#1 lib=crypto_box role=factory ret=Result<crypto_box::PublicKey, core::array::TryFromSliceError>/high params=&[u8] roles=-",
		"crypto_box::SalsaBox.decrypt#2 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=&crypto_box::Nonce|&[u8] roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.decrypt_in_place#3 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut dyn aead::Buffer roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.decrypt_in_place_detached#4 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut [u8]|&crypto_box::Tag roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.decrypt_inout_detached#4 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|aead::inout::InOutBuf<u8>|&crypto_box::Tag roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.encrypt#2 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=&crypto_box::Nonce|&[u8] roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.encrypt_in_place#3 lib=crypto_box role=operation ret=Result<(), aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut dyn aead::Buffer roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.encrypt_in_place_detached#3 lib=crypto_box role=operation ret=Result<crypto_box::Tag, aead::Error>/high params=&crypto_box::Nonce|&[u8]|&mut [u8] roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.encrypt_inout_detached#3 lib=crypto_box role=operation ret=Result<crypto_box::Tag, aead::Error>/high params=&crypto_box::Nonce|&[u8]|aead::inout::InOutBuf<u8> roles=0:nonce:metadata-contributing:nonceSize:argument_bit_length",
		"crypto_box::SalsaBox.generate_nonce#0 lib=crypto_box role=factory ret=core::result::Result/high params=- roles=-",
		"crypto_box::SalsaBox.generate_nonce#1 lib=crypto_box role=factory ret=crypto_box::Nonce/high params=- roles=-",
		"crypto_box::SalsaBox.generate_nonce_with_rng#1 lib=crypto_box role=factory ret=crypto_box::Nonce/high params=- roles=-",
		"crypto_box::SalsaBox.new#2 lib=crypto_box role=factory ret=crypto_box::SalsaBox/high params=&crypto_box::PublicKey|&crypto_box::SecretKey roles=-",
		"crypto_box::SalsaBox.new_from_clamped#2 lib=crypto_box role=factory ret=crypto_box::SalsaBox/high params=&crypto_box::PublicKey|&crypto_box::SecretKey roles=-",
		"crypto_box::SalsaBox.try_generate_nonce_with_rng#1 lib=crypto_box role=factory ret=core::result::Result/high params=- roles=-",
		"crypto_box::SecretKey.as_bytes#0 lib=crypto_box role=output ret=&[u8; 32]/high params=- roles=-",
		"crypto_box::SecretKey.from#1 lib=crypto_box role=factory ret=crypto_box::SecretKey/high params=- roles=-",
		"crypto_box::SecretKey.from_bytes#1 lib=crypto_box role=factory ret=crypto_box::SecretKey/high params=[u8; 32] roles=0:bytes:metadata-contributing:keySize:argument_bit_length",
		"crypto_box::SecretKey.from_slice#1 lib=crypto_box role=factory ret=Result<crypto_box::SecretKey, core::array::TryFromSliceError>/high params=&[u8] roles=-",
		"crypto_box::SecretKey.generate#1 lib=crypto_box role=factory ret=crypto_box::SecretKey/high params=- roles=-",
		"crypto_box::SecretKey.public_key#0 lib=crypto_box role=factory ret=crypto_box::PublicKey/high params=- roles=-",
		"crypto_box::SecretKey.to_bytes#0 lib=crypto_box role=output ret=[u8; 32]/high params=- roles=-",
		"crypto_box::SecretKey.to_scalar#0 lib=crypto_box role=output ret=curve25519_dalek::Scalar/high params=- roles=-",
		"crypto_box::SecretKey.try_from#1 lib=crypto_box role=factory ret=Result<crypto_box::SecretKey, core::array::TryFromSliceError>/high params=&[u8] roles=-",
		"crypto_box::SecretKey.unseal#1 lib=crypto_box role=operation ret=Result<Vec<u8>, aead::Error>/high params=&[u8] roles=-",
	}

	if len(got) != len(want) {
		t.Errorf("crypto_box contract count = %d, want %d", len(got), len(want))
	}
	for i := 0; i < len(got) || i < len(want); i++ {
		switch {
		case i >= len(want):
			t.Errorf("unexpected contract: %s", got[i])
		case i >= len(got):
			t.Errorf("missing contract: %s", want[i])
		case got[i] != want[i]:
			t.Errorf("contract[%d]\n got: %s\nwant: %s", i, got[i], want[i])
		}
	}
}

// The two variants must never collapse onto one another: SalsaBox and
// ChaChaBox carry the same method set at the same arities, so a copy-paste
// slip in either direction produces a KB that loads cleanly and serves the
// wrong AEAD. Asserting the returns are self-referential catches it directly.
func TestRustCryptoBoxVariantsDoNotCollapse(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct{ method, want string }{
		{"crypto_box::SalsaBox.new", "crypto_box::SalsaBox"},
		{"crypto_box::SalsaBox.new_from_clamped", "crypto_box::SalsaBox"},
		{"crypto_box::ChaChaBox.new", "crypto_box::ChaChaBox"},
		{"crypto_box::ChaChaBox.new_from_clamped", "crypto_box::ChaChaBox"},
	} {
		ctrs := kb.ContractsFor(tc.method, 2)
		if len(ctrs) != 1 {
			t.Fatalf("ContractsFor(%s, 2) returned %d contracts, want 1", tc.method, len(ctrs))
		}
		if ctrs[0].Return.Type != tc.want {
			t.Errorf("%s returns %q, want %q", tc.method, ctrs[0].Return.Type, tc.want)
		}
	}
}

// The library block is parsed and then never consulted by the resolver, so
// corrupting version_range or coordinates loads cleanly and leaves every
// contract assertion green. Read the file itself and pin them.
//
// The range starts at 0.1.0 rather than 0.0.0 because 0.0.0 is a name
// reservation: its src/lib.rs is fourteen lines of doc comment and three
// attributes, with no API at all. It stops below 0.11.0 so the 0.10.0-pre.0
// pre-release the Tier 0 matrix lists is inside it.
func TestRustCryptoBoxLibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("rust/crypto_box.yaml")
	if err != nil {
		t.Fatalf("read rust/crypto_box.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(rust/crypto_box.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatal("crypto_box.yaml declares no library block")
	}
	lib := kb.Library

	if lib.Name != "crypto_box" {
		t.Errorf("library.name = %q, want %q", lib.Name, "crypto_box")
	}
	if want := ">=0.1.0,<0.11.0"; lib.VersionRange != want {
		t.Errorf("version_range = %q, want %q -- 0.0.0 declares no API and the "+
			"upper bound must admit the 0.10.0-pre.0 row the matrix lists",
			lib.VersionRange, want)
	}
	if len(lib.Coordinates) != 1 || lib.Coordinates[0] != "crypto_box" {
		t.Errorf("coordinates = %v, want [crypto_box] -- the crate name is spelled "+
			"with an underscore on crates.io and there is no hyphenated alias",
			lib.Coordinates)
	}
	if lib.Description == "" {
		t.Error("library.description is empty")
	}
	if kb.Ecosystem != "rust" || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema_version = %q/%q, want rust/2", kb.Ecosystem, kb.SchemaVersion)
	}
}

// renderCryptoBoxContracts renders every loaded crypto_box contract as one
// deterministic line each, sorted. Everything a KB consumer reads is in the
// line, so any corruption of any field changes it.
func renderCryptoBoxContracts(kb *contracts.KnowledgeBase) []string {
	var out []string
	for key, ctrs := range kb.Contracts {
		if !strings.HasPrefix(key, "crypto_box.") && !strings.HasPrefix(key, "crypto_box::") {
			continue
		}
		for i := range ctrs {
			c := &ctrs[i]
			params := "-"
			if len(c.ParameterTypes) > 0 {
				params = strings.Join(c.ParameterTypes, "|")
			}
			roles := "-"
			if len(c.Parameters) > 0 {
				parts := make([]string, 0, len(c.Parameters))
				for _, p := range c.Parameters {
					idx := "-"
					if p.Index != nil {
						idx = fmt.Sprintf("%d", *p.Index)
					}
					contrib := "-"
					if p.Contributes != nil {
						contrib = fmt.Sprintf("%s:%s", p.Contributes.Property, p.Contributes.Derivation)
					}
					parts = append(parts, fmt.Sprintf("%s:%s:%s:%s", idx, p.Name, p.Role, contrib))
				}
				roles = strings.Join(parts, ",")
			}
			out = append(out, fmt.Sprintf(
				"%s lib=%s role=%s ret=%s/%s params=%s roles=%s",
				key, c.SourceLibrary, c.Role, c.Return.Type, c.Return.Confidence, params, roles,
			))
		}
	}
	sort.Strings(out)
	return out
}
