// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// rusoto_kms re-exports every type from the crate ROOT (`pub use generated::*`
// in lib.rs), so the graph emits `rusoto_kms.KmsClient.encrypt` with no module
// segment and the KB file authors `rusoto_kms::KmsClient.encrypt` —
// rustAuthoredKey moves the second-to-last dot when the file loads. Authoring
// the emitted form instead produces a KB that loads without error and joins
// nothing, which is indistinguishable from having no contract.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot
// see an entry that should not be there, an entry that was dropped, or a field
// that was corrupted; only the whole-set comparison does. Seven targeted
// mutations were run against it before the family shipped — entry deletion, a
// role flip, an arity change, a corrupted return type, corrupted
// parameter_types, a downgraded confidence and a renamed method — and each one
// failed this test.
func renderRusotoKmsContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "rusoto_kms" {
				continue
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence))
		}
	}
	sort.Strings(got)
	return got
}

// The whole surface, named as literals. Fifteen entries: five constructors —
// `new` at BOTH arities, because 0.25.0-0.32.0 takes (dispatcher, credentials,
// region) and 0.33.0 onward takes (region) — and the ten cryptographic
// operations, each taking exactly one request struct in every published era.
var wantRusotoKmsContracts = []string{
	"rusoto_kms::KmsClient.new#1/factory/rusoto_kms::KmsClient//[rusoto_core::region::Region]/high",
	"rusoto_kms::KmsClient.new#3/factory/rusoto_kms::KmsClient//[rusoto_core::request::DispatchSignedRequest,rusoto_core::credential::ProvideAwsCredentials,rusoto_core::region::Region]/high",
	"rusoto_kms::KmsClient.new_with#3/factory/rusoto_kms::KmsClient//[rusoto_core::request::DispatchSignedRequest,rusoto_core::credential::ProvideAwsCredentials,rusoto_core::region::Region]/high",
	"rusoto_kms::KmsClient.new_with_client#2/factory/rusoto_kms::KmsClient//[rusoto_core::Client,rusoto_core::region::Region]/high",
	"rusoto_kms::KmsClient.simple#1/factory/rusoto_kms::KmsClient//[rusoto_core::region::Region]/high",
	"rusoto_kms::KmsClient.encrypt#1/operation/core::result::Result/core::result::Result<rusoto_kms::EncryptResponse, rusoto_core::RusotoError<rusoto_kms::EncryptError>>/[rusoto_kms::EncryptRequest]/high",
	"rusoto_kms::KmsClient.decrypt#1/operation/core::result::Result/core::result::Result<rusoto_kms::DecryptResponse, rusoto_core::RusotoError<rusoto_kms::DecryptError>>/[rusoto_kms::DecryptRequest]/high",
	"rusoto_kms::KmsClient.re_encrypt#1/operation/core::result::Result/core::result::Result<rusoto_kms::ReEncryptResponse, rusoto_core::RusotoError<rusoto_kms::ReEncryptError>>/[rusoto_kms::ReEncryptRequest]/high",
	"rusoto_kms::KmsClient.generate_data_key#1/factory/core::result::Result/core::result::Result<rusoto_kms::GenerateDataKeyResponse, rusoto_core::RusotoError<rusoto_kms::GenerateDataKeyError>>/[rusoto_kms::GenerateDataKeyRequest]/high",
	"rusoto_kms::KmsClient.generate_data_key_without_plaintext#1/factory/core::result::Result/core::result::Result<rusoto_kms::GenerateDataKeyWithoutPlaintextResponse, rusoto_core::RusotoError<rusoto_kms::GenerateDataKeyWithoutPlaintextError>>/[rusoto_kms::GenerateDataKeyWithoutPlaintextRequest]/high",
	"rusoto_kms::KmsClient.generate_data_key_pair#1/factory/core::result::Result/core::result::Result<rusoto_kms::GenerateDataKeyPairResponse, rusoto_core::RusotoError<rusoto_kms::GenerateDataKeyPairError>>/[rusoto_kms::GenerateDataKeyPairRequest]/high",
	"rusoto_kms::KmsClient.generate_data_key_pair_without_plaintext#1/factory/core::result::Result/core::result::Result<rusoto_kms::GenerateDataKeyPairWithoutPlaintextResponse, rusoto_core::RusotoError<rusoto_kms::GenerateDataKeyPairWithoutPlaintextError>>/[rusoto_kms::GenerateDataKeyPairWithoutPlaintextRequest]/high",
	"rusoto_kms::KmsClient.sign#1/operation/core::result::Result/core::result::Result<rusoto_kms::SignResponse, rusoto_core::RusotoError<rusoto_kms::SignError>>/[rusoto_kms::SignRequest]/high",
	"rusoto_kms::KmsClient.verify#1/operation/core::result::Result/core::result::Result<rusoto_kms::VerifyResponse, rusoto_core::RusotoError<rusoto_kms::VerifyError>>/[rusoto_kms::VerifyRequest]/high",
	"rusoto_kms::KmsClient.generate_random#1/operation/core::result::Result/core::result::Result<rusoto_kms::GenerateRandomResponse, rusoto_core::RusotoError<rusoto_kms::GenerateRandomError>>/[rusoto_kms::GenerateRandomRequest]/high",
}

func TestLoadEmbeddedRustRusotoKmsContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderRusotoKmsContracts(t)
	want := append([]string(nil), wantRusotoKmsContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("rusoto_kms contracts: got %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("unexpected rusoto_kms contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing rusoto_kms contract:    %s", w)
		}
	}
}

// THE LIBRARY BLOCK IS ASSERTED SEPARATELY, because the per-entry render above
// cannot see it: a Contract carries only the library NAME. Measured in a
// scratch copy — corrupting `version_range`, `coordinates` or `description`
// left the exact-set comparison green, so the range claim rested on nothing.
// The file is loaded on its own here (LoadEmbedded merges every rust library
// and drops the per-file block) and the three fields are pinned by literal.
func TestRusotoKmsLibraryMetadataIsPinned(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("rust", "rusoto_kms.yaml"))
	if err != nil {
		t.Fatalf("reading the contract file: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(rust/rusoto_kms.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatal("the file declares no library block")
	}
	if kb.Library.Name != "rusoto_kms" {
		t.Errorf("library.name = %q, want rusoto_kms", kb.Library.Name)
	}
	// 0.25.0 is the oldest published row and 0.48.0 the newest; the range may
	// not be widened without re-reading the signatures at the new ends.
	if kb.Library.VersionRange != ">=0.25.0,<0.49.0" {
		t.Errorf("library.version_range = %q, want >=0.25.0,<0.49.0", kb.Library.VersionRange)
	}
	if len(kb.Library.Coordinates) != 1 || kb.Library.Coordinates[0] != "rusoto_kms" {
		t.Errorf("library.coordinates = %v, want [rusoto_kms]", kb.Library.Coordinates)
	}
	if !strings.Contains(kb.Library.Description, "rusoto") ||
		!strings.Contains(kb.Library.Description, "Key Management Service") {
		t.Errorf("library.description = %q, want it to name rusoto and AWS Key Management Service",
			kb.Library.Description)
	}
}

// `new` is the one constructor whose arity genuinely differs across the
// published window, and the method+arity index is what keeps the two apart.
// Neither may swallow the other: 0.25.0 generated.rs:3668 takes three
// arguments on the generic client, 0.33.0 generated.rs:4913 takes one.
func TestRusotoKmsNewIsKeyedAtBothArities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	one := kb.ContractsFor("rusoto_kms::KmsClient.new", 1)
	three := kb.ContractsFor("rusoto_kms::KmsClient.new", 3)
	if len(one) != 1 || len(three) != 1 {
		t.Fatalf("rusoto_kms::KmsClient.new: arity 1 -> %d contracts, arity 3 -> %d, want 1 and 1", len(one), len(three))
	}
	if one[0].ParameterTypes[0] != "rusoto_core::region::Region" {
		t.Errorf("arity 1 first parameter = %q, want rusoto_core::region::Region", one[0].ParameterTypes[0])
	}
	if three[0].ParameterTypes[0] != "rusoto_core::request::DispatchSignedRequest" {
		t.Errorf("arity 3 first parameter = %q, want the dispatcher (0.25.0-0.32.0 order)", three[0].ParameterTypes[0])
	}
}
