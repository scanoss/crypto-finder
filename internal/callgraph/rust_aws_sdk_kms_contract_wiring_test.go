// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The aws-sdk-kms KB is keyed on what the Rust parser emits, and this SDK makes
// that non-uniform in a way a contract can get wrong silently.
//
// `Client` IS re-exported from the crate root (`pub use client::Client` in every
// version of the range), so its key carries NO module segment:
// `aws_sdk_kms.Client.encrypt`. The FLUENT BUILDERS are not re-exported, so
// theirs carry the whole path — the graph emits
// `aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.encryption_algorithm`.
// A key written the other way round for either group resolves to nothing, which
// looks exactly like having no contract at all.
//
// The second assertion is the one this contract exists for. Without it, the
// algorithm-bearing link of a builder chain comes back as the CONSUMER's own
// package (`<consumer>.encryption_algorithm`), which is what an absent contract
// looks like in an exported call graph.
func TestAwsSdkKmsContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// The FULL BUILDER, not the parser alone: contract-driven chain propagation
	// runs after the KB is loaded, so a parser-only helper cannot see the keys
	// this test is about.
	dir := t.TempDir()
	src := `use aws_sdk_kms::types::{EncryptionAlgorithmSpec, MacAlgorithmSpec, SigningAlgorithmSpec};
use aws_sdk_kms::Client;

async fn app(client: &Client, blob: Blob) {
    let _ = client.encrypt().encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256).send().await;
    let _ = client.sign().signing_algorithm(SigningAlgorithmSpec::EcdsaSha384).send().await;
    let _ = client.generate_mac().mac_algorithm(MacAlgorithmSpec::HmacSha512).send().await;
    let _ = client.generate_random().number_of_bytes(32).send().await;
    let _ = client.derive_shared_secret().send().await;
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Call-site keys join segments with "."; the KB keeps Rust's "::" module
	// separator and ContractsFor bridges the two. Only the keys the graph
	// actually resolves are asserted.
	want := map[string]string{
		"aws_sdk_kms.Client.encrypt":              "operation",
		"aws_sdk_kms.Client.sign":                 "operation",
		"aws_sdk_kms.Client.generate_mac":         "operation",
		"aws_sdk_kms.Client.generate_random":      "operation",
		"aws_sdk_kms.Client.derive_shared_secret": "operation",
		"aws_sdk_kms::operation::encrypt::builders.EncryptFluentBuilder.encryption_algorithm":   "config",
		"aws_sdk_kms::operation::sign::builders.SignFluentBuilder.signing_algorithm":            "config",
		"aws_sdk_kms::operation::generate_mac::builders.GenerateMacFluentBuilder.mac_algorithm": "config",
	}
	seen := map[string]bool{}

	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			callee := fn.Calls[i].Callee
			method, _ := splitMethodArity(&callee)
			role, ok := want[method]
			if !ok {
				continue
			}
			got := kb.ContractsFor(method, len(fn.Calls[i].Arguments))
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
					method, len(fn.Calls[i].Arguments), len(got))
			}
			if got[0].Role != role || got[0].SourceLibrary != "aws-sdk-kms" {
				t.Fatalf("contract for %q = %#v, want aws-sdk-kms %s", method, got[0], role)
			}
			seen[method] = true
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// TestAwsSdkKmsContractKeysArePinnedByName is the check a walk over the KB
// cannot be: a test that reads each entry's own method and arity back to query
// it hits by construction and cannot catch a misspelling. These keys are named
// as literals, so a typo, a changed arity or a deleted entry fails here.
//
// The list is the CLIENT surface — all thirteen operations — plus one algorithm
// selector per operation that has one, in both the modern and the pre-0.39.0
// builder spellings. The per-builder configuration methods are covered by
// TestAwsSdkKmsBuilderMethodSetsAreTheSourcesSets, which names each builder's
// whole set.
func TestAwsSdkKmsContractKeysArePinnedByName(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type key struct {
		method string
		arity  int
		role   string
	}
	want := []key{
		{"aws_sdk_kms::Client.encrypt", 0, "operation"},
		{"aws_sdk_kms::Client.decrypt", 0, "operation"},
		{"aws_sdk_kms::Client.re_encrypt", 0, "operation"},
		{"aws_sdk_kms::Client.sign", 0, "operation"},
		{"aws_sdk_kms::Client.verify", 0, "operation"},
		{"aws_sdk_kms::Client.generate_mac", 0, "operation"},
		{"aws_sdk_kms::Client.verify_mac", 0, "operation"},
		{"aws_sdk_kms::Client.generate_random", 0, "operation"},
		{"aws_sdk_kms::Client.derive_shared_secret", 0, "operation"},
		// Key generation mints material, so it is `factory`, as sodiumoxide's
		// gen_keypair and aes-gcm's generate_key are.
		{"aws_sdk_kms::Client.generate_data_key", 0, "factory"},
		{"aws_sdk_kms::Client.generate_data_key_pair", 0, "factory"},
		{"aws_sdk_kms::Client.generate_data_key_without_plaintext", 0, "factory"},
		{"aws_sdk_kms::Client.generate_data_key_pair_without_plaintext", 0, "factory"},
		// The algorithm selectors, modern spelling.
		{"aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder.encryption_algorithm", 1, "config"},
		{"aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder.encryption_algorithm", 1, "config"},
		{"aws_sdk_kms::operation::sign::builders::SignFluentBuilder.signing_algorithm", 1, "config"},
		{"aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder.signing_algorithm", 1, "config"},
		{"aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder.mac_algorithm", 1, "config"},
		{"aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder.mac_algorithm", 1, "config"},
		{"aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder.key_spec", 1, "config"},
		{"aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder.key_agreement_algorithm", 1, "config"},
		// And the pre-0.39.0 spelling of the same selectors.
		{"aws_sdk_kms::client::fluent_builders::Encrypt.encryption_algorithm", 1, "config"},
		{"aws_sdk_kms::client::fluent_builders::Sign.signing_algorithm", 1, "config"},
		{"aws_sdk_kms::client::fluent_builders::GenerateDataKey.key_spec", 1, "config"},
		// re_encrypt names two keys and no `key_id`, which is why a uniform
		// method set would have been wrong.
		{"aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder.source_key_id", 1, "config"},
		{"aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder.destination_key_id", 1, "config"},
		// generate_random names no key at all.
		{"aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder.number_of_bytes", 1, "config"},
	}

	for _, w := range want {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want exactly one", w.method, w.arity, len(got))
			continue
		}
		if got[0].SourceLibrary != "aws-sdk-kms" {
			t.Errorf("%q resolved to library %q, want aws-sdk-kms", w.method, got[0].SourceLibrary)
		}
		if got[0].Role != w.role {
			t.Errorf("%q role = %q, want %q", w.method, got[0].Role, w.role)
		}
	}

	// `re_encrypt` must NOT carry a plain `key_id`: the operation names a source
	// and a destination key and nothing else. This is the assertion that would
	// have caught a uniform, invented method set.
	if got := kb.ContractsFor("aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder.key_id", 1); len(got) != 0 {
		t.Errorf("re_encrypt declares a key_id it does not have: %#v", got)
	}
	if got := kb.ContractsFor("aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder.key_id", 1); len(got) != 0 {
		t.Errorf("generate_random declares a key_id it does not have: %#v", got)
	}
}

// TestAwsSdkKmsBuilderMethodSetsAreTheSourcesSets is the guard a count cannot
// be. An earlier draft of this contract applied the MODERN method list to the
// legacy type names and invented 19 entries — `dry_run` and `recipient`, which
// appear nowhere in the crate before 0.39.0, and a whole `DeriveSharedSecret`
// legacy builder for an operation that arrives at 1.32.0, after the legacy
// module was deleted. A test that reads each entry's own method back to query
// it hits by construction and caught none of that; a total-count assertion
// actively defended the invented entries, because deleting them broke it.
//
// So the sets are named here, per builder, exactly as the sources have them:
// the modern ones from `src/operation/<op>/builders.rs` at 1.111.0 and the
// pre-0.39.0 ones from the `impl <Op>` blocks in `src/client.rs` at 0.24.0.
// A method the contract declares and the crate does not have fails here, and so
// does one the crate has and the contract silently drops.
func TestAwsSdkKmsBuilderMethodSetsAreTheSourcesSets(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	declared := map[string]map[string]bool{}
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary != "aws-sdk-kms" {
				continue
			}
			dot := strings.LastIndex(entry.Method, ".")
			if dot < 0 {
				continue
			}
			owner, method := entry.Method[:dot], entry.Method[dot+1:]
			if declared[owner] == nil {
				declared[owner] = map[string]bool{}
			}
			declared[owner][method] = true
		}
	}

	for _, tc := range builderSets() {
		got := declared[tc.builder]
		if got == nil {
			t.Errorf("%s: no entries declared at all", tc.builder)
			continue
		}
		for _, m := range tc.methods {
			if !got[m] {
				t.Errorf("%s: the sources have %q and the contract does not declare it", tc.builder, m)
			}
		}
		for m := range got {
			found := false
			for _, want := range tc.methods {
				if m == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: the contract declares %q, which the sources do not have", tc.builder, m)
			}
		}
	}

	// AND NOTHING BEYOND THE LIST. Without this the table only checks the
	// builders it names, so re-adding the invented
	// `client::fluent_builders::DeriveSharedSecret` — the exact entry class this
	// test exists to catch — passes green. Measured, before this loop existed.
	owners := map[string]bool{"aws_sdk_kms::Client": true}
	for _, tc := range builderSets() {
		owners[tc.builder] = true
	}
	for owner := range declared {
		if !owners[owner] {
			t.Errorf("the contract declares entries for %q, which is not a builder the sources have", owner)
		}
	}

	// The client surface itself: every operation, arity 0, and nothing else.
	clientOps := declared["aws_sdk_kms::Client"]
	if len(clientOps) != 13 {
		t.Errorf("aws_sdk_kms::Client declares %d operations, want 13", len(clientOps))
	}
}

// builderSetsRow is one builder and the method set its era's sources declare.
type builderSetsRow struct {
	builder string
	methods []string
}

// builderSets is the table itself, extracted so the owner-closure check above
// can assert the contract declares nothing outside it.
func builderSets() []builderSetsRow {
	return []builderSetsRow{
		{"aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder", []string{"dry_run", "encryption_algorithm", "encryption_context", "grant_tokens", "key_id", "plaintext"}},
		{"aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder", []string{"ciphertext_blob", "dry_run", "dry_run_modifiers", "encryption_algorithm", "encryption_context", "grant_tokens", "key_id", "recipient"}},
		{"aws_sdk_kms::operation::re_encrypt::builders::ReEncryptFluentBuilder", []string{"ciphertext_blob", "destination_encryption_algorithm", "destination_encryption_context", "destination_key_id", "dry_run", "dry_run_modifiers", "grant_tokens", "source_encryption_algorithm", "source_encryption_context", "source_key_id"}},
		{"aws_sdk_kms::operation::sign::builders::SignFluentBuilder", []string{"dry_run", "grant_tokens", "key_id", "message", "message_type", "signing_algorithm"}},
		{"aws_sdk_kms::operation::verify::builders::VerifyFluentBuilder", []string{"dry_run", "grant_tokens", "key_id", "message", "message_type", "signature", "signing_algorithm"}},
		{"aws_sdk_kms::operation::generate_mac::builders::GenerateMacFluentBuilder", []string{"dry_run", "grant_tokens", "key_id", "mac_algorithm", "message"}},
		{"aws_sdk_kms::operation::verify_mac::builders::VerifyMacFluentBuilder", []string{"dry_run", "grant_tokens", "key_id", "mac", "mac_algorithm", "message"}},
		{"aws_sdk_kms::operation::generate_data_key::builders::GenerateDataKeyFluentBuilder", []string{"dry_run", "encryption_context", "grant_tokens", "key_id", "key_spec", "number_of_bytes", "recipient"}},
		{"aws_sdk_kms::operation::generate_data_key_pair::builders::GenerateDataKeyPairFluentBuilder", []string{"dry_run", "encryption_context", "grant_tokens", "key_id", "key_pair_spec", "recipient"}},
		{"aws_sdk_kms::operation::generate_data_key_without_plaintext::builders::GenerateDataKeyWithoutPlaintextFluentBuilder", []string{"dry_run", "encryption_context", "grant_tokens", "key_id", "key_spec", "number_of_bytes"}},
		{"aws_sdk_kms::operation::generate_data_key_pair_without_plaintext::builders::GenerateDataKeyPairWithoutPlaintextFluentBuilder", []string{"dry_run", "encryption_context", "grant_tokens", "key_id", "key_pair_spec"}},
		{"aws_sdk_kms::operation::generate_random::builders::GenerateRandomFluentBuilder", []string{"custom_key_store_id", "number_of_bytes", "recipient"}},
		{"aws_sdk_kms::operation::derive_shared_secret::builders::DeriveSharedSecretFluentBuilder", []string{"dry_run", "grant_tokens", "key_agreement_algorithm", "key_id", "public_key", "recipient"}},
		{"aws_sdk_kms::client::fluent_builders::Encrypt", []string{"encryption_algorithm", "encryption_context", "grant_tokens", "key_id", "plaintext"}},
		{"aws_sdk_kms::client::fluent_builders::Decrypt", []string{"ciphertext_blob", "encryption_algorithm", "encryption_context", "grant_tokens", "key_id"}},
		{"aws_sdk_kms::client::fluent_builders::ReEncrypt", []string{"ciphertext_blob", "destination_encryption_algorithm", "destination_encryption_context", "destination_key_id", "grant_tokens", "source_encryption_algorithm", "source_encryption_context", "source_key_id"}},
		{"aws_sdk_kms::client::fluent_builders::Sign", []string{"grant_tokens", "key_id", "message", "message_type", "signing_algorithm"}},
		{"aws_sdk_kms::client::fluent_builders::Verify", []string{"grant_tokens", "key_id", "message", "message_type", "signature", "signing_algorithm"}},
		{"aws_sdk_kms::client::fluent_builders::GenerateMac", []string{"grant_tokens", "key_id", "mac_algorithm", "message"}},
		{"aws_sdk_kms::client::fluent_builders::VerifyMac", []string{"grant_tokens", "key_id", "mac", "mac_algorithm", "message"}},
		{"aws_sdk_kms::client::fluent_builders::GenerateDataKey", []string{"encryption_context", "grant_tokens", "key_id", "key_spec", "number_of_bytes"}},
		{"aws_sdk_kms::client::fluent_builders::GenerateDataKeyPair", []string{"encryption_context", "grant_tokens", "key_id", "key_pair_spec"}},
		{"aws_sdk_kms::client::fluent_builders::GenerateDataKeyWithoutPlaintext", []string{"encryption_context", "grant_tokens", "key_id", "key_spec", "number_of_bytes"}},
		{"aws_sdk_kms::client::fluent_builders::GenerateDataKeyPairWithoutPlaintext", []string{"encryption_context", "grant_tokens", "key_id", "key_pair_spec"}},
		{"aws_sdk_kms::client::fluent_builders::GenerateRandom", []string{"custom_key_store_id", "number_of_bytes"}},
	}
}
