// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The rusoto_kms KB is keyed on what the Rust parser emits, and the keys were
// read off an exported call graph rather than written from the API: a probe
// consumer emits `rusoto_kms.KmsClient.encrypt(?)` with empty parameter_types
// before this contract exists, and the same command is the proof it resolved
// afterwards. Everything this crate exposes is `pub use generated::*` from the
// crate root, so no key carries a module segment — the opposite of
// rust/aws-sdk-kms, whose fluent builders are not re-exported and whose keys
// therefore carry the whole path.
//
// ALL FIFTEEN DECLARED KEYS ARE EXERCISED, not a representative subset: an
// entry no call site reaches is an entry nothing proves. Both receiver shapes
// are covered — the client bound from a constructor and the client reached
// through a struct field, which is what every published consumer of this crate
// actually writes — and `new` is called at both of its arities, because
// 0.25.0-0.32.0 takes (dispatcher, credentials, region) and 0.33.0 onward takes
// the region alone.
func TestRusotoKmsContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	const src = `use rusoto_core::Region;
use rusoto_kms::{DecryptRequest, EncryptRequest, GenerateDataKeyPairRequest, GenerateDataKeyPairWithoutPlaintextRequest, GenerateDataKeyRequest, GenerateDataKeyWithoutPlaintextRequest, GenerateRandomRequest, Kms, KmsClient, ReEncryptRequest, SignRequest, VerifyRequest};

struct Wrapper {
    kms: KmsClient,
}

async fn app(enc: EncryptRequest, dec: DecryptRequest, re: ReEncryptRequest, dk: GenerateDataKeyRequest, dkw: GenerateDataKeyWithoutPlaintextRequest, dkp: GenerateDataKeyPairRequest, dkpw: GenerateDataKeyPairWithoutPlaintextRequest, sig: SignRequest, ver: VerifyRequest, rnd: GenerateRandomRequest, w: &Wrapper) {
    let client = KmsClient::new(Region::UsEast1);
    let _ = client.encrypt(enc).await;
    let _ = client.decrypt(dec).await;
    let _ = client.re_encrypt(re).await;
    let _ = client.generate_data_key(dk).await;
    let _ = client.generate_data_key_without_plaintext(dkw).await;
    let _ = client.generate_data_key_pair(dkp).await;
    let _ = client.generate_data_key_pair_without_plaintext(dkpw).await;
    let _ = client.sign(sig).await;
    let _ = w.kms.verify(ver).await;
    let _ = w.kms.generate_random(rnd).await;
}

fn constructors(dispatcher: HttpClient, credentials: ChainProvider, http: Client) {
    let _ = KmsClient::new_with(dispatcher, credentials, Region::UsEast1);
    let _ = KmsClient::new_with_client(http, Region::UsEast1);
    let _ = KmsClient::simple(Region::UsEast1);
    let _ = KmsClient::new(dispatcher, credentials, Region::UsEast1);
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
	// separator and ContractsFor bridges the two.
	type key struct {
		method string
		arity  int
	}
	want := map[key]string{
		{"rusoto_kms.KmsClient.new", 1}:                                      "factory",
		{"rusoto_kms.KmsClient.new", 3}:                                      "factory",
		{"rusoto_kms.KmsClient.new_with", 3}:                                 "factory",
		{"rusoto_kms.KmsClient.new_with_client", 2}:                          "factory",
		{"rusoto_kms.KmsClient.simple", 1}:                                   "factory",
		{"rusoto_kms.KmsClient.encrypt", 1}:                                  "operation",
		{"rusoto_kms.KmsClient.decrypt", 1}:                                  "operation",
		{"rusoto_kms.KmsClient.re_encrypt", 1}:                               "operation",
		{"rusoto_kms.KmsClient.generate_data_key", 1}:                        "factory",
		{"rusoto_kms.KmsClient.generate_data_key_without_plaintext", 1}:      "factory",
		{"rusoto_kms.KmsClient.generate_data_key_pair", 1}:                   "factory",
		{"rusoto_kms.KmsClient.generate_data_key_pair_without_plaintext", 1}: "factory",
		{"rusoto_kms.KmsClient.sign", 1}:                                     "operation",
		{"rusoto_kms.KmsClient.verify", 1}:                                   "operation",
		{"rusoto_kms.KmsClient.generate_random", 1}:                          "operation",
	}
	if len(want) != 15 {
		t.Fatalf("the KB declares 15 entries; this test names %d", len(want))
	}
	seen := map[key]bool{}

	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			callee := fn.Calls[i].Callee
			method, _ := splitMethodArity(&callee)
			k := key{method, len(fn.Calls[i].Arguments)}
			role, ok := want[k]
			if !ok {
				continue
			}
			got := kb.ContractsFor(k.method, k.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
					k.method, k.arity, len(got))
			}
			if got[0].Role != role || got[0].SourceLibrary != "rusoto_kms" {
				t.Fatalf("contract for %q/%d = %#v, want rusoto_kms %s", k.method, k.arity, got[0], role)
			}
			seen[k] = true
		}
	}

	for k := range want {
		if !seen[k] {
			t.Fatalf("parsed calls did not cover %q at arity %d; seen = %v", k.method, k.arity, seen)
		}
	}
}
