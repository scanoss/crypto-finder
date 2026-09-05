// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// google-cloud-kms is a gRPC client for a REMOTE service: it implements no
// cryptography, and every method here marshals a protobuf request. Three things
// about that make the contract easy to get wrong in ways nothing else notices.
//
//  1. `Client` is NOT re-exported from the crate root -- `lib.rs` is `pub mod`
//     lines and nothing else, two at 0.1.0/0.2.0 and three from 0.3.0 -- so every
//     key carries its module segment, and the signer keys carry two. A key written without them loads without error and
//     resolves nothing, which is indistinguishable from having no contract.
//  2. The crate declares TWO types named `Client`: `client::Client` and the
//     `grpc::apiv1::kms_client::Client` it derefs to (src/client.rs:82-88).
//     Consumers call the RPCs through the deref on the outer type, and the
//     graph resolves them to the outer one -- which is the key declared here.
//  3. The contract must NOT acquire algorithm metadata. The algorithm-bearing
//     enums belong to google-cloud-googleapis, not to this crate, and no
//     argument here contributes a cryptographic property. TestNoAlgorithm...
//     below pins that as a test rather than as a comment in the YAML.
//
// The contract file for this family was authored by reading these keys off an
// exported call graph, then applying rustAuthoredKey's one substitution
// (contracts.go:267): the graph emits `google_cloud_kms::client.Client.encrypt`
// and the file must say `google_cloud_kms::client::Client.encrypt`.

const gckmsLibrary = "google-cloud-kms"

// gckmsContractFile loads THIS family's YAML on its own, so the library block
// is reachable. LoadEmbedded merges every rust contract and leaves Library nil.
func gckmsContractFile(t *testing.T) *contracts.KnowledgeBase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("contracts", ecosystemRust, "google-cloud-kms.yaml"))
	if err != nil {
		t.Fatalf("read google-cloud-kms.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(google-cloud-kms.yaml): %v", err)
	}
	return kb
}

// renderGckmsContract renders one entry in full. Every field that a mutation
// could corrupt is in the string, INCLUDING canonical_return_type and the
// parameters block: a per-key subset assertion cannot see an entry that should
// not be there, an entry that was dropped, or a field that was silently
// changed, and renaming a contributed property loads cleanly through the
// schema's presence checks while changing what downstream resolution computes.
func renderGckmsContract(c contracts.Contract) string {
	params := "-"
	if len(c.Parameters) > 0 {
		parts := make([]string, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			idx := "-"
			if p.Index != nil {
				idx = fmt.Sprint(*p.Index)
			}
			contrib := "-"
			if p.Contributes != nil {
				contrib = p.Contributes.Property + ":" + p.Contributes.Derivation
			}
			parts = append(parts, fmt.Sprintf("%s/%s/%s/%s", idx, p.Name, p.Role, contrib))
		}
		params = strings.Join(parts, ";")
	}
	return fmt.Sprintf("%s#%d|%s|%s|%s|%s|%s|%s|%v",
		c.Method, c.Arity, c.Role,
		c.Return.Type, c.Return.Confidence,
		c.CanonicalReturnType,
		strings.Join(c.ParameterTypes, ","),
		params, c.Varargs)
}

// TestGoogleCloudKmsContractSetIsExact compares the WHOLE loaded set against a
// literal. Not a per-key lookup: a lookup built from each entry's own method
// and arity hits by construction and cannot catch a spurious entry, a dropped
// one, or a corrupted field.
func TestGoogleCloudKmsContractSetIsExact(t *testing.T) {
	t.Parallel()

	kb := gckmsContractFile(t)

	var got []string
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if entry.SourceLibrary != gckmsLibrary {
				t.Fatalf("entry %q carries library %q", entry.Method, entry.SourceLibrary)
			}
			got = append(got, renderGckmsContract(entry))
		}
	}
	sort.Strings(got)

	want := []string{
		"google_cloud_kms::client::Client.asymmetric_sign#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::AsymmetricSignResponse, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::AsymmetricSignRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.create_crypto_key#2|factory|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::CryptoKey, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::CreateCryptoKeyRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.create_crypto_key_version#2|factory|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::CryptoKeyVersion, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::CreateCryptoKeyVersionRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.decrypt#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::DecryptResponse, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::DecryptRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.destroy_crypto_key_version#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::CryptoKeyVersion, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::DestroyCryptoKeyVersionRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.encrypt#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::EncryptResponse, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::EncryptRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.generate_random_bytes#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::GenerateRandomBytesResponse, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::GenerateRandomBytesRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.get_public_key#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::PublicKey, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::GetPublicKeyRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.mac_sign#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::MacSignResponse, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::MacSignRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.mac_verify#2|operation|core::result::Result|high|core::result::Result<google_cloud_kms::grpc::kms::v1::MacVerifyResponse, google_cloud_gax::grpc::Status>|google_cloud_kms::grpc::kms::v1::MacVerifyRequest,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::client::Client.new#1|factory|core::result::Result|high|core::result::Result<google_cloud_kms::client::Client, google_cloud_gax::conn::Error>|google_cloud_kms::client::ClientConfig|-|false",
		"google_cloud_kms::signer::ethereum::Signer.new#4|factory|core::result::Result|high|core::result::Result<google_cloud_kms::signer::ethereum::Signer, google_cloud_kms::signer::ethereum::Error>|google_cloud_kms::client::Client,&str,u64,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::signer::ethereum::Signer.new_with_pubkey#6|factory|google_cloud_kms::signer::ethereum::Signer|high||google_cloud_kms::client::Client,&str,ethers_core::k256::ecdsa::VerifyingKey,ethers_core::types::Address,u64,core::option::Option<google_cloud_gax::retry::RetrySetting>|-|false",
		"google_cloud_kms::signer::ethereum::Signer.sign_digest#1|operation|core::result::Result|high|core::result::Result<ethers_core::types::Signature, google_cloud_kms::signer::ethereum::Error>|&[u8]|-|false",
	}

	if len(got) != len(want) {
		t.Fatalf("contract set size = %d, want %d\n got: %s\nwant: %s",
			len(got), len(want), strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("contract[%d] mismatch\n got: %s\nwant: %s", i, got[i], want[i])
		}
	}
}

// TestGoogleCloudKmsLibraryBlockIsExact covers the four fields the entry
// comparison above cannot see. They are parsed and then never consulted by any
// other assertion, so corrupting one is otherwise entirely silent -- and
// version_range is the field that decides which releases this contract claims
// to describe.
func TestGoogleCloudKmsLibraryBlockIsExact(t *testing.T) {
	t.Parallel()

	kb := gckmsContractFile(t)
	if kb.Library == nil {
		t.Fatal("library block is missing")
	}
	if kb.Ecosystem != ecosystemRust || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema = %q/%q, want rust/2", kb.Ecosystem, kb.SchemaVersion)
	}
	if kb.Library.Name != gckmsLibrary {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, gckmsLibrary)
	}
	// The published range, and no more. 0.6.0 is the newest release on
	// crates.io; for a 0.x crate each minor is a breaking boundary, so an upper
	// bound of 1.0.0 would claim these signatures for a 0.7.0 that does not
	// exist.
	if kb.Library.VersionRange != ">=0.1.0,<0.7.0" {
		t.Errorf("library.version_range = %q, want %q", kb.Library.VersionRange, ">=0.1.0,<0.7.0")
	}
	// Both spellings: the package name is hyphenated, the lib name and every
	// path a consumer writes are underscored.
	want := []string{"google-cloud-kms", "google_cloud_kms"}
	if strings.Join(kb.Library.Coordinates, ",") != strings.Join(want, ",") {
		t.Errorf("library.coordinates = %v, want %v", kb.Library.Coordinates, want)
	}
	if !strings.Contains(kb.Library.Description, "Key Management Service") {
		t.Errorf("library.description = %q, want it to name the service", kb.Library.Description)
	}
}

// TestGoogleCloudKmsDeclaresNoAlgorithmContribution is the refusal, pinned in
// the analyzer as well as in the rules.
//
// A `parameters:` entry exists to say that an argument CONTRIBUTES a
// cryptographic property. No argument in this crate does: the first is an
// opaque protobuf request whose algorithm-bearing fields hold enum values owned
// by the SEPARATE crate google-cloud-googleapis, and the second is a retry
// policy. If someone later adds a contribution here -- reading a key size, a
// curve or a protection level off a request -- this fails, and it should,
// because the value would be manufactured rather than read.
func TestGoogleCloudKmsDeclaresNoAlgorithmContribution(t *testing.T) {
	t.Parallel()

	kb := gckmsContractFile(t)
	for _, bucket := range kb.Contracts {
		for _, entry := range bucket {
			if len(entry.Parameters) != 0 {
				t.Errorf("%s declares parameter contributions %#v; this family names no "+
					"algorithm because the call site does not carry one", entry.Method, entry.Parameters)
			}
			if entry.When != nil {
				t.Errorf("%s declares an argument condition; no argument here selects an algorithm", entry.Method)
			}
		}
	}
}

// TestGoogleCloudKmsDoesNotDeclareAbsentMethods names, as literals, methods
// that a reasonable author would expect this contract to have and which it must
// not: two the crate does not implement, one that belongs to `Result`, and
// three that are key-management reads rather than cryptography.
func TestGoogleCloudKmsDoesNotDeclareAbsentMethods(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemRust)
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	absent := []struct {
		method string
		arity  int
		why    string
	}{
		// The Cloud KMS service has these RPCs; this client never wrapped them.
		// Verified absent from all seven published versions.
		{"google_cloud_kms::client::Client.asymmetric_decrypt", 2, "the crate does not implement it"},
		{"google_cloud_kms::client::Client.raw_encrypt", 2, "the crate does not implement it"},
		// `unwrap` is Result's. The graph emits it for the chained
		// `Client::new(cfg).await.unwrap()` because the crypto call resolves to
		// the outermost call; declaring it would be a false statement about
		// this library.
		{"google_cloud_kms::client::Client.unwrap", 0, "it belongs to Result, not to this crate"},
		// Key rings are containers and get_crypto_key reads a resource
		// description; neither performs or configures an operation.
		{"google_cloud_kms::client::Client.create_key_ring", 2, "a key ring is a container"},
		{"google_cloud_kms::client::Client.get_key_ring", 2, "a key ring is a container"},
		{"google_cloud_kms::client::Client.get_crypto_key", 2, "a metadata read is not an operation"},
	}

	for _, a := range absent {
		if got := kb.ContractsFor(a.method, a.arity); len(got) != 0 {
			t.Errorf("%s is declared (%s): %#v", a.method, a.why, got)
		}
	}
}

// TestGoogleCloudKmsContractsResolveParsedCallIdentities is the join test: it
// builds a real graph from consumer-shaped source and asserts the keys the
// parser emits are the keys this contract declares. A contract written from the
// API instead of from the graph passes every other test in this file and
// resolves nothing here.
func TestGoogleCloudKmsContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemRust)
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::{AsymmetricSignRequest, CreateCryptoKeyRequest, DecryptRequest, EncryptRequest, GenerateRandomBytesRequest, GetPublicKeyRequest, MacSignRequest, MacVerifyRequest};
use google_cloud_kms::signer::ethereum::Signer;

async fn build(config: ClientConfig) {
    let _ = Client::new(config).await;
}

async fn app(client: &Client, e: EncryptRequest, d: DecryptRequest, a: AsymmetricSignRequest,
             ms: MacSignRequest, mv: MacVerifyRequest, g: GenerateRandomBytesRequest,
             p: GetPublicKeyRequest, ck: CreateCryptoKeyRequest) {
    let _ = client.encrypt(e, None).await;
    let _ = client.decrypt(d, None).await;
    let _ = client.asymmetric_sign(a, None).await;
    let _ = client.mac_sign(ms, None).await;
    let _ = client.mac_verify(mv, None).await;
    let _ = client.generate_random_bytes(g, None).await;
    let _ = client.get_public_key(p, None).await;
    let _ = client.create_crypto_key(ck, None).await;
}

async fn signing(client: Client, key_name: &str, digest: &[u8]) {
    let signer = google_cloud_kms::signer::ethereum::Signer::new(client, key_name, 1, None).await;
    let _ = signer.sign_digest(digest).await;
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBuilderForEcosystem(ecosystemRust, NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Call-site keys join segments with "."; the KB keeps Rust's "::" module
	// separator and ContractsFor bridges the two. The module segment on every
	// key is the point: `Client` is not re-exported from the crate root.
	want := map[string]string{
		"google_cloud_kms::client.Client.new":                   "factory",
		"google_cloud_kms::client.Client.encrypt":               "operation",
		"google_cloud_kms::client.Client.decrypt":               "operation",
		"google_cloud_kms::client.Client.asymmetric_sign":       "operation",
		"google_cloud_kms::client.Client.mac_sign":              "operation",
		"google_cloud_kms::client.Client.mac_verify":            "operation",
		"google_cloud_kms::client.Client.generate_random_bytes": "operation",
		"google_cloud_kms::client.Client.get_public_key":        "operation",
		"google_cloud_kms::client.Client.create_crypto_key":     "factory",
		"google_cloud_kms::signer::ethereum.Signer.new":         "factory",
		"google_cloud_kms::signer::ethereum.Signer.sign_digest": "operation",
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
				t.Errorf("ContractsFor(%q, %d) = %d, want exactly one contract",
					method, len(fn.Calls[i].Arguments), len(got))
				continue
			}
			if got[0].Role != role || got[0].SourceLibrary != gckmsLibrary {
				t.Errorf("contract for %q = library %q role %q, want %s %s",
					method, got[0].SourceLibrary, got[0].Role, gckmsLibrary, role)
			}
			seen[method] = true
		}
	}

	for method := range want {
		if !seen[method] {
			t.Errorf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}
