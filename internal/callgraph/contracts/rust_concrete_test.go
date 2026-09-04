// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// concrete publishes THREE unrelated APIs under one crate name, and the keys
// differ in shape between them because the module structure does. The 0.1.x
// types are `pub use`-exported from the crate root, so the graph emits
// `concrete.LWE.encode_encrypt` and the KB file authors
// `concrete::LWE.encode_encrypt` -- rustAuthoredKey (contracts.go:267) moves the
// second-to-last dot at lookup time. The 2.x types are reached only through
// `common`, `client` and `server` because `mod ffi` is private, so the graph
// emits `concrete::client.ClientFunction.prepare_input` and the file authors
// `concrete::client::ClientFunction.prepare_input`. The two free functions carry
// a single dot, which rustAuthoredKey returns unchanged, so they are authored in
// the dot form.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot see
// an entry that should not be there, an entry that was dropped, or a field that
// was corrupted; only the whole-set comparison does. It renders the role, both
// return types, the parameter list, the confidence AND the per-parameter
// contract block, so renaming a contributed property is visible too.
func renderConcreteContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "concrete" {
				continue
			}
			params := "none"
			if len(c.Parameters) > 0 {
				var rendered []string
				for _, p := range c.Parameters {
					idx := "-"
					if p.Index != nil {
						idx = fmt.Sprintf("%d", *p.Index)
					}
					contributes := ""
					if p.Contributes != nil {
						contributes = fmt.Sprintf("%s:%s", p.Contributes.Property, p.Contributes.Derivation)
					}
					rendered = append(rendered, fmt.Sprintf("%s|%s|%s|%s", idx, p.Name, p.Role, contributes))
				}
				sort.Strings(rendered)
				params = strings.Join(rendered, ";")
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/params=%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence, params))
		}
	}
	sort.Strings(got)
	return got
}

var wantConcreteContracts = []string{
	"concrete.generate_keys#1/factory/(concrete::ClientKey, concrete::ServerKey)/(concrete::ClientKey, concrete::ServerKey)/[concrete::Config]/high/params=none",
	"concrete.set_server_key#1/config/()/()/[concrete::ServerKey]/high/params=none",
	"concrete::ClientKey.generate#1/factory/concrete::ClientKey/concrete::ClientKey/[concrete::Config]/high/params=none",
	"concrete::ClientKey.generate_server_key#0/factory/concrete::ServerKey/concrete::ServerKey/[]/high/params=none",
	"concrete::ConfigBuilder.all_disabled#0/factory/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.all_enabled#0/factory/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.build#0/factory/concrete::Config/concrete::Config/[]/high/params=none",
	"concrete::ConfigBuilder.disable_bool#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.disable_uint12#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.disable_uint16#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.disable_uint2#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.disable_uint3#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.disable_uint4#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.disable_uint8#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.enable_custom_bool#1/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[concrete::FheBoolParameters]/high/params=none",
	"concrete::ConfigBuilder.enable_custom_uint2#1/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[concrete::FheUint2Parameters]/high/params=none",
	"concrete::ConfigBuilder.enable_custom_uint3#1/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[concrete::FheUint3Parameters]/high/params=none",
	"concrete::ConfigBuilder.enable_custom_uint4#1/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[concrete::FheUint4Parameters]/high/params=none",
	"concrete::ConfigBuilder.enable_default_bool#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.enable_default_uint12#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.enable_default_uint16#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.enable_default_uint2#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.enable_default_uint3#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.enable_default_uint4#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::ConfigBuilder.enable_default_uint8#0/config/concrete::ConfigBuilder/concrete::ConfigBuilder/[]/high/params=none",
	"concrete::Encoder.new#4/factory/core::result::Result/core::result::Result<concrete::Encoder, concrete::CryptoAPIError>/[f64,f64,usize,usize]/high/params=none",
	"concrete::Encoder.new_centered#4/factory/core::result::Result/core::result::Result<concrete::Encoder, concrete::CryptoAPIError>/[f64,f64,usize,usize]/high/params=none",
	"concrete::FheBool.decrypt#1/output/bool/bool/[concrete::ClientKey]/high/params=none",
	"concrete::FheBool.encrypt#2/operation/concrete::FheBool/concrete::FheBool/[bool,concrete::ClientKey]/high/params=none",
	"concrete::FheUint12.decrypt#1/output/u64/u64/[concrete::ClientKey]/high/params=none",
	"concrete::FheUint12.try_encrypt#2/operation/core::result::Result/core::result::Result<concrete::FheUint12, concrete::OutOfRangeError>/[u16,concrete::ClientKey]/high/params=none",
	"concrete::FheUint16.decrypt#1/output/u16/u16/[concrete::ClientKey]/high/params=none",
	"concrete::FheUint16.encrypt#2/operation/concrete::FheUint16/concrete::FheUint16/[u16,concrete::ClientKey]/high/params=none",
	"concrete::FheUint16.try_encrypt#2/operation/core::result::Result/core::result::Result<concrete::FheUint16, concrete::OutOfRangeError>/[u16,concrete::ClientKey]/high/params=none",
	"concrete::FheUint2.decrypt#1/output/u8/u8/[concrete::ClientKey]/high/params=none",
	"concrete::FheUint2.try_encrypt#2/operation/core::result::Result/core::result::Result<concrete::FheUint2, concrete::OutOfRangeError>/[u8,concrete::ClientKey]/high/params=none",
	"concrete::FheUint2.try_encrypt_trivial#1/operation/core::result::Result/core::result::Result<concrete::FheUint2, concrete::OutOfRangeError>/[u8]/high/params=none",
	"concrete::FheUint3.bivariate_pbs#2/operation/concrete::FheUint3/concrete::FheUint3/[concrete::FheUint3,F]/high/params=none",
	"concrete::FheUint3.decrypt#1/output/u8/u8/[concrete::ClientKey]/high/params=none",
	"concrete::FheUint3.try_encrypt#2/operation/core::result::Result/core::result::Result<concrete::FheUint3, concrete::OutOfRangeError>/[u8,concrete::ClientKey]/high/params=none",
	"concrete::FheUint3.try_encrypt_trivial#1/operation/core::result::Result/core::result::Result<concrete::FheUint3, concrete::OutOfRangeError>/[u8]/high/params=none",
	"concrete::FheUint4.decrypt#1/output/u8/u8/[concrete::ClientKey]/high/params=none",
	"concrete::FheUint4.try_encrypt#2/operation/core::result::Result/core::result::Result<concrete::FheUint4, concrete::OutOfRangeError>/[u8,concrete::ClientKey]/high/params=none",
	"concrete::FheUint4.try_encrypt_trivial#1/operation/core::result::Result/core::result::Result<concrete::FheUint4, concrete::OutOfRangeError>/[u8]/high/params=none",
	"concrete::FheUint8.bivariate_function#2/operation/concrete::FheUint8/concrete::FheUint8/[concrete::FheUint8,F]/high/params=none",
	"concrete::FheUint8.decrypt#1/output/u8/u8/[concrete::ClientKey]/high/params=none",
	"concrete::FheUint8.encrypt#2/operation/concrete::FheUint8/concrete::FheUint8/[u8,concrete::ClientKey]/high/params=none",
	"concrete::FheUint8.try_encrypt#2/operation/core::result::Result/core::result::Result<concrete::FheUint8, concrete::OutOfRangeError>/[u8,concrete::ClientKey]/high/params=none",
	"concrete::LWE.bootstrap#1/operation/core::result::Result/core::result::Result<concrete::LWE, concrete::CryptoAPIError>/[concrete::LWEBSK]/high/params=none",
	"concrete::LWE.bootstrap_with_function#3/operation/core::result::Result/core::result::Result<concrete::LWE, concrete::CryptoAPIError>/[concrete::LWEBSK,F,concrete::Encoder]/high/params=none",
	"concrete::LWE.decrypt_decode#1/output/core::result::Result/core::result::Result<f64, concrete::CryptoAPIError>/[concrete::LWESecretKey]/high/params=none",
	"concrete::LWE.decrypt_decode_round#1/output/core::result::Result/core::result::Result<f64, concrete::CryptoAPIError>/[concrete::LWESecretKey]/high/params=none",
	"concrete::LWE.encode_encrypt#3/operation/core::result::Result/core::result::Result<concrete::LWE, concrete::CryptoAPIError>/[concrete::LWESecretKey,f64,concrete::Encoder]/high/params=none",
	"concrete::LWE.encrypt_raw#2/operation/core::result::Result/core::result::Result<(), concrete::CryptoAPIError>/[concrete::LWESecretKey,concrete::Torus]/high/params=none",
	"concrete::LWE.keyswitch#1/operation/core::result::Result/core::result::Result<concrete::LWE, concrete::CryptoAPIError>/[concrete::LWEKSK]/high/params=none",
	"concrete::LWE.mul_from_bootstrap#2/operation/core::result::Result/core::result::Result<concrete::LWE, concrete::CryptoAPIError>/[concrete::LWE,concrete::LWEBSK]/high/params=none",
	"concrete::LWE.zero#1/factory/core::result::Result/core::result::Result<concrete::LWE, concrete::CryptoAPIError>/[usize]/high/params=none",
	"concrete::LWEBSK.new#4/factory/concrete::LWEBSK/concrete::LWEBSK/[concrete::LWESecretKey,concrete::RLWESecretKey,usize,usize]/high/params=none",
	"concrete::LWEKSK.new#4/factory/concrete::LWEKSK/concrete::LWEKSK/[concrete::LWESecretKey,concrete::LWESecretKey,usize,usize]/high/params=none",
	"concrete::LWESecretKey.new#1/factory/concrete::LWESecretKey/concrete::LWESecretKey/[concrete::LWEParams]/high/params=none",
	"concrete::LWESecretKey.new_raw#2/factory/concrete::LWESecretKey/concrete::LWESecretKey/[usize,f64]/high/params=none",
	"concrete::Plaintext.encode#2/factory/core::result::Result/core::result::Result<concrete::Plaintext, concrete::CryptoAPIError>/[&[f64],concrete::Encoder]/high/params=none",
	"concrete::RLWESecretKey.new#1/factory/concrete::RLWESecretKey/concrete::RLWESecretKey/[concrete::RLWEParams]/high/params=none",
	"concrete::RLWESecretKey.new_raw#3/factory/concrete::RLWESecretKey/concrete::RLWESecretKey/[usize,usize,f64]/high/params=none",
	"concrete::VectorLWE.bootstrap_nth#2/operation/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[concrete::LWEBSK,usize]/high/params=none",
	"concrete::VectorLWE.bootstrap_nth_with_function#4/operation/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[concrete::LWEBSK,F,concrete::Encoder,usize]/high/params=none",
	"concrete::VectorLWE.decrypt_decode#1/output/core::result::Result/core::result::Result<alloc::vec::Vec<f64>, concrete::CryptoAPIError>/[concrete::LWESecretKey]/high/params=none",
	"concrete::VectorLWE.decrypt_decode_round#1/output/core::result::Result/core::result::Result<alloc::vec::Vec<f64>, concrete::CryptoAPIError>/[concrete::LWESecretKey]/high/params=none",
	"concrete::VectorLWE.decrypt_raw#1/output/core::result::Result/core::result::Result<alloc::vec::Vec<u64>, concrete::CryptoAPIError>/[concrete::LWESecretKey]/high/params=none",
	"concrete::VectorLWE.encode_encrypt#3/operation/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[concrete::LWESecretKey,&[f64],concrete::Encoder]/high/params=none",
	"concrete::VectorLWE.encode_encrypt_several_encoders#3/operation/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[concrete::LWESecretKey,&[f64],&[concrete::Encoder]]/high/params=none",
	"concrete::VectorLWE.encrypt#2/operation/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[concrete::LWESecretKey,concrete::Plaintext]/high/params=none",
	"concrete::VectorLWE.encrypt_inplace#2/operation/core::result::Result/core::result::Result<(), concrete::CryptoAPIError>/[concrete::LWESecretKey,concrete::Plaintext]/high/params=none",
	"concrete::VectorLWE.encrypt_raw#2/operation/core::result::Result/core::result::Result<(), concrete::CryptoAPIError>/[concrete::LWESecretKey,&[concrete::Torus]]/high/params=none",
	"concrete::VectorLWE.keyswitch#1/operation/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[concrete::LWEKSK]/high/params=none",
	"concrete::VectorLWE.mul_from_bootstrap_nth#4/operation/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[concrete::VectorLWE,concrete::LWEBSK,usize,usize]/high/params=none",
	"concrete::VectorLWE.zero#2/factory/core::result::Result/core::result::Result<concrete::VectorLWE, concrete::CryptoAPIError>/[usize,usize]/high/params=none",
	"concrete::VectorRLWE.decrypt_decode#1/output/core::result::Result/core::result::Result<alloc::vec::Vec<f64>, concrete::CryptoAPIError>/[concrete::RLWESecretKey]/high/params=none",
	"concrete::VectorRLWE.decrypt_decode_round#1/output/core::result::Result/core::result::Result<alloc::vec::Vec<f64>, concrete::CryptoAPIError>/[concrete::RLWESecretKey]/high/params=none",
	"concrete::VectorRLWE.decrypt_with_encoders#1/output/core::result::Result/core::result::Result<(alloc::vec::Vec<f64>, alloc::vec::Vec<concrete::Encoder>), concrete::CryptoAPIError>/[concrete::RLWESecretKey]/high/params=none",
	"concrete::VectorRLWE.encode_encrypt#3/operation/core::result::Result/core::result::Result<concrete::VectorRLWE, concrete::CryptoAPIError>/[concrete::RLWESecretKey,&[f64],concrete::Encoder]/high/params=none",
	"concrete::VectorRLWE.encode_encrypt_packed#3/operation/core::result::Result/core::result::Result<concrete::VectorRLWE, concrete::CryptoAPIError>/[concrete::RLWESecretKey,&[f64],concrete::Encoder]/high/params=none",
	"concrete::VectorRLWE.encrypt#2/operation/core::result::Result/core::result::Result<concrete::VectorRLWE, concrete::CryptoAPIError>/[concrete::RLWESecretKey,concrete::Plaintext]/high/params=none",
	"concrete::VectorRLWE.encrypt_packed#2/operation/core::result::Result/core::result::Result<concrete::VectorRLWE, concrete::CryptoAPIError>/[concrete::RLWESecretKey,concrete::Plaintext]/high/params=none",
	"concrete::VectorRLWE.encrypt_packed_raw#2/operation/core::result::Result/core::result::Result<(), concrete::CryptoAPIError>/[concrete::RLWESecretKey,&[concrete::Torus]]/high/params=none",
	"concrete::VectorRLWE.zero#3/factory/core::result::Result/core::result::Result<concrete::VectorRLWE, concrete::CryptoAPIError>/[usize,usize,usize]/high/params=none",
	"concrete::client::ClientFunction.new_encrypted#3/factory/concrete::client::ClientFunction/cxx::UniquePtr<concrete::client::ClientFunction>/[concrete::protocol::CircuitInfo,concrete::common::ClientKeyset,concrete::common::EncryptionCsprng]/high/params=none",
	"concrete::client::ClientFunction.prepare_input#2/operation/concrete::common::TransportValue/cxx::UniquePtr<concrete::common::TransportValue>/[concrete::common::Value,usize]/high/params=none",
	"concrete::client::ClientFunction.prepare_input#3/operation/concrete::common::TransportValue/cxx::UniquePtr<concrete::common::TransportValue>/[core::pin::Pin<&mut concrete::client::ClientFunction>,concrete::common::Value,usize]/high/params=none",
	"concrete::client::ClientFunction.process_output#2/output/concrete::common::Value/cxx::UniquePtr<concrete::common::Value>/[concrete::common::TransportValue,usize]/high/params=none",
	"concrete::client::ClientFunction.process_output#3/output/concrete::common::Value/cxx::UniquePtr<concrete::common::Value>/[core::pin::Pin<&mut concrete::client::ClientFunction>,concrete::common::TransportValue,usize]/high/params=none",
	"concrete::client::ClientModule.new_encrypted#3/factory/concrete::client::ClientModule/cxx::UniquePtr<concrete::client::ClientModule>/[concrete::protocol::ProgramInfo,concrete::common::ClientKeyset,concrete::common::EncryptionCsprng]/high/params=none",
	"concrete::common::EncryptionCsprng.new#1/factory/concrete::common::EncryptionCsprng/cxx::UniquePtr<concrete::common::EncryptionCsprng>/[u128]/high/params=none",
	"concrete::common::Keyset.get_client#0/factory/concrete::common::ClientKeyset/cxx::UniquePtr<concrete::common::ClientKeyset>/[]/high/params=none",
	"concrete::common::Keyset.get_server#0/factory/concrete::common::ServerKeyset/cxx::UniquePtr<concrete::common::ServerKeyset>/[]/high/params=none",
	"concrete::common::Keyset.new#3/factory/concrete::common::Keyset/cxx::UniquePtr<concrete::common::Keyset>/[concrete::protocol::KeysetInfo,concrete::common::SecretCsprng,concrete::common::EncryptionCsprng]/high/params=none",
	"concrete::common::Keyset.new#4/factory/concrete::common::Keyset/cxx::UniquePtr<concrete::common::Keyset>/[concrete::protocol::KeysetInfo,concrete::common::SecretCsprng,concrete::common::EncryptionCsprng,alloc::vec::Vec<concrete::common::LweSecretKey>]/high/params=none",
	"concrete::common::SecretCsprng.new#1/factory/concrete::common::SecretCsprng/cxx::UniquePtr<concrete::common::SecretCsprng>/[u128]/high/params=none",
	"concrete::crypto_api::LWE.encode_encrypt#3/operation/core::result::Result/core::result::Result<concrete::crypto_api::LWE, concrete::CryptoAPIError>/[concrete::crypto_api::LWESecretKey,f64,concrete::crypto_api::Encoder]/high/params=none",
	"concrete::crypto_api::LWEBSK.new#4/factory/concrete::crypto_api::LWEBSK/concrete::crypto_api::LWEBSK/[concrete::crypto_api::LWESecretKey,concrete::crypto_api::RLWESecretKey,usize,usize]/high/params=none",
	"concrete::crypto_api::LWEKSK.new#4/factory/concrete::crypto_api::LWEKSK/concrete::crypto_api::LWEKSK/[concrete::crypto_api::LWESecretKey,concrete::crypto_api::LWESecretKey,usize,usize]/high/params=none",
	"concrete::crypto_api::LWESecretKey.new#1/factory/concrete::crypto_api::LWESecretKey/concrete::crypto_api::LWESecretKey/[concrete::crypto_api::LWEParams]/high/params=none",
	"concrete::crypto_api::LWESecretKey.new_raw#2/factory/concrete::crypto_api::LWESecretKey/concrete::crypto_api::LWESecretKey/[usize,f64]/high/params=none",
	"concrete::crypto_api::RLWESecretKey.new#1/factory/concrete::crypto_api::RLWESecretKey/concrete::crypto_api::RLWESecretKey/[concrete::crypto_api::RLWEParams]/high/params=none",
	"concrete::crypto_api::RLWESecretKey.new_raw#3/factory/concrete::crypto_api::RLWESecretKey/concrete::crypto_api::RLWESecretKey/[usize,usize,f64]/high/params=none",
	"concrete::crypto_api::VectorLWE.encode_encrypt#3/operation/core::result::Result/core::result::Result<concrete::crypto_api::VectorLWE, concrete::CryptoAPIError>/[concrete::crypto_api::LWESecretKey,&[f64],concrete::crypto_api::Encoder]/high/params=none",
	"concrete::crypto_api::VectorLWE.encode_encrypt_several_encoders#3/operation/core::result::Result/core::result::Result<concrete::crypto_api::VectorLWE, concrete::CryptoAPIError>/[concrete::crypto_api::LWESecretKey,&[f64],&[concrete::crypto_api::Encoder]]/high/params=none",
	"concrete::crypto_api::VectorLWE.encrypt#2/operation/core::result::Result/core::result::Result<concrete::crypto_api::VectorLWE, concrete::CryptoAPIError>/[concrete::crypto_api::LWESecretKey,concrete::crypto_api::Plaintext]/high/params=none",
	"concrete::crypto_api::VectorRLWE.encode_encrypt#3/operation/core::result::Result/core::result::Result<concrete::crypto_api::VectorRLWE, concrete::CryptoAPIError>/[concrete::crypto_api::RLWESecretKey,&[f64],concrete::crypto_api::Encoder]/high/params=none",
	"concrete::crypto_api::VectorRLWE.encode_encrypt_packed#3/operation/core::result::Result/core::result::Result<concrete::crypto_api::VectorRLWE, concrete::CryptoAPIError>/[concrete::crypto_api::RLWESecretKey,&[f64],concrete::crypto_api::Encoder]/high/params=none",
	"concrete::crypto_api::VectorRLWE.encrypt#2/operation/core::result::Result/core::result::Result<concrete::crypto_api::VectorRLWE, concrete::CryptoAPIError>/[concrete::crypto_api::RLWESecretKey,concrete::crypto_api::Plaintext]/high/params=none",
	"concrete::crypto_api::VectorRLWE.encrypt_packed#2/operation/core::result::Result/core::result::Result<concrete::crypto_api::VectorRLWE, concrete::CryptoAPIError>/[concrete::crypto_api::RLWESecretKey,concrete::crypto_api::Plaintext]/high/params=none",
	"concrete::server::ServerFunction.call#2/operation/alloc::vec::Vec<concrete::common::TransportValue>/alloc::vec::Vec<cxx::UniquePtr<concrete::common::TransportValue>>/[concrete::common::ServerKeyset,alloc::vec::Vec<concrete::common::TransportValue>]/high/params=none",
	"concrete::server::ServerFunction.call#3/operation/alloc::vec::Vec<concrete::common::TransportValue>/alloc::vec::Vec<cxx::UniquePtr<concrete::common::TransportValue>>/[core::pin::Pin<&mut concrete::server::ServerFunction>,concrete::common::ServerKeyset,alloc::vec::Vec<concrete::common::TransportValue>]/high/params=none",
	"concrete::server::ServerFunction.new#3/factory/concrete::server::ServerFunction/cxx::UniquePtr<concrete::server::ServerFunction>/[concrete::protocol::CircuitInfo,*mut concrete::c_void,bool]/high/params=none",
}

func TestLoadEmbeddedRustConcreteContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderConcreteContracts(t)
	want := append([]string(nil), wantConcreteContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("concrete contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected concrete contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing concrete contract:    %s", w)
		}
	}
}

// The library block is part of what this file declares and nothing else asserts
// it. A corrupted version_range, coordinate list, name or description loads
// cleanly and would pass a contracts-only comparison. Read from the single file
// rather than the merged KB, because Merge() drops per-library metadata.
func TestLoadRustConcreteLibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("rust/concrete.yaml")
	if err != nil {
		t.Fatalf("read concrete.yaml: %v", err)
	}
	single, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(concrete.yaml): %v", err)
	}
	if single.Library == nil {
		t.Fatal("concrete.yaml declares no library: block")
	}
	lib := single.Library

	if lib.Name != "concrete" {
		t.Errorf("library name: got %q, want %q", lib.Name, "concrete")
	}
	// 0.1.0, 0.1.1 and 0.1.2 are a different project under the same crate name
	// ("A prototype computer language", GPL-3.0-or-later) with no API to type;
	// Zama's FHE library starts at 0.1.4. The upper bound admits 2.10.1-rc1 and
	// 2.11.0, the compiler-bindings era.
	if lib.VersionRange != ">=0.1.4,<3.0.0" {
		t.Errorf("version_range = %q, want %q -- the range must cover only versions "+
			"for which every declared signature is true",
			lib.VersionRange, ">=0.1.4,<3.0.0")
	}
	if len(lib.Coordinates) != 1 || lib.Coordinates[0] != "concrete" {
		t.Errorf("coordinates: got %v, want [concrete]", lib.Coordinates)
	}
	if lib.Description != "Concrete: Zama's TFHE library and FHE compiler" {
		t.Errorf("description: got %q", lib.Description)
	}
	if single.Ecosystem != "rust" {
		t.Errorf("ecosystem: got %q, want rust", single.Ecosystem)
	}
	if single.SchemaVersion != "2" {
		t.Errorf("schema_version: got %q, want 2", single.SchemaVersion)
	}
}

// The keys above are the AUTHORED spelling. What the parser looks up is the
// dot-joined spelling the call graph emits, and rustAuthoredKey bridges the two.
// Every key below was read off an exported call graph of a probe consumer that
// calls all three eras the way the crate's own sources show.
func TestRustConcreteEmittedKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	cases := []struct {
		emitted string
		arity   int
		want    string
	}{
		// Era 1, crate-root spelling.
		{"concrete.LWESecretKey.new", 1, "concrete::LWESecretKey"},
		{"concrete.LWE.encode_encrypt", 3, "core::result::Result"},
		{"concrete.LWE.decrypt_decode", 1, "core::result::Result"},
		{"concrete.LWE.bootstrap", 1, "core::result::Result"},
		{"concrete.LWE.keyswitch", 1, "core::result::Result"},
		{"concrete.VectorLWE.decrypt_raw", 1, "core::result::Result"},
		{"concrete.VectorRLWE.decrypt_with_encoders", 1, "core::result::Result"},
		{"concrete.LWEBSK.new", 4, "concrete::LWEBSK"},
		// Era 1, the 0.1.4-0.1.5 crypto_api module spelling.
		{"concrete::crypto_api.LWESecretKey.new", 1, "concrete::crypto_api::LWESecretKey"},
		{"concrete::crypto_api.LWE.encode_encrypt", 3, "core::result::Result"},
		// Era 2. The free functions carry one dot and resolve unchanged.
		{"concrete.generate_keys", 1, "(concrete::ClientKey, concrete::ServerKey)"},
		{"concrete.set_server_key", 1, "()"},
		{"concrete.ClientKey.generate", 1, "concrete::ClientKey"},
		{"concrete.ClientKey.generate_server_key", 0, "concrete::ServerKey"},
		{"concrete.FheUint8.encrypt", 2, "concrete::FheUint8"},
		{"concrete.FheUint12.try_encrypt", 2, "core::result::Result"},
		{"concrete.FheBool.decrypt", 1, "bool"},
		{"concrete.FheUint4.try_encrypt_trivial", 1, "core::result::Result"},
		{"concrete.FheUint3.bivariate_pbs", 2, "concrete::FheUint3"},
		{"concrete.FheUint8.bivariate_function", 2, "concrete::FheUint8"},
		{"concrete::crypto_api.VectorLWE.encode_encrypt_several_encoders", 3, "core::result::Result"},
		// Era 3, module-qualified. Keyset::new takes three arguments in
		// 2.10.1-rc1 and four in 2.11.0.
		{"concrete::common.Keyset.new", 3, "concrete::common::Keyset"},
		{"concrete::common.Keyset.new", 4, "concrete::common::Keyset"},
		{"concrete::client.ClientFunction.new_encrypted", 3, "concrete::client::ClientFunction"},
		{"concrete::client.ClientFunction.prepare_input", 2, "concrete::common::TransportValue"},
		{"concrete::client.ClientFunction.process_output", 2, "concrete::common::Value"},
		{"concrete::server.ServerFunction.call", 2, "alloc::vec::Vec<concrete::common::TransportValue>"},
		// The explicit-self path form a UniquePtr holder writes.
		{"concrete::server.ServerFunction.call", 3, "alloc::vec::Vec<concrete::common::TransportValue>"},
	}

	for _, tc := range cases {
		ctrs := kb.ContractsFor(tc.emitted, tc.arity)
		if len(ctrs) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract; the emitted key does not resolve", tc.emitted, tc.arity)
			continue
		}
		if ctrs[0].Return.Type != tc.want {
			t.Errorf("ContractsFor(%q, %d): return %q, want %q", tc.emitted, tc.arity, ctrs[0].Return.Type, tc.want)
		}
	}
}
