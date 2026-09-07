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

// ml-kem (RustCrypto, FIPS 203) publishes THREE distinct call-site key shapes
// for the same operations, and all three are declared, because all three are
// spellings real published consumers write:
//
//	use ml_kem::MlKem768;  MlKem768::generate(..)
//	    -> ml_kem.MlKem768.generate                     (authored ml_kem::MlKem768.generate)
//	ml_kem::ml_kem_768::MlKem768::generate_keypair()
//	    -> ml_kem::ml_kem_768.MlKem768.generate_keypair (authored ...::MlKem768.generate_keypair)
//	DecapsulationKey::<MlKem768>::from_seed(..)
//	    -> ml_kem.DecapsulationKey.from_seed            (the TYPE ARGUMENT does not reach the key)
//
// Every key below was read off `crypto-finder scan --export-callgraph` for a
// probe consumer, not written from the API, and then had its second-to-last dot
// rewritten to `::` (rustAuthoredKey, contracts.go:267).
//
// The set is compared EXACTLY, not per key, and it renders the `parameters:`
// block as well as the scalar fields.
//
// IT ALSO RENDERS `Varargs`, which most of this directory does not, and that is
// deliberate: the field is parsed and defaults to false, so a `varargs: true`
// slipped onto any entry here loads cleanly and survives an otherwise-exact
// comparison. No ml-kem entry is variadic -- Rust has no variadic methods on
// these types -- so the rendered value is `v=false` throughout, and the
// mutation battery includes flipping one to prove the assertion bites.

// renderMlKemContracts renders every loaded ml-kem contract as one
// deterministic line, sorted.
func renderMlKemContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "ml-kem" {
				continue
			}
			params := make([]string, 0, len(c.Parameters))
			for _, p := range c.Parameters {
				idx := "-"
				if p.Index != nil {
					idx = fmt.Sprintf("%d", *p.Index)
				}
				contributes := "-"
				if p.Contributes != nil {
					contributes = p.Contributes.Property + ":" + p.Contributes.Derivation
				}
				params = append(params, fmt.Sprintf("%s=%s:%s:%s", idx, p.Name, p.Role, contributes))
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/{%s}/v=%t",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				strings.Join(params, ";"), c.Varargs))
		}
	}
	sort.Strings(got)
	return got
}

// TWO ENTRIES CARRY `confidence: low` AND THAT IS LOAD-BEARING.
// `decapsulate#1` returns `Result<SharedKey, Error>` in the KemCore era and a
// bare `SharedKey` from 0.3.0-pre.4 on; `encapsulate_deterministic#1` moved the
// same way. Divergent returns on ONE (method, arity) key are a hard load error
// (contracts.go:936-968, Rule 2), so each is declared ONCE, naming the current
// era with low confidence. `encapsulate` needs no such treatment: era 1 takes
// an rng (arity 1) and era 2 takes nothing (arity 0).
var wantMlKemContracts = []string{
	"ml_kem::DecapsulationKey.decapsulate#1/operation/ml_kem::SharedKey/ml_kem::SharedKey/[&ml_kem::Ciphertext]/low/{}/v=false",
	"ml_kem::DecapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::DecapsulationKey, ml_kem::InvalidKey>/ml_kem::DecapsulationKey/[&ml_kem::param::ExpandedDecapsulationKey]/high/{}/v=false",
	"ml_kem::DecapsulationKey.from_seed#1/factory/ml_kem::DecapsulationKey/ml_kem::DecapsulationKey/[ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey.generate_from_rng#1/factory/ml_kem::DecapsulationKey/ml_kem::DecapsulationKey/[&mut R]/high/{}/v=false",
	"ml_kem::DecapsulationKey.new#1/factory/ml_kem::DecapsulationKey/ml_kem::DecapsulationKey/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey.try_decapsulate#1/operation/Result<ml_kem::SharedKey, ml_kem::InvalidKey>/ml_kem::SharedKey/[&ml_kem::Ciphertext]/high/{}/v=false",
	"ml_kem::DecapsulationKey1024.decapsulate#1/operation/ml_kem::SharedKey/ml_kem::SharedKey/[&ml_kem::ml_kem_1024::Ciphertext]/low/{}/v=false",
	"ml_kem::DecapsulationKey1024.encapsulation_key#0/output/&ml_kem::EncapsulationKey1024/&ml_kem::EncapsulationKey1024/[]/high/{}/v=false",
	"ml_kem::DecapsulationKey1024.from_encoded_bytes#1/factory/Result<ml_kem::DecapsulationKey1024, ml_kem::InvalidKey>/ml_kem::DecapsulationKey1024/[&ml_kem::param::ExpandedDecapsulationKey]/high/{}/v=false",
	"ml_kem::DecapsulationKey1024.from_seed#1/factory/ml_kem::DecapsulationKey1024/ml_kem::DecapsulationKey1024/[ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey1024.generate_from_rng#1/factory/ml_kem::DecapsulationKey1024/ml_kem::DecapsulationKey1024/[&mut R]/high/{}/v=false",
	"ml_kem::DecapsulationKey1024.new#1/factory/ml_kem::DecapsulationKey1024/ml_kem::DecapsulationKey1024/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey1024.try_decapsulate#1/operation/Result<ml_kem::SharedKey, ml_kem::InvalidKey>/ml_kem::SharedKey/[&ml_kem::ml_kem_1024::Ciphertext]/high/{}/v=false",
	"ml_kem::DecapsulationKey512.decapsulate#1/operation/ml_kem::SharedKey/ml_kem::SharedKey/[&ml_kem::ml_kem_512::Ciphertext]/low/{}/v=false",
	"ml_kem::DecapsulationKey512.encapsulation_key#0/output/&ml_kem::EncapsulationKey512/&ml_kem::EncapsulationKey512/[]/high/{}/v=false",
	"ml_kem::DecapsulationKey512.from_encoded_bytes#1/factory/Result<ml_kem::DecapsulationKey512, ml_kem::InvalidKey>/ml_kem::DecapsulationKey512/[&ml_kem::param::ExpandedDecapsulationKey]/high/{}/v=false",
	"ml_kem::DecapsulationKey512.from_seed#1/factory/ml_kem::DecapsulationKey512/ml_kem::DecapsulationKey512/[ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey512.generate_from_rng#1/factory/ml_kem::DecapsulationKey512/ml_kem::DecapsulationKey512/[&mut R]/high/{}/v=false",
	"ml_kem::DecapsulationKey512.new#1/factory/ml_kem::DecapsulationKey512/ml_kem::DecapsulationKey512/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey512.try_decapsulate#1/operation/Result<ml_kem::SharedKey, ml_kem::InvalidKey>/ml_kem::SharedKey/[&ml_kem::ml_kem_512::Ciphertext]/high/{}/v=false",
	"ml_kem::DecapsulationKey768.decapsulate#1/operation/ml_kem::SharedKey/ml_kem::SharedKey/[&ml_kem::ml_kem_768::Ciphertext]/low/{}/v=false",
	"ml_kem::DecapsulationKey768.encapsulation_key#0/output/&ml_kem::EncapsulationKey768/&ml_kem::EncapsulationKey768/[]/high/{}/v=false",
	"ml_kem::DecapsulationKey768.from_encoded_bytes#1/factory/Result<ml_kem::DecapsulationKey768, ml_kem::InvalidKey>/ml_kem::DecapsulationKey768/[&ml_kem::param::ExpandedDecapsulationKey]/high/{}/v=false",
	"ml_kem::DecapsulationKey768.from_seed#1/factory/ml_kem::DecapsulationKey768/ml_kem::DecapsulationKey768/[ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey768.generate_from_rng#1/factory/ml_kem::DecapsulationKey768/ml_kem::DecapsulationKey768/[&mut R]/high/{}/v=false",
	"ml_kem::DecapsulationKey768.new#1/factory/ml_kem::DecapsulationKey768/ml_kem::DecapsulationKey768/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::DecapsulationKey768.try_decapsulate#1/operation/Result<ml_kem::SharedKey, ml_kem::InvalidKey>/ml_kem::SharedKey/[&ml_kem::ml_kem_768::Ciphertext]/high/{}/v=false",
	"ml_kem::EncapsulationKey.encapsulate#0/operation/(ml_kem::Ciphertext, ml_kem::SharedKey)/(ml_kem::Ciphertext, ml_kem::SharedKey)/[]/high/{}/v=false",
	"ml_kem::EncapsulationKey.encapsulate#1/operation/Result<(ml_kem::Ciphertext, ml_kem::SharedKey), ()>/(ml_kem::Ciphertext, ml_kem::SharedKey)/[&mut impl rand_core::CryptoRngCore]/high/{}/v=false",
	"ml_kem::EncapsulationKey.encapsulate_deterministic#1/operation/(ml_kem::Ciphertext, ml_kem::SharedKey)/(ml_kem::Ciphertext, ml_kem::SharedKey)/[&ml_kem::B32]/low/{}/v=false",
	"ml_kem::EncapsulationKey.encapsulate_with_rng#1/operation/(ml_kem::Ciphertext, ml_kem::SharedKey)/(ml_kem::Ciphertext, ml_kem::SharedKey)/[&mut R]/low/{}/v=false",
	"ml_kem::EncapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::EncapsulationKey, ml_kem::InvalidKey>/ml_kem::EncapsulationKey/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::EncapsulationKey.new#1/factory/Result<ml_kem::EncapsulationKey, ml_kem::InvalidKey>/ml_kem::EncapsulationKey/[&ml_kem::kem::Key]/high/{}/v=false",
	"ml_kem::EncapsulationKey1024.encapsulate#0/operation/(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey)/[]/high/{}/v=false",
	"ml_kem::EncapsulationKey1024.encapsulate#1/operation/Result<(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey), ()>/(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey)/[&mut impl rand_core::CryptoRngCore]/high/{}/v=false",
	"ml_kem::EncapsulationKey1024.encapsulate_deterministic#1/operation/(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey)/[&ml_kem::B32]/low/{}/v=false",
	"ml_kem::EncapsulationKey1024.encapsulate_with_rng#1/operation/(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_1024::Ciphertext, ml_kem::SharedKey)/[&mut R]/low/{}/v=false",
	"ml_kem::EncapsulationKey1024.from_encoded_bytes#1/factory/Result<ml_kem::EncapsulationKey1024, ml_kem::InvalidKey>/ml_kem::EncapsulationKey1024/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::EncapsulationKey1024.new#1/factory/Result<ml_kem::EncapsulationKey1024, ml_kem::InvalidKey>/ml_kem::EncapsulationKey1024/[&ml_kem::kem::Key]/high/{}/v=false",
	"ml_kem::EncapsulationKey512.encapsulate#0/operation/(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey)/[]/high/{}/v=false",
	"ml_kem::EncapsulationKey512.encapsulate#1/operation/Result<(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey), ()>/(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey)/[&mut impl rand_core::CryptoRngCore]/high/{}/v=false",
	"ml_kem::EncapsulationKey512.encapsulate_deterministic#1/operation/(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey)/[&ml_kem::B32]/low/{}/v=false",
	"ml_kem::EncapsulationKey512.encapsulate_with_rng#1/operation/(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_512::Ciphertext, ml_kem::SharedKey)/[&mut R]/low/{}/v=false",
	"ml_kem::EncapsulationKey512.from_encoded_bytes#1/factory/Result<ml_kem::EncapsulationKey512, ml_kem::InvalidKey>/ml_kem::EncapsulationKey512/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::EncapsulationKey512.new#1/factory/Result<ml_kem::EncapsulationKey512, ml_kem::InvalidKey>/ml_kem::EncapsulationKey512/[&ml_kem::kem::Key]/high/{}/v=false",
	"ml_kem::EncapsulationKey768.encapsulate#0/operation/(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey)/[]/high/{}/v=false",
	"ml_kem::EncapsulationKey768.encapsulate#1/operation/Result<(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey), ()>/(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey)/[&mut impl rand_core::CryptoRngCore]/high/{}/v=false",
	"ml_kem::EncapsulationKey768.encapsulate_deterministic#1/operation/(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey)/[&ml_kem::B32]/low/{}/v=false",
	"ml_kem::EncapsulationKey768.encapsulate_with_rng#1/operation/(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey)/(ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey)/[&mut R]/low/{}/v=false",
	"ml_kem::EncapsulationKey768.from_encoded_bytes#1/factory/Result<ml_kem::EncapsulationKey768, ml_kem::InvalidKey>/ml_kem::EncapsulationKey768/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::EncapsulationKey768.new#1/factory/Result<ml_kem::EncapsulationKey768, ml_kem::InvalidKey>/ml_kem::EncapsulationKey768/[&ml_kem::kem::Key]/high/{}/v=false",
	"ml_kem::MlKem1024.from_seed#1/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::MlKem1024.generate#1/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[&mut impl rand_core::CryptoRngCore]/high/{}/v=false",
	"ml_kem::MlKem1024.generate_deterministic#2/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[&ml_kem::B32,&ml_kem::B32]/high/{}/v=false",
	"ml_kem::MlKem1024.generate_keypair#0/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[]/high/{}/v=false",
	"ml_kem::MlKem1024.generate_keypair_from_rng#1/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[&mut R]/high/{}/v=false",
	"ml_kem::MlKem512.from_seed#1/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::MlKem512.generate#1/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[&mut impl rand_core::CryptoRngCore]/high/{}/v=false",
	"ml_kem::MlKem512.generate_deterministic#2/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[&ml_kem::B32,&ml_kem::B32]/high/{}/v=false",
	"ml_kem::MlKem512.generate_keypair#0/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[]/high/{}/v=false",
	"ml_kem::MlKem512.generate_keypair_from_rng#1/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[&mut R]/high/{}/v=false",
	"ml_kem::MlKem768.from_seed#1/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::MlKem768.generate#1/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[&mut impl rand_core::CryptoRngCore]/high/{}/v=false",
	"ml_kem::MlKem768.generate_deterministic#2/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[&ml_kem::B32,&ml_kem::B32]/high/{}/v=false",
	"ml_kem::MlKem768.generate_keypair#0/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[]/high/{}/v=false",
	"ml_kem::MlKem768.generate_keypair_from_rng#1/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[&mut R]/high/{}/v=false",
	"ml_kem::kem::DecapsulationKey.from_bytes#1/factory/Result<ml_kem::kem::DecapsulationKey, ml_kem::Error>/ml_kem::kem::DecapsulationKey/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::kem::EncapsulationKey.from_bytes#1/factory/Result<ml_kem::kem::EncapsulationKey, ml_kem::Error>/ml_kem::kem::EncapsulationKey/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_1024::DecapsulationKey.from_bytes#1/factory/Result<ml_kem::DecapsulationKey1024, ml_kem::Error>/ml_kem::DecapsulationKey1024/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_1024::DecapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::DecapsulationKey1024, ml_kem::InvalidKey>/ml_kem::DecapsulationKey1024/[&ml_kem::param::ExpandedDecapsulationKey]/high/{}/v=false",
	"ml_kem::ml_kem_1024::DecapsulationKey.from_seed#1/factory/ml_kem::DecapsulationKey1024/ml_kem::DecapsulationKey1024/[ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_1024::DecapsulationKey.generate_from_rng#1/factory/ml_kem::DecapsulationKey1024/ml_kem::DecapsulationKey1024/[&mut R]/high/{}/v=false",
	"ml_kem::ml_kem_1024::DecapsulationKey.new#1/factory/ml_kem::DecapsulationKey1024/ml_kem::DecapsulationKey1024/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_1024::EncapsulationKey.from_bytes#1/factory/Result<ml_kem::EncapsulationKey1024, ml_kem::Error>/ml_kem::EncapsulationKey1024/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_1024::EncapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::EncapsulationKey1024, ml_kem::InvalidKey>/ml_kem::EncapsulationKey1024/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_1024::EncapsulationKey.new#1/factory/Result<ml_kem::EncapsulationKey1024, ml_kem::InvalidKey>/ml_kem::EncapsulationKey1024/[&ml_kem::kem::Key]/high/{}/v=false",
	"ml_kem::ml_kem_1024::MlKem1024.from_seed#1/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_1024::MlKem1024.generate_keypair#0/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[]/high/{}/v=false",
	"ml_kem::ml_kem_1024::MlKem1024.generate_keypair_from_rng#1/factory/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/(ml_kem::DecapsulationKey1024, ml_kem::EncapsulationKey1024)/[&mut R]/high/{}/v=false",
	"ml_kem::ml_kem_512::DecapsulationKey.from_bytes#1/factory/Result<ml_kem::DecapsulationKey512, ml_kem::Error>/ml_kem::DecapsulationKey512/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_512::DecapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::DecapsulationKey512, ml_kem::InvalidKey>/ml_kem::DecapsulationKey512/[&ml_kem::param::ExpandedDecapsulationKey]/high/{}/v=false",
	"ml_kem::ml_kem_512::DecapsulationKey.from_seed#1/factory/ml_kem::DecapsulationKey512/ml_kem::DecapsulationKey512/[ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_512::DecapsulationKey.generate_from_rng#1/factory/ml_kem::DecapsulationKey512/ml_kem::DecapsulationKey512/[&mut R]/high/{}/v=false",
	"ml_kem::ml_kem_512::DecapsulationKey.new#1/factory/ml_kem::DecapsulationKey512/ml_kem::DecapsulationKey512/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_512::EncapsulationKey.from_bytes#1/factory/Result<ml_kem::EncapsulationKey512, ml_kem::Error>/ml_kem::EncapsulationKey512/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_512::EncapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::EncapsulationKey512, ml_kem::InvalidKey>/ml_kem::EncapsulationKey512/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_512::EncapsulationKey.new#1/factory/Result<ml_kem::EncapsulationKey512, ml_kem::InvalidKey>/ml_kem::EncapsulationKey512/[&ml_kem::kem::Key]/high/{}/v=false",
	"ml_kem::ml_kem_512::MlKem512.from_seed#1/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_512::MlKem512.generate_keypair#0/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[]/high/{}/v=false",
	"ml_kem::ml_kem_512::MlKem512.generate_keypair_from_rng#1/factory/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/(ml_kem::DecapsulationKey512, ml_kem::EncapsulationKey512)/[&mut R]/high/{}/v=false",
	"ml_kem::ml_kem_768::DecapsulationKey.from_bytes#1/factory/Result<ml_kem::DecapsulationKey768, ml_kem::Error>/ml_kem::DecapsulationKey768/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_768::DecapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::DecapsulationKey768, ml_kem::InvalidKey>/ml_kem::DecapsulationKey768/[&ml_kem::param::ExpandedDecapsulationKey]/high/{}/v=false",
	"ml_kem::ml_kem_768::DecapsulationKey.from_seed#1/factory/ml_kem::DecapsulationKey768/ml_kem::DecapsulationKey768/[ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_768::DecapsulationKey.generate_from_rng#1/factory/ml_kem::DecapsulationKey768/ml_kem::DecapsulationKey768/[&mut R]/high/{}/v=false",
	"ml_kem::ml_kem_768::DecapsulationKey.new#1/factory/ml_kem::DecapsulationKey768/ml_kem::DecapsulationKey768/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_768::EncapsulationKey.from_bytes#1/factory/Result<ml_kem::EncapsulationKey768, ml_kem::Error>/ml_kem::EncapsulationKey768/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_768::EncapsulationKey.from_encoded_bytes#1/factory/Result<ml_kem::EncapsulationKey768, ml_kem::InvalidKey>/ml_kem::EncapsulationKey768/[&ml_kem::Encoded]/high/{}/v=false",
	"ml_kem::ml_kem_768::EncapsulationKey.new#1/factory/Result<ml_kem::EncapsulationKey768, ml_kem::InvalidKey>/ml_kem::EncapsulationKey768/[&ml_kem::kem::Key]/high/{}/v=false",
	"ml_kem::ml_kem_768::MlKem768.from_seed#1/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[&ml_kem::Seed]/high/{}/v=false",
	"ml_kem::ml_kem_768::MlKem768.generate_keypair#0/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[]/high/{}/v=false",
	"ml_kem::ml_kem_768::MlKem768.generate_keypair_from_rng#1/factory/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/(ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768)/[&mut R]/high/{}/v=false",
}

func TestLoadEmbeddedRustMlKemContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderMlKemContracts(t)
	want := append([]string(nil), wantMlKemContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("ml-kem contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected ml-kem contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing ml-kem contract:    %s", w)
		}
	}
}

// The DOT-JOINED spelling the call graph actually emits must resolve, because
// that -- not the authored spelling -- is what the parser looks up. Every key
// and arity below was read off `--export-callgraph` for probe consumers that
// call each entry point through the crate-root, submodule, turbofish, numeric
// alias and UFCS spellings.
//
// WHAT THIS DOES AND DOES NOT PROVE. It proves the KB resolves each emitted key
// -- that the authored spelling, the arity and the normalization line up. It
// does NOT prove the annotation pipeline reaches every one of them: a call graph
// exported over a probe exercising all of these still renders 34 of the
// signatures as `name(?)` with empty parameter_types. The same holds for keys in
// already merged, certainly-contracted families
// (`chacha20poly1305.ChaCha20Poly1305.new(?)`, `aes_gcm.Aes256Gcm.new(?)`), so
// it is a pre-existing analyzer property rather than a defect in ml-kem.yaml.
// The end-to-end half is evidenced by the family's gate run, not by this test.
func TestMlKemEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type key struct {
		method string
		arity  int
	}
	emitted := make([]key, 0, 128)
	for _, n := range []string{"512", "768", "1024"} {
		emitted = append(emitted,
			// keygen on the parameter-set type, crate-root and submodule spellings
			key{"ml_kem.MlKem" + n + ".generate", 1},
			key{"ml_kem.MlKem" + n + ".generate_deterministic", 2},
			key{"ml_kem.MlKem" + n + ".generate_keypair", 0},
			key{"ml_kem.MlKem" + n + ".generate_keypair_from_rng", 1},
			key{"ml_kem.MlKem" + n + ".from_seed", 1},
			key{"ml_kem::ml_kem_" + n + ".MlKem" + n + ".generate_keypair", 0},
			key{"ml_kem::ml_kem_" + n + ".MlKem" + n + ".generate_keypair_from_rng", 1},
			key{"ml_kem::ml_kem_" + n + ".MlKem" + n + ".from_seed", 1},
			// key objects, numeric alias and submodule spellings
			key{"ml_kem.DecapsulationKey" + n + ".from_seed", 1},
			key{"ml_kem.DecapsulationKey" + n + ".new", 1},
			key{"ml_kem.DecapsulationKey" + n + ".generate_from_rng", 1},
			key{"ml_kem.DecapsulationKey" + n + ".from_encoded_bytes", 1},
			key{"ml_kem.EncapsulationKey" + n + ".new", 1},
			key{"ml_kem.EncapsulationKey" + n + ".from_encoded_bytes", 1},
			key{"ml_kem::ml_kem_" + n + ".DecapsulationKey.from_seed", 1},
			key{"ml_kem::ml_kem_" + n + ".DecapsulationKey.new", 1},
			key{"ml_kem::ml_kem_" + n + ".DecapsulationKey.generate_from_rng", 1},
			key{"ml_kem::ml_kem_" + n + ".DecapsulationKey.from_encoded_bytes", 1},
			key{"ml_kem::ml_kem_" + n + ".DecapsulationKey.from_bytes", 1},
			key{"ml_kem::ml_kem_" + n + ".EncapsulationKey.new", 1},
			key{"ml_kem::ml_kem_" + n + ".EncapsulationKey.from_encoded_bytes", 1},
			key{"ml_kem::ml_kem_" + n + ".EncapsulationKey.from_bytes", 1},
			// operations, once a contracted return has typed the receiver
			key{"ml_kem.EncapsulationKey" + n + ".encapsulate", 0},
			key{"ml_kem.DecapsulationKey" + n + ".decapsulate", 1},
		)
	}
	emitted = append(emitted,
		// the turbofish spellings, whose keys carry no parameter set
		key{"ml_kem.DecapsulationKey.from_seed", 1},
		key{"ml_kem.DecapsulationKey.new", 1},
		key{"ml_kem.DecapsulationKey.generate_from_rng", 1},
		key{"ml_kem.DecapsulationKey.from_encoded_bytes", 1},
		key{"ml_kem.EncapsulationKey.new", 1},
		key{"ml_kem.EncapsulationKey.from_encoded_bytes", 1},
		// era 1: the public from_bytes lives under the `kem` module path
		key{"ml_kem::kem.DecapsulationKey.from_bytes", 1},
		key{"ml_kem::kem.EncapsulationKey.from_bytes", 1},
		// operations on an unresolved receiver
		key{"ml_kem.EncapsulationKey.encapsulate", 0},
		key{"ml_kem.EncapsulationKey.encapsulate", 1},
		key{"ml_kem.EncapsulationKey.encapsulate_with_rng", 1},
		key{"ml_kem.EncapsulationKey.encapsulate_deterministic", 1},
		key{"ml_kem.DecapsulationKey.decapsulate", 1},
		key{"ml_kem.DecapsulationKey.try_decapsulate", 1},
	)

	for _, k := range emitted {
		got := kb.ContractsFor(k.method, k.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", k.method, k.arity)
			continue
		}
		if got[0].SourceLibrary != "ml-kem" {
			t.Errorf("%s: library = %q, want ml-kem", k.method, got[0].SourceLibrary)
		}
	}
	// Positive control: an empty `emitted` set would pass the loop above
	// vacuously.
	if len(emitted) != 86 {
		t.Fatalf("emitted key set is %d entries, want 86 -- the loop above proves "+
			"nothing if the set is not the one that was measured", len(emitted))
	}
}

// THE AUTHORED KEY IS NOT THE EMITTED KEY, AND THE FILE MUST CARRY THE
// AUTHORED ONE. Every ml-kem entry point is a method on a type, so every key
// has at least two dots and `rustAuthoredKey` (contracts.go:267) always
// rewrites one: the graph emits `ml_kem.MlKem768.generate`, the file contains
// `ml_kem::MlKem768.generate`.
//
// MEASURED, because the direction is not obvious and it decides whether a
// mis-authored file fails loudly or quietly. A KB authored in the AUTHORED
// spelling resolves BOTH forms -- the emitted one through the normalization
// retry. A KB authored in the EMITTED spelling resolves only the emitted form,
// and every lookup that arrives already normalized misses. So the authored
// spelling is strictly the safer one, and this pins that ml-kem.yaml uses it:
// the contract behind the emitted key must render its method with `::`.
func TestMlKemEmittedKeyResolvesToAnAuthoredSpelling(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		emitted  string
		arity    int
		authored string
	}{
		{"ml_kem.MlKem768.generate", 1, "ml_kem::MlKem768.generate"},
		{"ml_kem::ml_kem_512.MlKem512.generate_keypair", 0, "ml_kem::ml_kem_512::MlKem512.generate_keypair"},
		{"ml_kem.DecapsulationKey.from_seed", 1, "ml_kem::DecapsulationKey.from_seed"},
		{"ml_kem::ml_kem_768.DecapsulationKey.from_seed", 1, "ml_kem::ml_kem_768::DecapsulationKey.from_seed"},
	} {
		got := kb.ContractsFor(tc.emitted, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): the EMITTED key does not resolve", tc.emitted, tc.arity)
			continue
		}
		if got[0].Method != tc.authored {
			t.Errorf("ContractsFor(%q, %d) resolved to method %q, want the authored "+
				"spelling %q -- a file keyed in the emitted spelling loads cleanly and "+
				"then misses every already-normalized lookup",
				tc.emitted, tc.arity, got[0].Method, tc.authored)
		}
	}
}

// The library block is parsed and then never consulted by any assertion above,
// so corrupting version_range, coordinates, name or description loads cleanly
// and leaves every contract assertion green. Read the file itself and pin them.
//
// The range starts at 0.1.0-alpha and NOT at 0.0.1: `ml-kem 0.0.1` is an empty
// placeholder whose src/lib.rs is zero bytes and whose manifest description
// reads "Reserved to transfer ownership later". It exposes no symbol at all.
// The upper bound admits every 0.3.x row the Tier 0 matrix lists, 0.3.2
// included.
func TestRustMlKemLibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("rust/ml-kem.yaml")
	if err != nil {
		t.Fatalf("read rust/ml-kem.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(rust/ml-kem.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatal("ml-kem.yaml declares no library block")
	}
	lib := kb.Library

	if lib.Name != "ml-kem" {
		t.Errorf("library.name = %q, want %q", lib.Name, "ml-kem")
	}
	if want := ">=0.1.0-alpha,<0.4.0"; lib.VersionRange != want {
		t.Errorf("version_range = %q, want %q -- 0.0.1 is an empty placeholder "+
			"crate and declares no API", lib.VersionRange, want)
	}
	wantCoords := []string{"ml-kem", "ml_kem"}
	if len(lib.Coordinates) != len(wantCoords) {
		t.Fatalf("coordinates = %v, want %v", lib.Coordinates, wantCoords)
	}
	for i, c := range wantCoords {
		if lib.Coordinates[i] != c {
			t.Errorf("coordinates[%d] = %q, want %q", i, lib.Coordinates[i], c)
		}
	}
	if lib.Description == "" {
		t.Error("library.description is empty")
	}
	if kb.Ecosystem != "rust" || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema_version = %q/%q, want rust/2", kb.Ecosystem, kb.SchemaVersion)
	}
}
