// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The rsa crate's contracts are split across era files because a file may only
// claim versions where every entry in it is true (the era table is in
// rust/rsa.yaml). The set is compared exactly, rendering role, return and every
// parameter's role, property and derivation, so a dropped entry, a stray one, or an entry moved to a file
// whose range makes it false all fail here.
var wantRsaContracts = []string{
	"rsa::Oaep.new#0/factory/rsa::Oaep/[]/rsa-0.8",
	"rsa::Oaep.new_with_label#1/factory/rsa::Oaep/[]/rsa-0.8",
	"rsa::Oaep.new_with_mgf_hash#0/factory/rsa::Oaep/[]/rsa-0.8",
	"rsa::Oaep.new_with_mgf_hash_and_label#1/factory/rsa::Oaep/[]/rsa-0.8",
	"rsa::PaddingScheme.new_oaep#0/factory/rsa::PaddingScheme/[]/rsa-padding-scheme",
	"rsa::PaddingScheme.new_pkcs1v15_encrypt#0/factory/rsa::PaddingScheme/[]/rsa-padding-scheme",
	"rsa::PaddingScheme.new_pkcs1v15_sign#0/factory/rsa::PaddingScheme/[]/rsa-padding-scheme-0.7",
	"rsa::PaddingScheme.new_pkcs1v15_sign#1/factory/rsa::PaddingScheme/[0:metadata-contributing:hashAlgorithm:argument_value]/rsa-padding-scheme-0.3",
	"rsa::PaddingScheme.new_pss#0/factory/rsa::PaddingScheme/[]/rsa-padding-scheme-0.7",
	"rsa::PaddingScheme.new_pss#1/factory/rsa::PaddingScheme/[]/rsa-padding-scheme-0.3",
	"rsa::Pkcs1v15Sign.new#0/factory/rsa::Pkcs1v15Sign/[]/rsa-0.8",
	"rsa::Pkcs1v15Sign.new_unprefixed#0/factory/rsa::Pkcs1v15Sign/[]/rsa-0.9",
	"rsa::Pss.new#0/factory/rsa::Pss/[]/rsa-0.8",
	"rsa::Pss.new_blinded#0/factory/rsa::Pss/[]/rsa-0.8",
	"rsa::Pss.new_blinded_with_salt#1/factory/rsa::Pss/[0:metadata-contributing:saltLength:argument_value]/rsa-0.8",
	"rsa::Pss.new_with_salt#1/factory/rsa::Pss/[0:metadata-contributing:saltLength:argument_value]/rsa-0.8",
	"rsa::RSAPrivateKey.new#2/factory/rsa::RSAPrivateKey/[1:metadata-contributing:keySize:argument_value]/rsa-0.1",
	"rsa::RsaPrivateKey.new#2/factory/rsa::RsaPrivateKey/[1:metadata-contributing:keySize:argument_value]/rsa",
	"rsa::RsaPrivateKey.new_with_exp#3/factory/rsa::RsaPrivateKey/[1:metadata-contributing:keySize:argument_value 2:metadata-contributing:publicExponent:argument_value]/rsa",
	"rsa::RsaPrivateKey.decrypt#2/operation/core::result::Result/[0:operation-determining:padding:argument_value]/rsa",
	"rsa::RsaPrivateKey.decrypt_blinded#3/operation/core::result::Result/[1:operation-determining:padding:argument_value]/rsa",
	"rsa::RsaPrivateKey.sign#2/operation/core::result::Result/[0:operation-determining:padding:argument_value]/rsa",
	"rsa::RsaPrivateKey.sign_with_rng#3/operation/core::result::Result/[1:operation-determining:padding:argument_value]/rsa-0.7",
	"rsa::RsaPublicKey.encrypt#3/operation/core::result::Result/[1:operation-determining:padding:argument_value]/rsa-0.9",
	"rsa::RsaPublicKey.verify#3/operation/core::result::Result/[0:operation-determining:padding:argument_value]/rsa-0.9",
	"rsa::oaep::DecryptingKey.new#1/factory/rsa::oaep::DecryptingKey/[]/rsa-0.8.2",
	"rsa::oaep::EncryptingKey.new#1/factory/rsa::oaep::EncryptingKey/[]/rsa-0.8.2",
	"rsa::pkcs1v15::DecryptingKey.new#1/factory/rsa::pkcs1v15::DecryptingKey/[]/rsa-0.8.2",
	"rsa::pkcs1v15::EncryptingKey.new#1/factory/rsa::pkcs1v15::EncryptingKey/[]/rsa-0.8.2",
	"rsa::pkcs1v15::SigningKey.new#1/factory/rsa::pkcs1v15::SigningKey/[]/rsa-0.7",
	"rsa::pkcs1v15::SigningKey.new_unprefixed#1/factory/rsa::pkcs1v15::SigningKey/[]/rsa-0.9",
	"rsa::pkcs1v15::SigningKey.new_with_prefix#1/factory/rsa::pkcs1v15::SigningKey/[]/rsa-0.7-prefixed",
	"rsa::pkcs1v15::SigningKey.random#2/factory/rsa::pkcs1v15::SigningKey/[1:metadata-contributing:keySize:argument_value]/rsa-0.8",
	"rsa::pkcs1v15::VerifyingKey.new#1/factory/rsa::pkcs1v15::VerifyingKey/[]/rsa-0.7",
	"rsa::pkcs1v15::VerifyingKey.new_unprefixed#1/factory/rsa::pkcs1v15::VerifyingKey/[]/rsa-0.9",
	"rsa::pkcs1v15::VerifyingKey.new_with_prefix#1/factory/rsa::pkcs1v15::VerifyingKey/[]/rsa-0.7-prefixed",
	"rsa::pss::BlindedSigningKey.new#1/factory/rsa::pss::BlindedSigningKey/[]/rsa-0.7",
	"rsa::pss::BlindedSigningKey.new_with_salt_len#2/factory/rsa::pss::BlindedSigningKey/[1:metadata-contributing:saltLength:argument_value]/rsa-0.7",
	"rsa::pss::BlindedSigningKey.random#2/factory/rsa::pss::BlindedSigningKey/[1:metadata-contributing:keySize:argument_value]/rsa-0.9",
	"rsa::pss::SigningKey.new#1/factory/rsa::pss::SigningKey/[]/rsa-0.7",
	"rsa::pss::SigningKey.new_with_salt_len#2/factory/rsa::pss::SigningKey/[1:metadata-contributing:saltLength:argument_value]/rsa-0.7",
	"rsa::pss::SigningKey.random#2/factory/rsa::pss::SigningKey/[1:metadata-contributing:keySize:argument_value]/rsa-0.8",
	"rsa::pss::VerifyingKey.new#1/factory/rsa::pss::VerifyingKey/[]/rsa-0.7",
	"rsa::pss::VerifyingKey.new_with_auto_salt_len#1/factory/rsa::pss::VerifyingKey/[]/rsa-0.10",
	"rsa::pss::VerifyingKey.new_with_salt_len#2/factory/rsa::pss::VerifyingKey/[1:metadata-contributing:saltLength:argument_value]/rsa-0.9",
}

func TestLoadEmbeddedRustRsaContractsExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "rsa" && !strings.HasPrefix(c.SourceLibrary, "rsa-") {
				continue
			}
			if c.Return.Confidence != "high" {
				t.Errorf("%s#%d: confidence %q, want high", c.Method, c.Arity, c.Return.Confidence)
			}
			var params []string
			for _, p := range c.Parameters {
				if p.Index == nil || p.Contributes == nil {
					t.Errorf("%s#%d: parameter %+v has no index or contribution", c.Method, c.Arity, p)
					continue
				}
				params = append(params, fmt.Sprintf("%d:%s:%s:%s", *p.Index, p.Role, p.Contributes.Property, p.Contributes.Derivation))
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/[%s]/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, strings.Join(params, " "), c.SourceLibrary))
		}
	}
	slices.Sort(got)
	want := slices.Clone(wantRsaContracts)
	slices.Sort(want)

	for _, g := range got {
		if !slices.Contains(want, g) {
			t.Errorf("unexpected rsa contract: %s", g)
		}
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing rsa contract:    %s", w)
		}
	}
}
