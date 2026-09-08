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

// The pgp (rPGP) KB is asserted as a SET, not as a sample.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. Comparing the whole set
// means none of those can happen without this test saying so.
//
// WHAT THIS TEST PROVES AND WHAT IT DOES NOT. It proves the loaded set matches
// what was written here; it does NOT prove what was written is true of the
// library. That is a separate gate, and for this family it was done by tracing
// every symbol to a `pub fn` in the crate sources at 0.2.0, 0.5.0, 0.7.2,
// 0.10.0, 0.11.0, 0.13.2, 0.14.2, 0.15.0, 0.16.0, 0.17.0, 0.18.0, 0.19.0 and
// 0.20.0 — which is how `create_signature` (present in no release) was removed
// before it shipped, and how `StringToKey::new_iterated` was corrected from the
// arity 4 an exported call graph reported to its real arity 3.
//
// `canonical_return_type` AND `varargs` ARE BOTH RENDERED HERE, and neither is
// rendered by most of the older rust exact-set tests in this directory. Every
// entry in this file carries a canonical return, and a contract whose canonical
// return is empty renders identically to no contract at all (measured on
// cargo-rustls-native-certs), so leaving it out would leave the one field whose
// absence is invisible unasserted. `varargs` is rendered even though no pgp
// entry sets it: a family measured that a `varargs: true` mutation survives every
// exact-set test that does not render the field, and "we do not use it" is only
// true until someone adds it.
func TestPgpContractSetIsExact(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type row struct {
		method  string
		arity   int
		role    string
		ret     string
		params  []string
		conf    string
		canon   string
		varargs bool
	}
	want := []row{
		{"pgp.decrypt_session_key", 3, "operation", "core::result::Result", []string{"&L", "F", "&[pgp::types::Mpi]"}, "high", "core::result::Result<pgp::composed::PlainSessionKey, pgp::errors::Error>", false},
		{"pgp.decrypt_session_key", 4, "operation", "core::result::Result", []string{"&L", "F", "&pgp::packet::PkeskBytes", "pgp::types::EskType"}, "high", "core::result::Result<pgp::composed::PlainSessionKey, pgp::errors::Error>", false},
		{"pgp.decrypt_session_key_with_password", 2, "operation", "core::result::Result", []string{"&pgp::packet::SymKeyEncryptedSessionKey", "F"}, "high", "core::result::Result<pgp::composed::PlainSessionKey, pgp::errors::Error>", false},
		{"pgp::Message.decrypt_with_password", 1, "operation", "core::result::Result", []string{"F"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.encrypt_to_keys", 3, "operation", "core::result::Result", []string{"&mut R", "pgp::crypto::sym::SymmetricKeyAlgorithm", "&[&impl pgp::types::PublicKeyTrait]"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.encrypt_to_keys_seipdv1", 3, "operation", "core::result::Result", []string{"R", "pgp::crypto::sym::SymmetricKeyAlgorithm", "&[&impl pgp::types::PublicKeyTrait]"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.encrypt_to_keys_seipdv2", 5, "operation", "core::result::Result", []string{"R", "pgp::crypto::sym::SymmetricKeyAlgorithm", "pgp::crypto::aead::AeadAlgorithm", "u8", "&[&impl pgp::types::PublicKeyTrait]"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.encrypt_with_password", 4, "operation", "core::result::Result", []string{"&mut R", "pgp::types::StringToKey", "pgp::crypto::sym::SymmetricKeyAlgorithm", "F"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.encrypt_with_password_seipdv1", 4, "operation", "core::result::Result", []string{"R", "pgp::types::StringToKey", "pgp::crypto::sym::SymmetricKeyAlgorithm", "F"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.encrypt_with_password_seipdv2", 6, "operation", "core::result::Result", []string{"R", "pgp::types::StringToKey", "pgp::crypto::sym::SymmetricKeyAlgorithm", "pgp::crypto::aead::AeadAlgorithm", "u8", "F"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.from_bytes", 1, "factory", "core::result::Result", []string{"R"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.sign", 3, "operation", "core::result::Result", []string{"&impl pgp::types::SecretKeyTrait", "F", "pgp::crypto::hash::HashAlgorithm"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::Message.sign", 4, "operation", "core::result::Result", []string{"R", "&impl pgp::types::SecretKeyTrait", "F", "pgp::crypto::hash::HashAlgorithm"}, "high", "core::result::Result<pgp::Message, pgp::errors::Error>", false},
		{"pgp::SecretKeyParamsBuilder.build", 0, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::SecretKeyParams, pgp::SecretKeyParamsBuilderError>", false},
		{"pgp::SecretKeyParamsBuilder.default", 0, "factory", "pgp::SecretKeyParamsBuilder", []string{}, "high", "pgp::SecretKeyParamsBuilder", false},
		{"pgp::SecretKeyParamsBuilder.key_type", 1, "config", "pgp::SecretKeyParamsBuilder", []string{"pgp::KeyType"}, "high", "&mut pgp::SecretKeyParamsBuilder", false},
		{"pgp::SignedPublicKey.from_armor_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedPublicKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_armor_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedPublicKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_armor_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedPublicKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_armor_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedPublicKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_bytes", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::SignedPublicKey, pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_bytes_many", 1, "factory", "core::result::Result", nil, "low", "core::result::Result<alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedPublicKey, pgp::errors::Error>>>, pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_reader_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedPublicKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_reader_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedPublicKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_reader_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedPublicKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_reader_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedPublicKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_string", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedPublicKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedPublicKey.from_string_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedPublicKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_armor_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedSecretKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_armor_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedSecretKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_armor_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedSecretKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_armor_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedSecretKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_bytes", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::SignedSecretKey, pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_bytes_many", 1, "factory", "core::result::Result", nil, "low", "core::result::Result<alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedSecretKey, pgp::errors::Error>>>, pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_reader_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedSecretKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_reader_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedSecretKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_reader_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedSecretKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_reader_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedSecretKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_string", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::SignedSecretKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SignedSecretKey.from_string_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::SignedSecretKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::SubkeyParamsBuilder.build", 0, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::SubkeyParams, pgp::SubkeyParamsBuilderError>", false},
		{"pgp::SubkeyParamsBuilder.default", 0, "factory", "pgp::SubkeyParamsBuilder", []string{}, "high", "pgp::SubkeyParamsBuilder", false},
		{"pgp::SubkeyParamsBuilder.key_type", 1, "config", "pgp::SubkeyParamsBuilder", []string{"pgp::KeyType"}, "high", "&mut pgp::SubkeyParamsBuilder", false},
		{"pgp::cleartext::CleartextSignedMessage.sign", 3, "operation", "core::result::Result", []string{"&str", "&impl pgp::types::SecretKeyTrait", "F"}, "high", "core::result::Result<pgp::cleartext::CleartextSignedMessage, pgp::errors::Error>", false},
		{"pgp::cleartext::CleartextSignedMessage.sign", 4, "operation", "core::result::Result", []string{"R", "&str", "&impl pgp::types::SecretKeyTrait", "F"}, "high", "core::result::Result<pgp::cleartext::CleartextSignedMessage, pgp::errors::Error>", false},
		{"pgp::cleartext::CleartextSignedMessage.verify_many", 1, "operation", "core::result::Result", []string{"F"}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::cleartext::CleartextSignedMessage.verify_many", 3, "operation", "core::result::Result", nil, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed.decrypt_session_key", 3, "operation", "core::result::Result", []string{"&L", "F", "&[pgp::types::Mpi]"}, "high", "core::result::Result<pgp::composed::PlainSessionKey, pgp::errors::Error>", false},
		{"pgp::composed.decrypt_session_key", 4, "operation", "core::result::Result", []string{"&L", "F", "&pgp::packet::PkeskBytes", "pgp::types::EskType"}, "high", "core::result::Result<pgp::composed::PlainSessionKey, pgp::errors::Error>", false},
		{"pgp::composed.decrypt_session_key_with_password", 2, "operation", "core::result::Result", []string{"&pgp::packet::SymKeyEncryptedSessionKey", "&pgp::types::Password"}, "high", "core::result::Result<pgp::composed::PlainSessionKey, pgp::errors::Error>", false},
		{"pgp::composed::CleartextSignedMessage.sign", 4, "operation", "core::result::Result", []string{"R", "&str", "&impl pgp::composed::SigningKey", "&pgp::types::Password"}, "high", "core::result::Result<pgp::composed::CleartextSignedMessage, pgp::errors::Error>", false},
		{"pgp::composed::CleartextSignedMessage.verify", 1, "operation", "core::result::Result", []string{"&impl pgp::composed::VerifyingKey"}, "high", "core::result::Result<&pgp::packet::Signature, pgp::errors::Error>", false},
		{"pgp::composed::CleartextSignedMessage.verify_many", 1, "operation", "core::result::Result", []string{"F"}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed::CleartextSignedMessage.verify_many", 3, "operation", "core::result::Result", []string{}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed::DetachedSignature.sign_binary_data", 5, "operation", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::DetachedSignature, pgp::errors::Error>", false},
		{"pgp::composed::DetachedSignature.sign_binary_data_with_subpackets", 6, "operation", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::DetachedSignature, pgp::errors::Error>", false},
		{"pgp::composed::DetachedSignature.sign_text_data", 5, "operation", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::DetachedSignature, pgp::errors::Error>", false},
		{"pgp::composed::DetachedSignature.sign_text_data_with_subpackets", 6, "operation", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::DetachedSignature, pgp::errors::Error>", false},
		{"pgp::composed::DetachedSignature.verify", 2, "operation", "core::result::Result", []string{"&impl pgp::composed::VerifyingKey", "&[u8]"}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed::Message.decrypt", 2, "operation", "core::result::Result", []string{"&pgp::types::Password", "&pgp::composed::SignedSecretKey"}, "high", "core::result::Result<pgp::composed::Message, pgp::errors::Error>", false},
		{"pgp::composed::Message.decrypt_the_ring", 2, "operation", "core::result::Result", []string{"pgp::composed::TheRing", "bool"}, "high", "core::result::Result<(pgp::composed::Message, pgp::composed::RingResult), pgp::errors::Error>", false},
		{"pgp::composed::Message.decrypt_with_password", 1, "operation", "core::result::Result", []string{"&pgp::types::Password"}, "high", "core::result::Result<pgp::composed::Message, pgp::errors::Error>", false},
		{"pgp::composed::Message.decrypt_with_session_key", 1, "operation", "core::result::Result", []string{"pgp::composed::PlainSessionKey"}, "high", "core::result::Result<pgp::composed::Message, pgp::errors::Error>", false},
		{"pgp::composed::Message.from_armor_file", 1, "factory", "core::result::Result", []string{"impl core::convert::AsRef"}, "high", "core::result::Result<(pgp::composed::Message, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::Message.from_bytes", 1, "factory", "core::result::Result", []string{"R"}, "high", "core::result::Result<pgp::composed::Message, pgp::errors::Error>", false},
		{"pgp::composed::Message.from_file", 1, "factory", "core::result::Result", []string{"impl core::convert::AsRef"}, "high", "core::result::Result<pgp::composed::Message, pgp::errors::Error>", false},
		{"pgp::composed::Message.verify_nested", 1, "operation", "core::result::Result", []string{"&[&dyn pgp::types::PublicKeyTrait]"}, "high", "core::result::Result<alloc::vec::Vec<pgp::composed::VerificationResult>, pgp::errors::Error>", false},
		{"pgp::composed::Message.verify_read", 1, "operation", "core::result::Result", []string{"&dyn pgp::types::PublicKeyTrait"}, "high", "core::result::Result<&pgp::packet::Signature, pgp::errors::Error>", false},
		{"pgp::composed::MessageBuilder.encrypt_to_key", 2, "operation", "core::result::Result", []string{"impl rand::CryptoRng", "&E"}, "high", "core::result::Result<&mut pgp::composed::MessageBuilder, pgp::errors::Error>", false},
		{"pgp::composed::MessageBuilder.encrypt_to_key_anonymous", 2, "operation", "core::result::Result", []string{"impl rand::CryptoRng", "&E"}, "high", "core::result::Result<&mut pgp::composed::MessageBuilder, pgp::errors::Error>", false},
		{"pgp::composed::MessageBuilder.encrypt_with_password", 2, "operation", "core::result::Result", []string{"pgp::types::StringToKey", "&pgp::types::Password"}, "high", "core::result::Result<&mut pgp::composed::MessageBuilder, pgp::errors::Error>", false},
		{"pgp::composed::MessageBuilder.encrypt_with_password", 3, "operation", "core::result::Result", []string{"impl rand::CryptoRng", "pgp::types::StringToKey", "&pgp::types::Password"}, "high", "core::result::Result<&mut pgp::composed::MessageBuilder, pgp::errors::Error>", false},
		{"pgp::composed::MessageBuilder.from_bytes", 2, "factory", "pgp::composed::MessageBuilder", []string{"impl core::convert::Into", "impl core::convert::Into"}, "high", "pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.from_file", 1, "factory", "pgp::composed::MessageBuilder", []string{"impl core::convert::AsRef"}, "high", "pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.from_reader", 2, "factory", "pgp::composed::MessageBuilder", []string{"impl core::convert::Into", "R"}, "high", "pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.seipd_v1", 2, "config", "pgp::composed::MessageBuilder", []string{"impl rand::CryptoRng", "pgp::crypto::sym::SymmetricKeyAlgorithm"}, "high", "pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.seipd_v2", 4, "config", "pgp::composed::MessageBuilder", []string{"impl rand::CryptoRng", "pgp::crypto::sym::SymmetricKeyAlgorithm", "pgp::crypto::aead::AeadAlgorithm", "pgp::composed::ChunkSize"}, "high", "pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.sign", 3, "config", "pgp::composed::MessageBuilder", []string{"&dyn pgp::composed::SigningKey", "pgp::types::Password", "pgp::crypto::hash::HashAlgorithm"}, "high", "&mut pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.sign_binary", 0, "config", "pgp::composed::MessageBuilder", []string{}, "high", "&mut pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.sign_text", 0, "config", "pgp::composed::MessageBuilder", []string{}, "high", "&mut pgp::composed::MessageBuilder", false},
		{"pgp::composed::MessageBuilder.to_vec", 1, "output", "core::result::Result", []string{"impl rand::CryptoRng"}, "high", "core::result::Result<alloc::vec::Vec<u8>, pgp::errors::Error>", false},
		{"pgp::composed::MessageBuilder.to_writer", 2, "output", "core::result::Result", []string{"impl rand::CryptoRng", "impl std::io::Write"}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed::SecretKeyParamsBuilder.build", 0, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::SecretKeyParams, pgp::composed::SecretKeyParamsBuilderError>", false},
		{"pgp::composed::SecretKeyParamsBuilder.default", 0, "factory", "pgp::composed::SecretKeyParamsBuilder", []string{}, "high", "pgp::composed::SecretKeyParamsBuilder", false},
		{"pgp::composed::SecretKeyParamsBuilder.key_type", 1, "config", "pgp::composed::SecretKeyParamsBuilder", []string{"pgp::composed::KeyType"}, "high", "&mut pgp::composed::SecretKeyParamsBuilder", false},
		{"pgp::composed::SignedPublicKey.from_armor_file", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedPublicKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_armor_file_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_armor_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_armor_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_armor_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedPublicKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_armor_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedPublicKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_bytes", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_bytes_many", 1, "factory", "core::result::Result", nil, "low", "core::result::Result<alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_file", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_file_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_reader_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_reader_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_reader_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedPublicKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_reader_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedPublicKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_string", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedPublicKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.from_string_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedPublicKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedPublicKey.verify_bindings", 0, "operation", "core::result::Result", []string{}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_armor_file", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedSecretKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_armor_file_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_armor_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_armor_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_armor_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedSecretKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_armor_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedSecretKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_bytes", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_bytes_many", 1, "factory", "core::result::Result", nil, "low", "core::result::Result<alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_file", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_file_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_reader_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_reader_many_buf", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_reader_single", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedSecretKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_reader_single_buf", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedSecretKey, core::option::Option<pgp::armor::Headers>), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_string", 1, "factory", "core::result::Result", []string{}, "high", "core::result::Result<(pgp::composed::SignedSecretKey, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.from_string_many", 1, "factory", "core::result::Result", nil, "high", "core::result::Result<(alloc::boxed::Box<dyn core::iter::Iterator<Item = core::result::Result<pgp::composed::SignedSecretKey, pgp::errors::Error>>>, pgp::armor::Headers), pgp::errors::Error>", false},
		{"pgp::composed::SignedSecretKey.verify_bindings", 0, "operation", "core::result::Result", []string{}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed::SubkeyParamsBuilder.build", 0, "factory", "core::result::Result", []string{}, "high", "core::result::Result<pgp::composed::SubkeyParams, pgp::composed::SubkeyParamsBuilderError>", false},
		{"pgp::composed::SubkeyParamsBuilder.default", 0, "factory", "pgp::composed::SubkeyParamsBuilder", []string{}, "high", "pgp::composed::SubkeyParamsBuilder", false},
		{"pgp::composed::SubkeyParamsBuilder.key_type", 1, "config", "pgp::composed::SubkeyParamsBuilder", []string{"pgp::composed::KeyType"}, "high", "&mut pgp::composed::SubkeyParamsBuilder", false},
		{"pgp::composed::cleartext::CleartextSignedMessage.sign", 3, "operation", "core::result::Result", []string{"&str", "&impl pgp::types::SecretKeyTrait", "F"}, "high", "core::result::Result<pgp::composed::cleartext::CleartextSignedMessage, pgp::errors::Error>", false},
		{"pgp::composed::cleartext::CleartextSignedMessage.sign", 4, "operation", "core::result::Result", []string{"R", "&str", "&impl pgp::types::SecretKeyTrait", "F"}, "high", "core::result::Result<pgp::composed::cleartext::CleartextSignedMessage, pgp::errors::Error>", false},
		{"pgp::composed::cleartext::CleartextSignedMessage.verify_many", 1, "operation", "core::result::Result", []string{"F"}, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::composed::cleartext::CleartextSignedMessage.verify_many", 3, "operation", "core::result::Result", nil, "high", "core::result::Result<(), pgp::errors::Error>", false},
		{"pgp::types::StringToKey.new_argon2", 4, "factory", "pgp::types::StringToKey", []string{"R", "u8", "u8", "u8"}, "high", "pgp::types::StringToKey", false},
		{"pgp::types::StringToKey.new_default", 1, "factory", "pgp::types::StringToKey", []string{"R"}, "high", "pgp::types::StringToKey", false},
		{"pgp::types::StringToKey.new_iterated", 3, "factory", "pgp::types::StringToKey", []string{"R", "pgp::crypto::hash::HashAlgorithm", "u8"}, "high", "pgp::types::StringToKey", false},
	}

	render := func(method string, arity int, role, ret string, params []string, conf, canon string, varargs bool) string {
		return fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=%s canon=%s varargs=%t",
			method, arity, role, ret, strings.Join(params, ","), conf, canon, varargs)
	}

	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[render(r.method, r.arity, r.role, r.ret, r.params, r.conf, r.canon, r.varargs)] = true
	}

	gotSet := map[string]bool{}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "pgp" {
				continue
			}
			gotSet[render(c.Method, c.Arity, c.Role, c.Return.Type,
				c.ParameterTypes, c.Return.Confidence, c.CanonicalReturnType, c.Varargs)] = true
		}
	}

	var missing, unexpected []string
	for k := range wantSet {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for k := range gotSet {
		if !wantSet[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	for _, m := range missing {
		t.Errorf("missing from the KB: %s", m)
	}
	for _, u := range unexpected {
		t.Errorf("present in the KB but not declared here: %s", u)
	}
	if len(want) != len(wantSet) {
		t.Errorf("the want table has duplicate rows: %d rows render to %d keys", len(want), len(wantSet))
	}
	if len(gotSet) != 129 {
		t.Errorf("loaded pgp contract entries = %d, want 129", len(gotSet))
	}
}

// THE KEYS MUST BE AUTHORED IN THE CONVENTION SHAPE `pgp::<module>::Type.method`,
// not in the shape the call graph emits. `rustAuthoredKey` bridges the emitted
// form onto this one by rewriting the second-to-last dot — but ONLY when the key
// has at least two dots. A crate-module FREE FUNCTION emits exactly one dot, so
// for it the authored key IS the emitted key and the substitution must not be
// applied; writing `pgp::composed::decrypt_session_key_with_password` would load
// without error and join nothing.
//
// This test pins both halves: every type-method key has no `.` before its final
// one, and the two free-function keys are exempt BY NAME rather than by a
// pattern, so a new key cannot quietly join the exemption.
func TestPgpKeysUseTheAuthoredShape(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	freeFunctions := map[string]bool{
		"pgp::composed.decrypt_session_key_with_password": true,
		"pgp.decrypt_session_key_with_password":           true,
	}
	seenFree := map[string]bool{}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "pgp" {
				continue
			}
			if freeFunctions[c.Method] {
				seenFree[c.Method] = true
				continue
			}
			head := c.Method
			if i := strings.LastIndex(head, "."); i > 0 {
				head = head[:i]
			}
			if strings.Contains(head, ".") {
				t.Errorf("%s: module path uses '.', want '::' (the authored shape)", c.Method)
			}
		}
	}
	for k := range freeFunctions {
		if !seenFree[k] {
			t.Errorf("free-function key %s is not in the KB; the single-dot exemption is now vacuous", k)
		}
	}
}

// BOTH IMPORT SPELLINGS MUST BE PRESENT. The key follows the consumer's import,
// and this crate can be reached two ways: `use pgp::composed::Message;` (valid in
// every version, and the only spelling from 0.16.0 on) and `use pgp::Message;`
// (valid up to 0.15.0 through `pub use self::composed::*;`). Both occur in real
// published consumers — wicrs_server 0.13.1 writes the first against pgp 0.7,
// tugger-rust-toolchain 0.9.0 writes the second. A family contracting only one
// would silently join nothing for the other, which reads exactly like having no
// contract at all.
//
// `pgp::SignedSecretKey.from_armor_file` MUST NOT be present: `from_armor_file`
// arrives at 0.16.0, the release that removed the crate-root re-exports, so the
// pair compiles in no published release.
func TestPgpBothImportSpellingsAreContracted(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	mustHave := []struct {
		method string
		arity  int
	}{
		{"pgp::composed::SignedSecretKey.from_armor_file", 1},
		{"pgp::composed::SignedSecretKey.from_armor_single", 1},
		{"pgp::SignedSecretKey.from_armor_single", 1},
		{"pgp::composed::SecretKeyParamsBuilder.default", 0},
		{"pgp::SecretKeyParamsBuilder.default", 0},
		{"pgp::composed::Message.decrypt_with_password", 1},
		{"pgp::Message.encrypt_to_keys", 3},
		{"pgp::types::StringToKey.new_iterated", 3},
	}
	for _, m := range mustHave {
		if got := kb.ContractsFor(m.method, m.arity); len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d) = 0 contracts, want at least one", m.method, m.arity)
		}
	}
	// `pgp::CleartextSignedMessage` is not a spelling any release has: composed
	// re-exports the cleartext MODULE up to 0.15.0 and the TYPE from 0.16.0, so
	// the crate root never carries the type. Two entries under that key shipped
	// in an earlier draft of this file.
	for _, arity := range []int{1, 3, 4} {
		if got := kb.ContractsFor("pgp::CleartextSignedMessage.sign", arity); len(got) != 0 {
			t.Errorf("pgp::CleartextSignedMessage.sign#%d is contracted; that spelling "+
				"compiles in no published release", arity)
		}
	}
	// The composed-TYPE path arrives at 0.16.0, where sign takes 4 arguments; the
	// 3-argument form is 0.13.x, when only the module spellings existed.
	if got := kb.ContractsFor("pgp::composed::CleartextSignedMessage.sign", 3); len(got) != 0 {
		t.Error("pgp::composed::CleartextSignedMessage.sign#3 is contracted, but the " +
			"composed-type path (0.16.0+) and arity 3 (0.13.x) have disjoint windows")
	}
	if got := kb.ContractsFor("pgp::SignedSecretKey.from_armor_file", 1); len(got) != 0 {
		t.Errorf("pgp::SignedSecretKey.from_armor_file is contracted, but the crate-root spelling " +
			"and from_armor_file have disjoint version windows: it compiles in no release")
	}
}

// `CleartextSignedMessage.verify_many` IS DECLARED AT TWO ARITIES ON PURPOSE.
// The source signature is arity 1 (0.20.0 src/composed/cleartext.rs:138), but the
// parser counts a multi-parameter closure literal's parameters as separate call
// arguments, so the crate's own documented spelling
// `m.verify_many(|i, sig, data| ..)` — the bound is `Fn(usize, &Signature, &[u8])`
// — emits arity 3. Measured with three probes through one binary: a named
// function and a one-parameter closure both give arity 1. Dropping either entry
// silently stops the join for one real spelling, so both are pinned here.
func TestPgpVerifyManyIsContractedAtBothObservedArities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, arity := range []int{1, 3} {
		if got := kb.ContractsFor("pgp::composed::CleartextSignedMessage.verify_many", arity); len(got) == 0 {
			t.Errorf("verify_many at arity %d is not contracted; the closure-arity workaround is incomplete", arity)
		}
	}
}

// THE LIBRARY BLOCK IS PARSED AND THEN CONSULTED BY NOTHING ELSE IN THIS FILE,
// so corrupting `version_range`, `coordinates`, `name` or `description` leaves
// every other assertion above green. Measured on an earlier family; pinned here
// by loading the single YAML rather than the merged KB, because `LoadEmbedded`
// returns a merged KnowledgeBase whose Library is nil by construction.
//
// The floor is 0.2.0 and not 0.1.0 deliberately: 0.1.0 is in the matrix range
// but is a different library under the same name — its `src/` holds only
// `email.rs`, `header.rs`, `pgp.rs` and `types.rs`, with no `composed`, no
// `crypto` and no key or message API for anything here to join against.
func TestPgpLibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("contracts", "rust", "pgp.yaml"))
	if err != nil {
		t.Fatalf("read pgp.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(pgp.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatal("pgp.yaml carries no library block")
	}
	if got, want := kb.Library.Name, "pgp"; got != want {
		t.Errorf("library.name = %q, want %q", got, want)
	}
	if got, want := kb.Library.VersionRange, ">=0.2.0,<0.21.0"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
	if got, want := strings.Join(kb.Library.Coordinates, ","), "pgp"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	if kb.Library.Description == "" {
		t.Error("library.description is empty")
	}
}
