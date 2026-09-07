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

	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// josekit is a JOSE implementation (JWT, JWS, JWE, JWA, JWK) over OpenSSL, and
// its algorithm is a SELECTOR rather than a method name: `signer_from_pem` says
// nothing on its own, while `josekit::jws::RS256.signer_from_pem(..)` names
// RSASSA-PKCS1-v1_5 with SHA-256.
//
// THREE OF THE FOUR CALL-SITE KEY SHAPES THIS CRATE EMITS ARE DECLARED, and the
// fourth is a recorded gap. Every key was read off
// `crypto-finder scan --export-callgraph` over a probe consumer and then had
// its second-to-last dot rewritten to `::` ONLY when the emitted key carried
// two or more dots (rustAuthoredKey, contracts.go:267):
//
//	RsassaJwsAlgorithm::Rs256.signer_from_jwk(j)   the selector's ENUM TYPE
//	    -> josekit::jws::alg::rsassa.RsassaJwsAlgorithm.signer_from_jwk
//	    -> josekit::jws::alg::rsassa::RsassaJwsAlgorithm.signer_from_jwk
//	RS256.signer_from_pem(p)                       the crate-root ALIAS CONSTANT
//	    -> josekit::jws.RS256.signer_from_pem
//	    -> josekit::jws::RS256.signer_from_pem
//	jwt::encode_with_signer(..)                    a SUBMODULE FREE FUNCTION
//	    -> josekit.jwt.encode_with_signer  (module-`self` import, two dots)
//	    -> josekit::jwt.encode_with_signer
//	josekit::jwt::decode_with_verifier(..)         the same function, qualified
//	    -> josekit::jwt.decode_with_verifier       (ONE dot, returned UNCHANGED)
//
// The last two land on ONE declared key, which is why a single single-dot entry
// serves both spellings. Writing `josekit::jwt::decode_with_verifier` instead
// would load without error and join nothing.
//
// THE FOURTH SHAPE IS NOT DECLARED AND THAT IS DELIBERATE.
// `use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs384;` then
// `Rs384.signer_from_jwk(j)` pushes the ENUM into the package position and
// emits `josekit::jws::alg::rsassa::RsassaJwsAlgorithm.Rs384.signer_from_jwk`,
// keyed on a variant name. Real -- logto-rs 0.1.0 verify_id_token.rs:77 writes
// it -- and reported as a gap rather than covered with one entry per
// (variant, method, era). TestJosekitUndeclaredVariantKeyShape pins it, so a
// future change that makes it resolve is a signal to update this note.
//
// The set is compared EXACTLY, not per key, and it renders the `parameters:`
// block and `Varargs` as well as the scalar fields. Varargs is rendered because
// it is parsed and defaults to false, so a `varargs: true` slipped onto any
// entry here would otherwise load cleanly and survive an exact comparison; Rust
// has no variadic methods on these types, so every rendered value is `v=false`.
// The `library:` block is pinned separately in TestJosekitLibraryBlock, because
// `coordinates`, `version_range`, `name` and `description` are parsed and never
// consulted by any other assertion.

// renderJosekitContracts renders every loaded josekit contract as one
// deterministic line, sorted.
func renderJosekitContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "josekit" {
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
			pt := make([]string, 0, len(c.ParameterTypes))
			for _, t := range c.ParameterTypes {
				pt = append(pt, fmt.Sprintf("%q", t))
			}
			when := "nil"
			if c.When != nil {
				when = "set"
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/{%s}/v=%t/w=%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(pt, ","), c.Return.Confidence,
				strings.Join(params, ";"), c.Varargs, when))
		}
	}
	sort.Strings(got)
	return got
}

var wantJosekitContracts = []string{
	"josekit::jwe.deserialize_compact#2/operation/Result<(Vec<u8>, josekit::jwe::JweHeader), josekit::JoseError>/(Vec<u8>, josekit::jwe::JweHeader)/[\"&str\",\"&dyn josekit::jwe::JweDecrypter\"]/high/{0=input:metadata-contributing:ciphertext:argument_value;1=decrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwe.deserialize_json#2/operation/Result<(Vec<u8>, josekit::jwe::JweHeader), josekit::JoseError>/(Vec<u8>, josekit::jwe::JweHeader)/[\"&str\",\"&dyn josekit::jwe::JweDecrypter\"]/high/{0=input:metadata-contributing:ciphertext:argument_value;1=decrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwe.serialize_compact#3/operation/Result<String, josekit::JoseError>/String/[\"&[u8]\",\"&josekit::jwe::JweHeader\",\"&dyn josekit::jwe::JweEncrypter\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;2=encrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwe.serialize_flattened_json#4/operation/Result<String, josekit::JoseError>/String/[]/high/{0=payload:metadata-contributing:plaintext:argument_value;3=encrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwe.serialize_flattened_json#5/operation/Result<String, josekit::JoseError>/String/[\"&[u8]\",\"Option<&josekit::jwe::JweHeaderSet>\",\"Option<&josekit::jwe::JweHeader>\",\"Option<&[u8]>\",\"&dyn josekit::jwe::JweEncrypter\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;4=encrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwe.serialize_flattened_json#6/operation/Result<String, josekit::JoseError>/String/[]/high/{0=payload:metadata-contributing:plaintext:argument_value;5=encrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwe.serialize_general_json#4/operation/Result<String, josekit::JoseError>/String/[\"&[u8]\",\"Option<&josekit::jwe::JweHeaderSet>\",\"&[(Option<&josekit::jwe::JweHeader>, &dyn josekit::jwe::JweEncrypter)]\",\"Option<&[u8]>\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;2=encrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwe::JweHeader.set_content_encryption#1/config/()//[\"impl Into<String>\"]/high/{0=value:operation-determining:contentEncryption:argument_value}/v=false/w=nil",
	"josekit::jwe::JweHeaderSet.set_content_encryption#2/config/()//[\"impl Into<String>\",\"bool\"]/high/{0=value:operation-determining:contentEncryption:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm.decrypter_from_bytes#1/factory/Result<josekit::jwe::alg::aesgcmkw::AesgcmkwJweDecrypter, josekit::JoseError>/josekit::jwe::alg::aesgcmkw::AesgcmkwJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm.decrypter_from_jwk#1/factory/Result<josekit::jwe::alg::aesgcmkw::AesgcmkwJweDecrypter, josekit::JoseError>/josekit::jwe::alg::aesgcmkw::AesgcmkwJweDecrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm.encrypter_from_bytes#1/factory/Result<josekit::jwe::alg::aesgcmkw::AesgcmkwJweEncrypter, josekit::JoseError>/josekit::jwe::alg::aesgcmkw::AesgcmkwJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm.encrypter_from_jwk#1/factory/Result<josekit::jwe::alg::aesgcmkw::AesgcmkwJweEncrypter, josekit::JoseError>/josekit::jwe::alg::aesgcmkw::AesgcmkwJweEncrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aeskw::AeskwJweAlgorithm.decrypter_from_bytes#1/factory/Result<josekit::jwe::alg::aeskw::AeskwJweDecrypter, josekit::JoseError>/josekit::jwe::alg::aeskw::AeskwJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aeskw::AeskwJweAlgorithm.decrypter_from_jwk#1/factory/Result<josekit::jwe::alg::aeskw::AeskwJweDecrypter, josekit::JoseError>/josekit::jwe::alg::aeskw::AeskwJweDecrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aeskw::AeskwJweAlgorithm.encrypter_from_bytes#1/factory/Result<josekit::jwe::alg::aeskw::AeskwJweEncrypter, josekit::JoseError>/josekit::jwe::alg::aeskw::AeskwJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::aeskw::AeskwJweAlgorithm.encrypter_from_jwk#1/factory/Result<josekit::jwe::alg::aeskw::AeskwJweEncrypter, josekit::JoseError>/josekit::jwe::alg::aeskw::AeskwJweEncrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::direct::DirectJweAlgorithm.decrypter_from_bytes#1/factory/Result<josekit::jwe::alg::direct::DirectJweDecrypter, josekit::JoseError>/josekit::jwe::alg::direct::DirectJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::direct::DirectJweAlgorithm.decrypter_from_jwk#1/factory/Result<josekit::jwe::alg::direct::DirectJweDecrypter, josekit::JoseError>/josekit::jwe::alg::direct::DirectJweDecrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::direct::DirectJweAlgorithm.encrypter_from_bytes#1/factory/Result<josekit::jwe::alg::direct::DirectJweEncrypter, josekit::JoseError>/josekit::jwe::alg::direct::DirectJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::direct::DirectJweAlgorithm.encrypter_from_jwk#1/factory/Result<josekit::jwe::alg::direct::DirectJweEncrypter, josekit::JoseError>/josekit::jwe::alg::direct::DirectJweEncrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.decrypter_from_der#1/factory/Result<josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter, josekit::JoseError>/josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.decrypter_from_jwk#1/factory/Result<josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter, josekit::JoseError>/josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.decrypter_from_pem#1/factory/Result<josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter, josekit::JoseError>/josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.encrypter_from_der#1/factory/Result<josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter, josekit::JoseError>/josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.encrypter_from_jwk#1/factory/Result<josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter, josekit::JoseError>/josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.encrypter_from_pem#1/factory/Result<josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter, josekit::JoseError>/josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.generate_ec_key_pair#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"josekit::jwk::alg::ec::EcCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.generate_ecx_key_pair#1/factory/Result<josekit::jwk::alg::ecx::EcxKeyPair, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"josekit::jwk::alg::ecx::EcxCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.key_pair_from_ec_der#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.key_pair_from_ec_pem#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.key_pair_from_ecx_der#1/factory/Result<josekit::jwk::alg::ecx::EcxKeyPair, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm.key_pair_from_ecx_pem#1/factory/Result<josekit::jwk::alg::ecx::EcxKeyPair, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm.decrypter_from_bytes#1/factory/Result<josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweDecrypter, josekit::JoseError>/josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm.decrypter_from_jwk#1/factory/Result<josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweDecrypter, josekit::JoseError>/josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweDecrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm.encrypter_from_bytes#1/factory/Result<josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweEncrypter, josekit::JoseError>/josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm.encrypter_from_jwk#1/factory/Result<josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweEncrypter, josekit::JoseError>/josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweEncrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.decrypter_from_der#1/factory/Result<josekit::jwe::alg::rsaes::RsaesJweDecrypter, josekit::JoseError>/josekit::jwe::alg::rsaes::RsaesJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.decrypter_from_jwk#1/factory/Result<josekit::jwe::alg::rsaes::RsaesJweDecrypter, josekit::JoseError>/josekit::jwe::alg::rsaes::RsaesJweDecrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.decrypter_from_pem#1/factory/Result<josekit::jwe::alg::rsaes::RsaesJweDecrypter, josekit::JoseError>/josekit::jwe::alg::rsaes::RsaesJweDecrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.encrypter_from_der#1/factory/Result<josekit::jwe::alg::rsaes::RsaesJweEncrypter, josekit::JoseError>/josekit::jwe::alg::rsaes::RsaesJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.encrypter_from_jwk#1/factory/Result<josekit::jwe::alg::rsaes::RsaesJweEncrypter, josekit::JoseError>/josekit::jwe::alg::rsaes::RsaesJweEncrypter/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.encrypter_from_pem#1/factory/Result<josekit::jwe::alg::rsaes::RsaesJweEncrypter, josekit::JoseError>/josekit::jwe::alg::rsaes::RsaesJweEncrypter/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwe::alg::rsaes::RsaesJweAlgorithm.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.from_bytes#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.from_map#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"impl Into<serde_json::Map<String, serde_json::Value>>\"]/high/{0=map:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.from_reader#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"&mut dyn std::io::Read\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.generate_ec_key#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"josekit::jwk::alg::ec::EcCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.generate_ecx_key#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"josekit::jwk::alg::ecx::EcxCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.generate_ed_key#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"josekit::jwk::alg::ed::EdCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.generate_oct_key#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"u8\"]/high/{0=key_len:metadata-contributing:keySize:argument_byte_length}/v=false/w=nil",
	"josekit::jwk::Jwk.generate_rsa_key#1/factory/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jwk::Jwk.to_public_key#0/output/Result<josekit::jwk::Jwk, josekit::JoseError>/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::JwkSet.from_bytes#1/factory/Result<josekit::jwk::JwkSet, josekit::JoseError>/josekit::jwk::JwkSet/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::JwkSet.from_map#1/factory/Result<josekit::jwk::JwkSet, josekit::JoseError>/josekit::jwk::JwkSet/[\"serde_json::Map<String, serde_json::Value>\"]/high/{0=map:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::JwkSet.from_reader#1/factory/Result<josekit::jwk::JwkSet, josekit::JoseError>/josekit::jwk::JwkSet/[\"&mut dyn std::io::Read\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.from_der#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::jwk::alg::ec::EcCurve>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.from_jwk#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.from_jwk#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"&josekit::jwk::Jwk\",\"Option<josekit::jwk::alg::ec::EcCurve>\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.from_pem#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::jwk::alg::ec::EcCurve>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.generate#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"josekit::jwk::alg::ec::EcCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.to_jwk_key_pair#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.to_jwk_private_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ec::EcKeyPair.to_jwk_public_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.from_der#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.from_der#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::jwk::alg::ecx::EcxCurve>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.from_jwk#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.from_jwk#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"&josekit::jwk::Jwk\",\"Option<josekit::jwk::alg::ecx::EcxCurve>\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.from_pem#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.from_pem#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::jwk::alg::ecx::EcxCurve>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.generate#1/factory/Result<josekit::jwk::alg::ecx::EcxKeyPair, josekit::JoseError>/josekit::jwk::alg::ecx::EcxKeyPair/[\"josekit::jwk::alg::ecx::EcxCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.to_jwk_key_pair#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.to_jwk_private_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ecx::EcxKeyPair.to_jwk_public_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.from_der#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.from_der#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::jwk::alg::ed::EdCurve>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.from_jwk#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.from_jwk#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"&josekit::jwk::Jwk\",\"Option<josekit::jwk::alg::ed::EdCurve>\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.from_pem#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.from_pem#2/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::jwk::alg::ed::EdCurve>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.generate#1/factory/Result<josekit::jwk::alg::ed::EdKeyPair, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"josekit::jwk::alg::ed::EdCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.to_jwk_key_pair#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.to_jwk_private_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::ed::EdKeyPair.to_jwk_public_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::rsa::RsaKeyPair.from_der#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsa::RsaKeyPair.from_jwk#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsa::RsaKeyPair.from_pem#1/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsa::RsaKeyPair.generate#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsa::RsaKeyPair.to_jwk_key_pair#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::rsa::RsaKeyPair.to_jwk_private_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::rsa::RsaKeyPair.to_jwk_public_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::rsapss::RsaPssKeyPair.from_der#4/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::util::HashAlgorithm>\",\"Option<josekit::util::HashAlgorithm>\",\"Option<u8>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsapss::RsaPssKeyPair.from_jwk#4/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"&josekit::jwk::Jwk\",\"josekit::util::HashAlgorithm\",\"josekit::util::HashAlgorithm\",\"u8\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsapss::RsaPssKeyPair.from_pem#4/factory/Result<Self, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\",\"Option<josekit::util::HashAlgorithm>\",\"Option<josekit::util::HashAlgorithm>\",\"Option<u8>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsapss::RsaPssKeyPair.generate#4/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"u32\",\"josekit::util::HashAlgorithm\",\"josekit::util::HashAlgorithm\",\"u8\"]/high/{0=bits:metadata-contributing:keySize:argument_value;3=salt_len:metadata-contributing:saltLength:argument_value}/v=false/w=nil",
	"josekit::jwk::alg::rsapss::RsaPssKeyPair.to_jwk_key_pair#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::rsapss::RsaPssKeyPair.to_jwk_private_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jwk::alg::rsapss::RsaPssKeyPair.to_jwk_public_key#0/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[]/high/{}/v=false/w=nil",
	"josekit::jws.deserialize_compact#2/operation/Result<(Vec<u8>, josekit::jws::JwsHeader), josekit::JoseError>/(Vec<u8>, josekit::jws::JwsHeader)/[\"impl AsRef<[u8]>\",\"&dyn josekit::jws::JwsVerifier\"]/high/{0=input:metadata-contributing:input:argument_value;1=verifier:metadata-contributing:signer:argument_type}/v=false/w=nil",
	"josekit::jws.deserialize_json#2/operation/Result<(Vec<u8>, josekit::jws::JwsHeader), josekit::JoseError>/(Vec<u8>, josekit::jws::JwsHeader)/[\"impl AsRef<[u8]>\",\"&dyn josekit::jws::JwsVerifier\"]/high/{0=input:metadata-contributing:input:argument_value;1=verifier:metadata-contributing:signer:argument_type}/v=false/w=nil",
	"josekit::jws.serialize_compact#3/operation/Result<String, josekit::JoseError>/String/[\"&[u8]\",\"&josekit::jws::JwsHeader\",\"&dyn josekit::jws::JwsSigner\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;2=signer:metadata-contributing:signer:argument_type}/v=false/w=nil",
	"josekit::jws.serialize_flattened_json#3/operation/Result<String, josekit::JoseError>/String/[\"&[u8]\",\"&josekit::jws::JwsHeaderSet\",\"&dyn josekit::jws::JwsSigner\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;2=signer:metadata-contributing:signer:argument_type}/v=false/w=nil",
	"josekit::jws.serialize_flattened_json#4/operation/Result<String, josekit::JoseError>/String/[]/high/{0=payload:metadata-contributing:plaintext:argument_value;3=signer:metadata-contributing:signer:argument_type}/v=false/w=nil",
	"josekit::jws.serialize_general_json#2/operation/Result<String, josekit::JoseError>/String/[\"&[u8]\",\"&[(&josekit::jws::JwsHeaderSet, &dyn josekit::jws::JwsSigner)]\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;1=signer:metadata-contributing:signer:argument_type}/v=false/w=nil",
	"josekit::jws::ES256.generate_key_pair#0/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[]/high/{}/v=false/w=nil",
	"josekit::jws::ES256.key_pair_from_der#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256.signer_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256.signer_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256.signer_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256.verifier_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256.verifier_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256.verifier_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.generate_key_pair#0/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[]/high/{}/v=false/w=nil",
	"josekit::jws::ES256K.key_pair_from_der#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.signer_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.signer_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.signer_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.verifier_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.verifier_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES256K.verifier_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.generate_key_pair#0/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[]/high/{}/v=false/w=nil",
	"josekit::jws::ES384.key_pair_from_der#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.signer_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.signer_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.signer_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.verifier_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.verifier_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES384.verifier_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.generate_key_pair#0/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[]/high/{}/v=false/w=nil",
	"josekit::jws::ES512.key_pair_from_der#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.signer_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.signer_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.signer_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.verifier_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.verifier_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::ES512.verifier_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.generate_key_pair#1/factory/Result<josekit::jwk::alg::ed::EdKeyPair, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"josekit::jwk::alg::ed::EdCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.key_pair_from_der#1/factory/Result<josekit::jwk::alg::ed::EdKeyPair, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::ed::EdKeyPair, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.signer_from_der#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsSigner, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.signer_from_jwk#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsSigner, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.signer_from_pem#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsSigner, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.verifier_from_der#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.verifier_from_jwk#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::EdDSA.verifier_from_pem#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS256.signer_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS256.signer_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS256.to_jwk#1/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[\"&[u8]\"]/high/{0=secret:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS256.verifier_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS256.verifier_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS384.signer_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS384.signer_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS384.to_jwk#1/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[\"&[u8]\"]/high/{0=secret:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS384.verifier_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS384.verifier_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS512.signer_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS512.signer_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS512.to_jwk#1/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[\"&[u8]\"]/high/{0=secret:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS512.verifier_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::HS512.verifier_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS256.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS384.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::PS512.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS256.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS384.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::RS512.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.generate_key_pair#0/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[]/high/{}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.key_pair_from_der#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::ec::EcKeyPair, josekit::JoseError>/josekit::jwk::alg::ec::EcKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.signer_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.signer_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.signer_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsSigner, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.verifier_from_der#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.verifier_from_jwk#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.verifier_from_pem#1/factory/Result<josekit::jws::alg::ecdsa::EcdsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::ecdsa::EcdsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.generate_key_pair#1/factory/Result<josekit::jwk::alg::ed::EdKeyPair, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"josekit::jwk::alg::ed::EdCurve\"]/high/{0=curve:metadata-contributing:curve:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.key_pair_from_der#1/factory/Result<josekit::jwk::alg::ed::EdKeyPair, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::ed::EdKeyPair, josekit::JoseError>/josekit::jwk::alg::ed::EdKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.signer_from_der#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsSigner, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.signer_from_jwk#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsSigner, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.signer_from_pem#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsSigner, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.verifier_from_der#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.verifier_from_jwk#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::eddsa::EddsaJwsAlgorithm.verifier_from_pem#1/factory/Result<josekit::jws::alg::eddsa::EddsaJwsVerifier, josekit::JoseError>/josekit::jws::alg::eddsa::EddsaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::hmac::HmacJwsAlgorithm.signer_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::hmac::HmacJwsAlgorithm.signer_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsSigner, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::hmac::HmacJwsAlgorithm.to_jwk#1/output/josekit::jwk::Jwk/josekit::jwk::Jwk/[\"&[u8]\"]/high/{0=secret:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::hmac::HmacJwsAlgorithm.verifier_from_bytes#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::hmac::HmacJwsAlgorithm.verifier_from_jwk#1/factory/Result<josekit::jws::alg::hmac::HmacJwsVerifier, josekit::JoseError>/josekit::jws::alg::hmac::HmacJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsa::RsaKeyPair, josekit::JoseError>/josekit::jwk::alg::rsa::RsaKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa::RsassaJwsAlgorithm.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa::RsassaJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa::RsassaJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.generate_key_pair#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"u32\"]/high/{0=bits:metadata-contributing:keySize:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.key_pair_from_der#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.key_pair_from_pem#1/factory/Result<josekit::jwk::alg::rsapss::RsaPssKeyPair, josekit::JoseError>/josekit::jwk::alg::rsapss::RsaPssKeyPair/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.signer_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.signer_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.signer_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsSigner/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.verifier_from_der#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.verifier_from_jwk#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"&josekit::jwk::Jwk\"]/high/{0=jwk:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm.verifier_from_pem#1/factory/Result<josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier, josekit::JoseError>/josekit::jws::alg::rsassa_pss::RsassaPssJwsVerifier/[\"impl AsRef<[u8]>\"]/high/{0=input:metadata-contributing:keyMaterial:argument_value}/v=false/w=nil",
	"josekit::jwt.decode_with_decrypter#2/operation/Result<(josekit::jwt::JwtPayload, josekit::jwe::JweHeader), josekit::JoseError>/(josekit::jwt::JwtPayload, josekit::jwe::JweHeader)/[\"impl AsRef<[u8]>\",\"&dyn josekit::jwe::JweDecrypter\"]/high/{0=input:metadata-contributing:ciphertext:argument_value;1=decrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwt.decode_with_verifier#2/operation/Result<(josekit::jwt::JwtPayload, josekit::jws::JwsHeader), josekit::JoseError>/(josekit::jwt::JwtPayload, josekit::jws::JwsHeader)/[\"impl AsRef<[u8]>\",\"&dyn josekit::jws::JwsVerifier\"]/high/{0=input:metadata-contributing:input:argument_value;1=verifier:metadata-contributing:signer:argument_type}/v=false/w=nil",
	"josekit::jwt.encode_with_encrypter#3/operation/Result<String, josekit::JoseError>/String/[\"&josekit::jwt::JwtPayload\",\"&josekit::jwe::JweHeader\",\"&dyn josekit::jwe::JweEncrypter\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;2=encrypter:metadata-contributing:cipher:argument_type}/v=false/w=nil",
	"josekit::jwt.encode_with_signer#3/operation/Result<String, josekit::JoseError>/String/[\"&josekit::jwt::JwtPayload\",\"&josekit::jws::JwsHeader\",\"&dyn josekit::jws::JwsSigner\"]/high/{0=payload:metadata-contributing:plaintext:argument_value;2=signer:metadata-contributing:signer:argument_type}/v=false/w=nil",
}

func TestJosekitContractsExactSet(t *testing.T) {
	got := renderJosekitContracts(t)
	want := append([]string(nil), wantJosekitContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("josekit contract count = %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("MISSING or ALTERED contract:\n  want %s", w)
		}
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("UNEXPECTED contract:\n  got  %s", g)
		}
	}
}

// TestJosekitLibraryBlock pins the fields that are parsed and then never
// consulted by any other assertion in this file. Corrupting `version_range`,
// `coordinates`, `name` or `description` leaves the exact-set test green.
func TestJosekitLibraryBlock(t *testing.T) {
	path := filepath.Join("rust", "josekit.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	if kb.Library == nil {
		t.Fatal("library block is nil")
	}
	if kb.Library.Name != "josekit" {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, "josekit")
	}
	if kb.Library.VersionRange != ">=0.2.0,<0.11.0" {
		t.Errorf("library.version_range = %q, want %q", kb.Library.VersionRange, ">=0.2.0,<0.11.0")
	}
	if len(kb.Library.Coordinates) != 1 || kb.Library.Coordinates[0] != "josekit" {
		t.Errorf("library.coordinates = %v, want [josekit]", kb.Library.Coordinates)
	}
	if kb.Library.Description != "JOSE (JWT, JWS, JWE, JWA, JWK) for Rust, over OpenSSL" {
		t.Errorf("library.description = %q, want %q", kb.Library.Description, "JOSE (JWT, JWS, JWE, JWA, JWK) for Rust, over OpenSSL")
	}
	if kb.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want 2", kb.SchemaVersion)
	}
	if kb.Ecosystem != "rust" {
		t.Errorf("ecosystem = %q, want rust", kb.Ecosystem)
	}
}

// TestJosekitAuthoredKeySpellingHolds pins the two spellings that are easy to
// get wrong in opposite directions, so a mechanical "apply the substitution
// everywhere" edit fails here rather than silently joining nothing.
func TestJosekitAuthoredKeySpellingHolds(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	// A submodule FREE FUNCTION emits one dot, so the authored key keeps the
	// dot. The `::` spelling must NOT resolve.
	if got := kb.ContractsFor("josekit::jwt.encode_with_signer", 3); len(got) != 1 {
		t.Errorf("josekit::jwt.encode_with_signer/3 resolved %d contracts, want 1", len(got))
	}
	if got := kb.ContractsFor("josekit::jwt::encode_with_signer", 3); len(got) != 0 {
		t.Errorf("josekit::jwt::encode_with_signer/3 resolved %d contracts, want 0 "+
			"(a free function in a submodule carries ONE dot; rustAuthoredKey "+
			"returns such keys unchanged)", len(got))
	}
	// A TYPE METHOD emits two dots, so the authored key moves the
	// second-to-last dot to `::`. The all-dots spelling must NOT resolve.
	if got := kb.ContractsFor("josekit::jws::alg::rsassa::RsassaJwsAlgorithm.signer_from_pem", 1); len(got) != 1 {
		t.Errorf("RsassaJwsAlgorithm.signer_from_pem/1 resolved %d contracts, want 1", len(got))
	}
	if got := kb.ContractsFor("josekit::jws::alg::rsassa::RsassaJwsAlgorithm::signer_from_pem", 1); len(got) != 0 {
		t.Errorf("the all-`::` spelling resolved %d contracts, want 0", len(got))
	}
	// The crate-root alias constant key.
	if got := kb.ContractsFor("josekit::jws::RS256.signer_from_pem", 1); len(got) != 1 {
		t.Errorf("josekit::jws::RS256.signer_from_pem/1 resolved %d contracts, want 1", len(got))
	}
	// EcdsaJwsAlgorithm::generate_key_pair takes NO argument (ecdsa.rs:32), so
	// it is arity 0 and arity 1 must not resolve.
	if got := kb.ContractsFor("josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.generate_key_pair", 0); len(got) != 1 {
		t.Errorf("EcdsaJwsAlgorithm.generate_key_pair/0 resolved %d contracts, want 1", len(got))
	}
	if got := kb.ContractsFor("josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm.generate_key_pair", 1); len(got) != 0 {
		t.Errorf("EcdsaJwsAlgorithm.generate_key_pair/1 resolved %d contracts, want 0", len(got))
	}
	// EcKeyPair::from_der / from_pem take a second Option<EcCurve> (ec.rs:122, :258).
	if got := kb.ContractsFor("josekit::jwk::alg::ec::EcKeyPair.from_pem", 2); len(got) != 1 {
		t.Errorf("EcKeyPair.from_pem/2 resolved %d contracts, want 1", len(got))
	}
	if got := kb.ContractsFor("josekit::jwk::alg::ec::EcKeyPair.from_pem", 1); len(got) != 0 {
		t.Errorf("EcKeyPair.from_pem/1 resolved %d contracts, want 0", len(got))
	}
}

// TestJosekitUndeclaredVariantKeyShape pins the ONE call-site key shape this
// family deliberately does not declare, so the note in josekit.yaml stays true.
// `use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs384;` then
// `Rs384.signer_from_jwk(j)` emits a key with the ENUM in the package position
// and the VARIANT in the type position. logto-rs 0.1.0 writes that import.
// A failure here means the shape became resolvable and the gap note is stale.
func TestJosekitUndeclaredVariantKeyShape(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	const variantKeyed = "josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs384.signer_from_jwk"
	if got := kb.ContractsFor(variantKeyed, 1); len(got) != 0 {
		t.Errorf("%s/1 resolved %d contracts, want 0 -- this shape is a recorded "+
			"gap in josekit.yaml; if it now resolves, update that note", variantKeyed, len(got))
	}
}

// TestJosekitTopLevelBlocks pins the two top-level blocks the per-contract
// fingerprint cannot see. Both are load-bearing -- `hierarchy` feeds
// `internal/scan/export.go:1833-1844` and `trait_associated_types` feeds
// `contracts.go:224-227` -- so a bogus block added to this file would otherwise
// go undetected by every assertion here. josekit declares neither.
func TestJosekitTopLevelBlocks(t *testing.T) {
	path := filepath.Join("rust", "josekit.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	allowed := map[string]bool{
		"schema_version": true, "ecosystem": true,
		"library": true, "contracts": true,
	}
	for k := range raw {
		if !allowed[k] {
			t.Errorf("unexpected top-level key %q in josekit.yaml; josekit declares no "+
				"hierarchy and no trait_associated_types, and both are load-bearing", k)
		}
	}
	for _, k := range []string{"hierarchy", "trait_associated_types"} {
		if _, ok := raw[k]; ok {
			t.Errorf("josekit.yaml must not declare %q", k)
		}
	}
}

// TestJosekitNoContractDeclaresWhen pins the field the fingerprint now renders,
// from the loaded side as well as the file side.
func TestJosekitNoContractDeclaresWhen(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary == "josekit" && c.When != nil {
				t.Errorf("%s#%d declares a `when:` condition; josekit declares none, and "+
					"a stray one disables Rust return-type resolution for that method",
					c.Method, c.Arity)
			}
		}
	}
}

// TestJosekitOctKeyLengthIsBytes pins the one derivation in this file that is
// NOT argument_value. jwk.rs:66 documents `key_len` as "A key byte length" and
// the body calls util::random_bytes(key_len as usize). Declaring
// argument_value would report 32 where 256 bits is meant.
func TestJosekitOctKeyLengthIsBytes(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	got := kb.ContractsFor("josekit::jwk::Jwk.generate_oct_key", 1)
	if len(got) != 1 {
		t.Fatalf("Jwk.generate_oct_key/1 resolved %d contracts, want 1", len(got))
	}
	if len(got[0].Parameters) != 1 || got[0].Parameters[0].Contributes == nil {
		t.Fatal("Jwk.generate_oct_key/1 declares no contributing parameter")
	}
	if d := got[0].Parameters[0].Contributes.Derivation; d != "argument_byte_length" {
		t.Errorf("generate_oct_key derivation = %q, want argument_byte_length", d)
	}
	// Every RSA modulus size in this family IS bits, so the sibling must differ.
	rsa := kb.ContractsFor("josekit::jwk::Jwk.generate_rsa_key", 1)
	if len(rsa) != 1 || len(rsa[0].Parameters) != 1 || rsa[0].Parameters[0].Contributes == nil {
		t.Fatal("Jwk.generate_rsa_key/1 declares no contributing parameter")
	}
	if d := rsa[0].Parameters[0].Contributes.Derivation; d != "argument_value" {
		t.Errorf("generate_rsa_key derivation = %q, want argument_value", d)
	}
}
