// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// mbedtlsContract pins one Mbed TLS contract: the call identity the C parser
// emits, its lifecycle role, the library file that owns it, and every parameter
// role as "index:role:property:derivation".
type mbedtlsContract struct {
	method     string
	arity      int
	role       string
	library    string
	parameters []string
}

// mbedtlsContracts lists every contract in c/mbedtls.yaml (legacy mbedtls_*)
// and c/mbedtls-psa.yaml (PSA Crypto). A deleted contract, a changed arity, a
// flipped lifecycle role or a changed parameter role fails the test.
var mbedtlsContracts = []mbedtlsContract{
	{"mbedtls_lms_export_public_key", 4, "output", "mbedtls", nil},
	{"mbedtls_lms_generate_private_key", 7, "factory", "mbedtls", []string{"1:operation-determining:parameterSet:argument_value", "2:operation-determining:parameterSet:argument_value", "6:metadata-contributing:seedLength:argument_value"}},
	{"mbedtls_lms_import_public_key", 3, "config", "mbedtls", []string{"2:metadata-contributing:keyLength:argument_value"}},
	{"mbedtls_lms_private_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_lms_public_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_lms_sign", 8, "operation", "mbedtls", []string{"4:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_lms_verify", 5, "operation", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value", "4:metadata-contributing:signatureLength:argument_value"}},
	{"mbedtls_pk_import_into_psa", 3, "factory", "mbedtls", nil},
	{"mbedtls_pk_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_pk_sign", 9, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value", "3:metadata-contributing:digestLength:argument_value"}},
	{"mbedtls_pk_verify", 6, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value", "3:metadata-contributing:digestLength:argument_value", "5:metadata-contributing:signatureLength:argument_value"}},
	{"mbedtls_rsa_gen_key", 5, "operation", "mbedtls", []string{"3:metadata-contributing:keySize:argument_value"}},
	{"mbedtls_pkcs7_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_pkcs7_signed_data_verify", 4, "operation", "mbedtls", []string{"3:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_pkcs7_signed_hash_verify", 4, "operation", "mbedtls", []string{"3:metadata-contributing:digestLength:argument_value"}},
	{"mbedtls_ssl_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_ssl_setup", 2, "config", "mbedtls", nil},
	{"mbedtls_x509_crl_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_x509_crl_parse", 3, "config", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_x509_crl_parse_der", 3, "config", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_x509_crl_parse_file", 2, "config", "mbedtls", nil},
	{"mbedtls_x509_crt_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_x509_crt_parse", 3, "config", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_x509_crt_parse_der", 3, "config", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_x509_crt_parse_file", 2, "config", "mbedtls", nil},
	{"mbedtls_x509_csr_init", 1, "factory", "mbedtls", nil},
	{"mbedtls_x509_csr_parse", 3, "config", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_x509_csr_parse_der", 3, "config", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_x509_csr_parse_file", 2, "config", "mbedtls", nil},
	{"mbedtls_lms_generate_private_key", 5, "factory", "mbedtls", []string{"1:operation-determining:parameterSet:argument_value", "2:operation-determining:parameterSet:argument_value", "4:metadata-contributing:seedLength:argument_value"}},
	{"mbedtls_lms_sign", 6, "operation", "mbedtls", []string{"2:metadata-contributing:dataLength:argument_value"}},
	{"mbedtls_pk_sign", 8, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value", "3:metadata-contributing:digestLength:argument_value"}},
	{"mbedtls_pk_sign", 7, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value", "3:metadata-contributing:digestLength:argument_value"}},
	{"mbedtls_cipher_info_from_type", 1, "factory", "mbedtls", []string{"0:operation-determining:algorithm:argument_value"}},
	{"mbedtls_md_info_from_type", 1, "factory", "mbedtls", []string{"0:operation-determining:algorithm:argument_value"}},
	{"mbedtls_aes_setkey_enc", 3, "config", "mbedtls", []string{"2:metadata-contributing:keySize:argument_value"}},
	{"mbedtls_aes_setkey_dec", 3, "config", "mbedtls", []string{"2:metadata-contributing:keySize:argument_value"}},
	{"mbedtls_aes_crypt_ecb", 4, "operation", "mbedtls", []string{"1:operation-determining:operation:argument_value"}},
	{"mbedtls_aes_crypt_cbc", 6, "operation", "mbedtls", []string{"1:operation-determining:operation:argument_value"}},
	{"mbedtls_aes_crypt_cfb128", 7, "operation", "mbedtls", []string{"1:operation-determining:operation:argument_value"}},
	{"mbedtls_aes_crypt_cfb8", 6, "operation", "mbedtls", []string{"1:operation-determining:operation:argument_value"}},
	{"mbedtls_aes_crypt_ofb", 6, "operation", "mbedtls", nil},
	{"mbedtls_aes_crypt_ctr", 7, "operation", "mbedtls", nil},
	{"mbedtls_aes_crypt_xts", 6, "operation", "mbedtls", []string{"1:operation-determining:operation:argument_value"}},
	{"mbedtls_gcm_crypt_and_tag", 11, "operation", "mbedtls", []string{"1:operation-determining:operation:argument_value"}},
	{"mbedtls_gcm_auth_decrypt", 10, "operation", "mbedtls", nil},
	{"mbedtls_ccm_encrypt_and_tag", 10, "operation", "mbedtls", nil},
	{"mbedtls_ccm_auth_decrypt", 10, "operation", "mbedtls", nil},
	{"mbedtls_ccm_star_encrypt_and_tag", 10, "operation", "mbedtls", nil},
	{"mbedtls_ccm_star_auth_decrypt", 10, "operation", "mbedtls", nil},
	{"mbedtls_chachapoly_encrypt_and_tag", 8, "operation", "mbedtls", nil},
	{"mbedtls_chachapoly_auth_decrypt", 8, "operation", "mbedtls", nil},
	{"mbedtls_md5", 3, "operation", "mbedtls", nil},
	{"mbedtls_md5_ret", 3, "operation", "mbedtls", nil},
	{"mbedtls_ripemd160", 3, "operation", "mbedtls", nil},
	{"mbedtls_ripemd160_ret", 3, "operation", "mbedtls", nil},
	{"mbedtls_sha1", 3, "operation", "mbedtls", nil},
	{"mbedtls_sha1_ret", 3, "operation", "mbedtls", nil},
	{"mbedtls_sha256", 4, "operation", "mbedtls", []string{"3:operation-determining:algorithm:argument_value"}},
	{"mbedtls_sha256_ret", 4, "operation", "mbedtls", []string{"3:operation-determining:algorithm:argument_value"}},
	{"mbedtls_sha512", 4, "operation", "mbedtls", []string{"3:operation-determining:algorithm:argument_value"}},
	{"mbedtls_sha512_ret", 4, "operation", "mbedtls", []string{"3:operation-determining:algorithm:argument_value"}},
	{"mbedtls_sha3", 5, "operation", "mbedtls", []string{"0:operation-determining:algorithm:argument_value"}},
	{"mbedtls_md_hmac", 6, "operation", "mbedtls", []string{"0:operation-determining:algorithm:argument_value", "2:metadata-contributing:keySize:argument_byte_length"}},
	{"mbedtls_hkdf", 9, "operation", "mbedtls", []string{"0:operation-determining:algorithm:argument_value", "8:metadata-contributing:outputLength:argument_value"}},
	{"mbedtls_pkcs5_pbkdf2_hmac_ext", 8, "operation", "mbedtls", []string{"0:operation-determining:algorithm:argument_value", "5:metadata-contributing:iterations:argument_value", "6:metadata-contributing:outputLength:argument_value"}},
	{"mbedtls_ecp_group_load", 2, "config", "mbedtls", []string{"1:operation-determining:curve:argument_value"}},
	{"mbedtls_ecp_gen_key", 4, "operation", "mbedtls", []string{"0:operation-determining:curve:argument_value"}},
	{"mbedtls_ecp_read_key", 4, "config", "mbedtls", []string{"0:operation-determining:curve:argument_value"}},
	{"mbedtls_ecdsa_genkey", 4, "operation", "mbedtls", []string{"1:operation-determining:curve:argument_value"}},
	{"mbedtls_ecdh_setup", 2, "config", "mbedtls", []string{"1:operation-determining:curve:argument_value"}},
	{"mbedtls_ecdh_calc_secret", 6, "operation", "mbedtls", nil},
	{"mbedtls_ecdh_compute_shared", 6, "operation", "mbedtls", nil},
	{"mbedtls_ecdsa_write_signature", 8, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value"}},
	{"mbedtls_ecdsa_write_signature", 9, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value"}},
	{"mbedtls_ecdsa_write_signature_restartable", 9, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value"}},
	{"mbedtls_ecdsa_write_signature_restartable", 10, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value"}},
	{"mbedtls_ecdsa_sign", 8, "operation", "mbedtls", nil},
	{"mbedtls_ecdsa_sign_det_ext", 9, "operation", "mbedtls", []string{"6:operation-determining:algorithm:argument_value"}},
	{"mbedtls_ecdsa_sign_restartable", 11, "operation", "mbedtls", nil},
	{"mbedtls_ecdsa_read_signature", 5, "operation", "mbedtls", nil},
	{"mbedtls_ecdsa_read_signature_restartable", 6, "operation", "mbedtls", nil},
	{"mbedtls_ecdsa_verify", 6, "operation", "mbedtls", nil},
	{"mbedtls_ecdsa_verify_restartable", 7, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_oaep_encrypt", 9, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_oaep_encrypt", 8, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_oaep_decrypt", 10, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_oaep_decrypt", 9, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_pkcs1_v15_encrypt", 7, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_pkcs1_v15_encrypt", 6, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_pkcs1_v15_decrypt", 8, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsaes_pkcs1_v15_decrypt", 7, "operation", "mbedtls", nil},
	{"mbedtls_rsa_rsassa_pkcs1_v15_sign", 8, "operation", "mbedtls", []string{"4:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pkcs1_v15_sign", 7, "operation", "mbedtls", []string{"3:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pkcs1_v15_verify", 8, "operation", "mbedtls", []string{"4:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pkcs1_v15_verify", 5, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pss_sign", 8, "operation", "mbedtls", []string{"4:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pss_sign", 7, "operation", "mbedtls", []string{"3:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pss_sign_ext", 8, "operation", "mbedtls", []string{"3:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pss_verify", 8, "operation", "mbedtls", []string{"4:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pss_verify", 5, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value"}},
	{"mbedtls_rsa_rsassa_pss_verify_ext", 10, "operation", "mbedtls", []string{"4:operation-determining:algorithm:argument_value", "7:metadata-contributing:maskGenerationFunction:argument_value"}},
	{"mbedtls_rsa_rsassa_pss_verify_ext", 7, "operation", "mbedtls", []string{"1:operation-determining:algorithm:argument_value", "4:metadata-contributing:maskGenerationFunction:argument_value"}},
	{"mbedtls_ssl_config_defaults", 4, "config", "mbedtls", []string{"2:operation-determining:protocol:argument_value"}},
	{"mbedtls_ssl_conf_min_tls_version", 2, "config", "mbedtls", []string{"1:operation-determining:protocolVersion:argument_value"}},
	{"mbedtls_ssl_conf_max_tls_version", 2, "config", "mbedtls", []string{"1:operation-determining:protocolVersion:argument_value"}},
	{"mbedtls_ssl_conf_min_version", 3, "config", "mbedtls", []string{"2:operation-determining:protocolVersion:argument_value"}},
	{"mbedtls_ssl_conf_max_version", 3, "config", "mbedtls", []string{"2:operation-determining:protocolVersion:argument_value"}},
	{"psa_crypto_init", 0, "config", "mbedtls-psa", nil},
	{"psa_key_attributes_init", 0, "factory", "mbedtls-psa", nil},
	{"psa_set_key_type", 2, "config", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_set_key_bits", 2, "config", "mbedtls-psa", []string{"1:metadata-contributing:keySize:argument_value"}},
	{"psa_set_key_algorithm", 2, "config", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_set_key_enrollment_algorithm", 2, "config", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_set_key_usage_flags", 2, "config", "mbedtls-psa", nil},
	{"psa_set_key_id", 2, "config", "mbedtls-psa", nil},
	{"psa_set_key_lifetime", 2, "config", "mbedtls-psa", nil},
	{"psa_get_key_attributes", 2, "output", "mbedtls-psa", nil},
	{"psa_generate_key", 2, "operation", "mbedtls-psa", nil},
	{"psa_generate_key_ext", 4, "operation", "mbedtls-psa", nil},
	{"psa_generate_key_custom", 5, "operation", "mbedtls-psa", nil},
	{"psa_import_key", 4, "factory", "mbedtls-psa", nil},
	{"psa_copy_key", 3, "factory", "mbedtls-psa", nil},
	{"psa_export_key", 4, "output", "mbedtls-psa", nil},
	{"psa_export_public_key", 4, "output", "mbedtls-psa", nil},
	{"psa_hash_compute", 6, "operation", "mbedtls-psa", []string{"0:operation-determining:algorithm:argument_value"}},
	{"psa_hash_compare", 5, "operation", "mbedtls-psa", []string{"0:operation-determining:algorithm:argument_value"}},
	{"psa_hash_operation_init", 0, "factory", "mbedtls-psa", nil},
	{"psa_hash_setup", 2, "config", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_hash_update", 3, "operation", "mbedtls-psa", nil},
	{"psa_hash_finish", 4, "operation", "mbedtls-psa", nil},
	{"psa_hash_verify", 3, "operation", "mbedtls-psa", nil},
	{"psa_hash_clone", 2, "factory", "mbedtls-psa", nil},
	{"psa_mac_compute", 7, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_mac_verify", 6, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_mac_operation_init", 0, "factory", "mbedtls-psa", nil},
	{"psa_mac_sign_setup", 3, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_mac_verify_setup", 3, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_mac_update", 3, "operation", "mbedtls-psa", nil},
	{"psa_mac_sign_finish", 4, "operation", "mbedtls-psa", nil},
	{"psa_mac_verify_finish", 3, "operation", "mbedtls-psa", nil},
	{"psa_cipher_encrypt", 7, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_cipher_decrypt", 7, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_cipher_operation_init", 0, "factory", "mbedtls-psa", nil},
	{"psa_cipher_encrypt_setup", 3, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_cipher_decrypt_setup", 3, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_cipher_generate_iv", 4, "config", "mbedtls-psa", nil},
	{"psa_cipher_set_iv", 3, "config", "mbedtls-psa", nil},
	{"psa_cipher_update", 6, "operation", "mbedtls-psa", nil},
	{"psa_cipher_finish", 4, "operation", "mbedtls-psa", nil},
	{"psa_aead_encrypt", 11, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_aead_decrypt", 11, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_aead_operation_init", 0, "factory", "mbedtls-psa", nil},
	{"psa_aead_encrypt_setup", 3, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_aead_decrypt_setup", 3, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_aead_set_lengths", 3, "config", "mbedtls-psa", nil},
	{"psa_aead_generate_nonce", 4, "config", "mbedtls-psa", nil},
	{"psa_aead_set_nonce", 3, "config", "mbedtls-psa", nil},
	{"psa_aead_update_ad", 3, "operation", "mbedtls-psa", nil},
	{"psa_aead_update", 6, "operation", "mbedtls-psa", nil},
	{"psa_aead_finish", 7, "operation", "mbedtls-psa", nil},
	{"psa_aead_verify", 6, "operation", "mbedtls-psa", nil},
	{"psa_sign_message", 7, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_verify_message", 6, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_sign_hash", 7, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_verify_hash", 6, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_asymmetric_sign", 7, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_asymmetric_verify", 6, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_sign_hash_start", 5, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_sign_hash_complete", 4, "operation", "mbedtls-psa", nil},
	{"psa_verify_hash_start", 7, "config", "mbedtls-psa", []string{"2:operation-determining:algorithm:argument_value"}},
	{"psa_verify_hash_complete", 1, "operation", "mbedtls-psa", nil},
	{"psa_asymmetric_encrypt", 9, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_asymmetric_decrypt", 9, "operation", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_raw_key_agreement", 7, "operation", "mbedtls-psa", []string{"0:operation-determining:algorithm:argument_value"}},
	{"psa_key_agreement", 6, "operation", "mbedtls-psa", []string{"3:operation-determining:algorithm:argument_value"}},
	{"psa_key_derivation_operation_init", 0, "factory", "mbedtls-psa", nil},
	{"psa_key_derivation_setup", 2, "config", "mbedtls-psa", []string{"1:operation-determining:algorithm:argument_value"}},
	{"psa_key_derivation_set_capacity", 2, "config", "mbedtls-psa", nil},
	{"psa_key_derivation_input_bytes", 4, "config", "mbedtls-psa", nil},
	{"psa_key_derivation_input_integer", 3, "config", "mbedtls-psa", nil},
	{"psa_key_derivation_input_key", 3, "config", "mbedtls-psa", nil},
	{"psa_key_derivation_key_agreement", 5, "operation", "mbedtls-psa", nil},
	{"psa_key_derivation_output_bytes", 3, "operation", "mbedtls-psa", []string{"2:metadata-contributing:outputLength:argument_value"}},
	{"psa_key_derivation_output_key", 3, "operation", "mbedtls-psa", nil},
	{"psa_key_derivation_output_key_ext", 5, "operation", "mbedtls-psa", nil},
	{"psa_key_derivation_output_key_custom", 6, "operation", "mbedtls-psa", nil},
	{"psa_key_derivation_verify_bytes", 3, "operation", "mbedtls-psa", nil},
	{"psa_key_derivation_verify_key", 2, "operation", "mbedtls-psa", nil},
}

// The Mbed TLS contracts key on bare C function names, which is what the C
// parser emits for a free-function call. Every contracted call is written out
// once with the arity the parser counts; the uncontracted teardown and
// attribute-read calls, and the anchor names no header declares, must resolve
// to nothing.
func TestMbedTLSContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <psa/crypto.h>
#include <mbedtls/ssl.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10) {
    mbedtls_lms_export_public_key(a0, a1, a2, a3);
    mbedtls_lms_generate_private_key(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_lms_import_public_key(a0, a1, a2);
    mbedtls_lms_private_init(a0);
    mbedtls_lms_public_init(a0);
    mbedtls_lms_sign(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_lms_verify(a0, a1, a2, a3, a4);
    mbedtls_pk_import_into_psa(a0, a1, a2);
    mbedtls_pk_init(a0);
    mbedtls_pk_sign(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    mbedtls_pk_verify(a0, a1, a2, a3, a4, a5);
    mbedtls_rsa_gen_key(a0, a1, a2, a3, a4);
    mbedtls_pkcs7_init(a0);
    mbedtls_pkcs7_signed_data_verify(a0, a1, a2, a3);
    mbedtls_pkcs7_signed_hash_verify(a0, a1, a2, a3);
    mbedtls_ssl_init(a0);
    mbedtls_ssl_setup(a0, a1);
    mbedtls_x509_crl_init(a0);
    mbedtls_x509_crl_parse(a0, a1, a2);
    mbedtls_x509_crl_parse_der(a0, a1, a2);
    mbedtls_x509_crl_parse_file(a0, a1);
    mbedtls_x509_crt_init(a0);
    mbedtls_x509_crt_parse(a0, a1, a2);
    mbedtls_x509_crt_parse_der(a0, a1, a2);
    mbedtls_x509_crt_parse_file(a0, a1);
    mbedtls_x509_csr_init(a0);
    mbedtls_x509_csr_parse(a0, a1, a2);
    mbedtls_x509_csr_parse_der(a0, a1, a2);
    mbedtls_x509_csr_parse_file(a0, a1);
    mbedtls_lms_generate_private_key(a0, a1, a2, a3, a4);
    mbedtls_lms_sign(a0, a1, a2, a3, a4, a5);
    mbedtls_pk_sign(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_pk_sign(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_cipher_info_from_type(a0);
    mbedtls_md_info_from_type(a0);
    mbedtls_aes_setkey_enc(a0, a1, a2);
    mbedtls_aes_setkey_dec(a0, a1, a2);
    mbedtls_aes_crypt_ecb(a0, a1, a2, a3);
    mbedtls_aes_crypt_cbc(a0, a1, a2, a3, a4, a5);
    mbedtls_aes_crypt_cfb128(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_aes_crypt_cfb8(a0, a1, a2, a3, a4, a5);
    mbedtls_aes_crypt_ofb(a0, a1, a2, a3, a4, a5);
    mbedtls_aes_crypt_ctr(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_aes_crypt_xts(a0, a1, a2, a3, a4, a5);
    mbedtls_gcm_crypt_and_tag(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    mbedtls_gcm_auth_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_ccm_encrypt_and_tag(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_ccm_auth_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_ccm_star_encrypt_and_tag(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_ccm_star_auth_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_chachapoly_encrypt_and_tag(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_chachapoly_auth_decrypt(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_md5(a0, a1, a2);
    mbedtls_md5_ret(a0, a1, a2);
    mbedtls_ripemd160(a0, a1, a2);
    mbedtls_ripemd160_ret(a0, a1, a2);
    mbedtls_sha1(a0, a1, a2);
    mbedtls_sha1_ret(a0, a1, a2);
    mbedtls_sha256(a0, a1, a2, a3);
    mbedtls_sha256_ret(a0, a1, a2, a3);
    mbedtls_sha512(a0, a1, a2, a3);
    mbedtls_sha512_ret(a0, a1, a2, a3);
    mbedtls_sha3(a0, a1, a2, a3, a4);
    mbedtls_md_hmac(a0, a1, a2, a3, a4, a5);
    mbedtls_hkdf(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    mbedtls_pkcs5_pbkdf2_hmac_ext(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_ecp_group_load(a0, a1);
    mbedtls_ecp_gen_key(a0, a1, a2, a3);
    mbedtls_ecp_read_key(a0, a1, a2, a3);
    mbedtls_ecdsa_genkey(a0, a1, a2, a3);
    mbedtls_ecdh_setup(a0, a1);
    mbedtls_ecdh_calc_secret(a0, a1, a2, a3, a4, a5);
    mbedtls_ecdh_compute_shared(a0, a1, a2, a3, a4, a5);
    mbedtls_ecdsa_write_signature(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_ecdsa_write_signature(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    mbedtls_ecdsa_write_signature_restartable(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    mbedtls_ecdsa_write_signature_restartable(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_ecdsa_sign(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_ecdsa_sign_det_ext(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    mbedtls_ecdsa_sign_restartable(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    mbedtls_ecdsa_read_signature(a0, a1, a2, a3, a4);
    mbedtls_ecdsa_read_signature_restartable(a0, a1, a2, a3, a4, a5);
    mbedtls_ecdsa_verify(a0, a1, a2, a3, a4, a5);
    mbedtls_ecdsa_verify_restartable(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_rsa_rsaes_oaep_encrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    mbedtls_rsa_rsaes_oaep_encrypt(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_rsa_rsaes_oaep_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_rsa_rsaes_oaep_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    mbedtls_rsa_rsaes_pkcs1_v15_encrypt(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_rsa_rsaes_pkcs1_v15_encrypt(a0, a1, a2, a3, a4, a5);
    mbedtls_rsa_rsaes_pkcs1_v15_decrypt(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_rsa_rsaes_pkcs1_v15_decrypt(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_rsa_rsassa_pkcs1_v15_sign(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_rsa_rsassa_pkcs1_v15_sign(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_rsa_rsassa_pkcs1_v15_verify(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_rsa_rsassa_pkcs1_v15_verify(a0, a1, a2, a3, a4);
    mbedtls_rsa_rsassa_pss_sign(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_rsa_rsassa_pss_sign(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_rsa_rsassa_pss_sign_ext(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_rsa_rsassa_pss_verify(a0, a1, a2, a3, a4, a5, a6, a7);
    mbedtls_rsa_rsassa_pss_verify(a0, a1, a2, a3, a4);
    mbedtls_rsa_rsassa_pss_verify_ext(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    mbedtls_rsa_rsassa_pss_verify_ext(a0, a1, a2, a3, a4, a5, a6);
    mbedtls_ssl_config_defaults(a0, a1, a2, a3);
    mbedtls_ssl_conf_min_tls_version(a0, a1);
    mbedtls_ssl_conf_max_tls_version(a0, a1);
    mbedtls_ssl_conf_min_version(a0, a1, a2);
    mbedtls_ssl_conf_max_version(a0, a1, a2);
    psa_crypto_init();
    psa_key_attributes_init();
    psa_set_key_type(a0, a1);
    psa_set_key_bits(a0, a1);
    psa_set_key_algorithm(a0, a1);
    psa_set_key_enrollment_algorithm(a0, a1);
    psa_set_key_usage_flags(a0, a1);
    psa_set_key_id(a0, a1);
    psa_set_key_lifetime(a0, a1);
    psa_get_key_attributes(a0, a1);
    psa_generate_key(a0, a1);
    psa_generate_key_ext(a0, a1, a2, a3);
    psa_generate_key_custom(a0, a1, a2, a3, a4);
    psa_import_key(a0, a1, a2, a3);
    psa_copy_key(a0, a1, a2);
    psa_export_key(a0, a1, a2, a3);
    psa_export_public_key(a0, a1, a2, a3);
    psa_hash_compute(a0, a1, a2, a3, a4, a5);
    psa_hash_compare(a0, a1, a2, a3, a4);
    psa_hash_operation_init();
    psa_hash_setup(a0, a1);
    psa_hash_update(a0, a1, a2);
    psa_hash_finish(a0, a1, a2, a3);
    psa_hash_verify(a0, a1, a2);
    psa_hash_clone(a0, a1);
    psa_mac_compute(a0, a1, a2, a3, a4, a5, a6);
    psa_mac_verify(a0, a1, a2, a3, a4, a5);
    psa_mac_operation_init();
    psa_mac_sign_setup(a0, a1, a2);
    psa_mac_verify_setup(a0, a1, a2);
    psa_mac_update(a0, a1, a2);
    psa_mac_sign_finish(a0, a1, a2, a3);
    psa_mac_verify_finish(a0, a1, a2);
    psa_cipher_encrypt(a0, a1, a2, a3, a4, a5, a6);
    psa_cipher_decrypt(a0, a1, a2, a3, a4, a5, a6);
    psa_cipher_operation_init();
    psa_cipher_encrypt_setup(a0, a1, a2);
    psa_cipher_decrypt_setup(a0, a1, a2);
    psa_cipher_generate_iv(a0, a1, a2, a3);
    psa_cipher_set_iv(a0, a1, a2);
    psa_cipher_update(a0, a1, a2, a3, a4, a5);
    psa_cipher_finish(a0, a1, a2, a3);
    psa_aead_encrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    psa_aead_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    psa_aead_operation_init();
    psa_aead_encrypt_setup(a0, a1, a2);
    psa_aead_decrypt_setup(a0, a1, a2);
    psa_aead_set_lengths(a0, a1, a2);
    psa_aead_generate_nonce(a0, a1, a2, a3);
    psa_aead_set_nonce(a0, a1, a2);
    psa_aead_update_ad(a0, a1, a2);
    psa_aead_update(a0, a1, a2, a3, a4, a5);
    psa_aead_finish(a0, a1, a2, a3, a4, a5, a6);
    psa_aead_verify(a0, a1, a2, a3, a4, a5);
    psa_sign_message(a0, a1, a2, a3, a4, a5, a6);
    psa_verify_message(a0, a1, a2, a3, a4, a5);
    psa_sign_hash(a0, a1, a2, a3, a4, a5, a6);
    psa_verify_hash(a0, a1, a2, a3, a4, a5);
    psa_asymmetric_sign(a0, a1, a2, a3, a4, a5, a6);
    psa_asymmetric_verify(a0, a1, a2, a3, a4, a5);
    psa_sign_hash_start(a0, a1, a2, a3, a4);
    psa_sign_hash_complete(a0, a1, a2, a3);
    psa_verify_hash_start(a0, a1, a2, a3, a4, a5, a6);
    psa_verify_hash_complete(a0);
    psa_asymmetric_encrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    psa_asymmetric_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    psa_raw_key_agreement(a0, a1, a2, a3, a4, a5, a6);
    psa_key_agreement(a0, a1, a2, a3, a4, a5);
    psa_key_derivation_operation_init();
    psa_key_derivation_setup(a0, a1);
    psa_key_derivation_set_capacity(a0, a1);
    psa_key_derivation_input_bytes(a0, a1, a2, a3);
    psa_key_derivation_input_integer(a0, a1, a2);
    psa_key_derivation_input_key(a0, a1, a2);
    psa_key_derivation_key_agreement(a0, a1, a2, a3, a4);
    psa_key_derivation_output_bytes(a0, a1, a2);
    psa_key_derivation_output_key(a0, a1, a2);
    psa_key_derivation_output_key_ext(a0, a1, a2, a3, a4);
    psa_key_derivation_output_key_custom(a0, a1, a2, a3, a4, a5);
    psa_key_derivation_verify_bytes(a0, a1, a2);
    psa_key_derivation_verify_key(a0, a1);
}

void not_contracted(void *a0, void *a1) {
    psa_destroy_key(a0);
    psa_hash_abort(a0);
    psa_reset_key_attributes(a0);
    psa_get_key_bits(a0);
    psa_generate_random(a0, a1);
    psa_set_key_identifier(a0, a1);
    mbedtls_aes_init(a0);
    mbedtls_aes_free(a0);
    mbedtls_gcm_encrypt_and_tag(a0, a1);
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]mbedtlsContract{}
	for _, c := range mbedtlsContracts {
		want[fmt.Sprintf("%s/%d", c.method, c.arity)] = c
	}
	negative := []string{
		"psa_destroy_key", "psa_hash_abort", "psa_reset_key_attributes", "psa_get_key_bits",
		"psa_generate_random", "psa_set_key_identifier", "mbedtls_aes_init", "mbedtls_aes_free",
		"mbedtls_gcm_encrypt_and_tag",
	}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				bare := method
				if idx := strings.LastIndex(bare, "."); idx >= 0 {
					bare = bare[idx+1:]
				}
				if slices.Contains(negative, bare) {
					if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
						t.Errorf("%s/%d resolved to %d contract(s), want none", bare, len(call.Arguments), len(got))
					}
					seen[bare] = true
					continue
				}
				key := fmt.Sprintf("%s/%d", bare, len(call.Arguments))
				expect, ok := want[key]
				if !ok {
					continue
				}
				seen[key] = true
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Errorf("ContractsForCFunction(%q, %d) = %d, want exactly one contract", method, expect.arity, len(got))
					continue
				}
				c := got[0]
				if c.Role != expect.role || c.SourceLibrary != expect.library || c.Return.Confidence != "high" {
					t.Errorf("%s: role %q library %q confidence %q, want %q %q high", key, c.Role, c.SourceLibrary, c.Return.Confidence, expect.role, expect.library)
				}
				var params []string
				for _, p := range c.Parameters {
					if p.Index == nil || p.Contributes == nil {
						t.Errorf("%s: parameter %#v has no index or contribution", key, p)
						continue
					}
					params = append(params, fmt.Sprintf("%d:%s:%s:%s", *p.Index, p.Role, p.Contributes.Property, p.Contributes.Derivation))
				}
				if !slices.Equal(params, expect.parameters) {
					t.Errorf("%s: parameters = %v, want %v", key, params, expect.parameters)
				}
			}
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("parsed calls did not cover %s", key)
		}
	}
	for _, n := range negative {
		if !seen[n] {
			t.Errorf("parsed calls did not cover negative %s", n)
		}
	}

	// Nothing outside the pinned list may carry an Mbed TLS contract.
	for _, group := range kb.Contracts {
		for _, c := range group {
			if c.SourceLibrary != "mbedtls" && c.SourceLibrary != "mbedtls-psa" {
				continue
			}
			if _, ok := want[fmt.Sprintf("%s/%d", c.Method, c.Arity)]; !ok {
				t.Errorf("%s/%d (%s) is contracted but not pinned in mbedtlsContracts", c.Method, c.Arity, c.SourceLibrary)
			}
		}
	}
}
