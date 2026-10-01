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

// The libsodium contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: calls outside the contracted surface resolve to nothing.
func TestLibsodiumExtensionContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <sodium.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9) {
    crypto_aead_aes256gcm_beforenm(a0, a1);
    crypto_aead_aes256gcm_decrypt_afternm(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    crypto_aead_aes256gcm_decrypt_detached_afternm(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    crypto_aead_aes256gcm_encrypt_afternm(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    crypto_aead_aes256gcm_encrypt_detached_afternm(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    crypto_auth_hmacsha256(a0, a1, a2, a3);
    crypto_auth_hmacsha256_final(a0, a1);
    crypto_auth_hmacsha256_init(a0, a1, a2);
    crypto_auth_hmacsha256_keygen(a0);
    crypto_auth_hmacsha256_update(a0, a1, a2);
    crypto_auth_hmacsha256_verify(a0, a1, a2, a3);
    crypto_auth_hmacsha512(a0, a1, a2, a3);
    crypto_auth_hmacsha512_final(a0, a1);
    crypto_auth_hmacsha512_init(a0, a1, a2);
    crypto_auth_hmacsha512_keygen(a0);
    crypto_auth_hmacsha512_update(a0, a1, a2);
    crypto_auth_hmacsha512_verify(a0, a1, a2, a3);
    crypto_auth_hmacsha512256(a0, a1, a2, a3);
    crypto_auth_hmacsha512256_final(a0, a1);
    crypto_auth_hmacsha512256_init(a0, a1, a2);
    crypto_auth_hmacsha512256_keygen(a0);
    crypto_auth_hmacsha512256_update(a0, a1, a2);
    crypto_auth_hmacsha512256_verify(a0, a1, a2, a3);
    crypto_box(a0, a1, a2, a3, a4, a5);
    crypto_box_afternm(a0, a1, a2, a3, a4);
    crypto_box_open(a0, a1, a2, a3, a4, a5);
    crypto_box_open_afternm(a0, a1, a2, a3, a4);
    crypto_box_curve25519xchacha20poly1305_beforenm(a0, a1, a2);
    crypto_box_curve25519xchacha20poly1305_detached(a0, a1, a2, a3, a4, a5, a6);
    crypto_box_curve25519xchacha20poly1305_detached_afternm(a0, a1, a2, a3, a4, a5);
    crypto_box_curve25519xchacha20poly1305_easy(a0, a1, a2, a3, a4, a5);
    crypto_box_curve25519xchacha20poly1305_easy_afternm(a0, a1, a2, a3, a4);
    crypto_box_curve25519xchacha20poly1305_keypair(a0, a1);
    crypto_box_curve25519xchacha20poly1305_open_detached(a0, a1, a2, a3, a4, a5, a6);
    crypto_box_curve25519xchacha20poly1305_open_detached_afternm(a0, a1, a2, a3, a4, a5);
    crypto_box_curve25519xchacha20poly1305_open_easy(a0, a1, a2, a3, a4, a5);
    crypto_box_curve25519xchacha20poly1305_open_easy_afternm(a0, a1, a2, a3, a4);
    crypto_box_curve25519xchacha20poly1305_seal(a0, a1, a2, a3);
    crypto_box_curve25519xchacha20poly1305_seal_open(a0, a1, a2, a3, a4);
    crypto_box_curve25519xchacha20poly1305_seed_keypair(a0, a1, a2);
    crypto_box_curve25519xsalsa20poly1305(a0, a1, a2, a3, a4, a5);
    crypto_box_curve25519xsalsa20poly1305_afternm(a0, a1, a2, a3, a4);
    crypto_box_curve25519xsalsa20poly1305_beforenm(a0, a1, a2);
    crypto_box_curve25519xsalsa20poly1305_keypair(a0, a1);
    crypto_box_curve25519xsalsa20poly1305_open(a0, a1, a2, a3, a4, a5);
    crypto_box_curve25519xsalsa20poly1305_open_afternm(a0, a1, a2, a3, a4);
    crypto_box_curve25519xsalsa20poly1305_seed_keypair(a0, a1, a2);
    crypto_generichash_blake2b(a0, a1, a2, a3, a4, a5);
    crypto_generichash_blake2b_final(a0, a1, a2);
    crypto_generichash_blake2b_init(a0, a1, a2, a3);
    crypto_generichash_blake2b_init_salt_personal(a0, a1, a2, a3, a4, a5);
    crypto_generichash_blake2b_keygen(a0);
    crypto_generichash_blake2b_salt_personal(a0, a1, a2, a3, a4, a5, a6, a7);
    crypto_generichash_blake2b_update(a0, a1, a2);
    crypto_hash_sha256(a0, a1, a2);
    crypto_hash_sha256_final(a0, a1);
    crypto_hash_sha256_init(a0);
    crypto_hash_sha256_update(a0, a1, a2);
    crypto_hash_sha3256(a0, a1, a2);
    crypto_hash_sha3256_final(a0, a1);
    crypto_hash_sha3256_init(a0);
    crypto_hash_sha3256_update(a0, a1, a2);
    crypto_hash_sha3512(a0, a1, a2);
    crypto_hash_sha3512_final(a0, a1);
    crypto_hash_sha3512_init(a0);
    crypto_hash_sha3512_update(a0, a1, a2);
    crypto_hash_sha512(a0, a1, a2);
    crypto_hash_sha512_final(a0, a1);
    crypto_hash_sha512_init(a0);
    crypto_hash_sha512_update(a0, a1, a2);
    crypto_ipcrypt_decrypt(a0, a1, a2);
    crypto_ipcrypt_encrypt(a0, a1, a2);
    crypto_ipcrypt_keygen(a0);
    crypto_ipcrypt_nd_decrypt(a0, a1, a2);
    crypto_ipcrypt_nd_encrypt(a0, a1, a2, a3);
    crypto_ipcrypt_nd_keygen(a0);
    crypto_ipcrypt_ndx_decrypt(a0, a1, a2);
    crypto_ipcrypt_ndx_encrypt(a0, a1, a2, a3);
    crypto_ipcrypt_ndx_keygen(a0);
    crypto_ipcrypt_pfx_decrypt(a0, a1, a2);
    crypto_ipcrypt_pfx_encrypt(a0, a1, a2);
    crypto_ipcrypt_pfx_keygen(a0);
    crypto_kdf_blake2b_derive_from_key(a0, a1, a2, a3, a4);
    crypto_kdf_hkdf_sha256_expand(a0, a1, a2, a3, a4);
    crypto_kdf_hkdf_sha256_extract(a0, a1, a2, a3, a4);
    crypto_kdf_hkdf_sha256_extract_final(a0, a1);
    crypto_kdf_hkdf_sha256_extract_init(a0, a1, a2);
    crypto_kdf_hkdf_sha256_extract_update(a0, a1, a2);
    crypto_kdf_hkdf_sha256_keygen(a0);
    crypto_kdf_hkdf_sha512_expand(a0, a1, a2, a3, a4);
    crypto_kdf_hkdf_sha512_extract(a0, a1, a2, a3, a4);
    crypto_kdf_hkdf_sha512_extract_final(a0, a1);
    crypto_kdf_hkdf_sha512_extract_init(a0, a1, a2);
    crypto_kdf_hkdf_sha512_extract_update(a0, a1, a2);
    crypto_kdf_hkdf_sha512_keygen(a0);
    crypto_kem_mlkem768_dec(a0, a1, a2);
    crypto_kem_mlkem768_enc(a0, a1, a2);
    crypto_kem_mlkem768_enc_deterministic(a0, a1, a2, a3);
    crypto_kem_mlkem768_keypair(a0, a1);
    crypto_kem_mlkem768_seed_keypair(a0, a1, a2);
    crypto_kem_xwing_dec(a0, a1, a2);
    crypto_kem_xwing_enc(a0, a1, a2);
    crypto_kem_xwing_enc_deterministic(a0, a1, a2, a3);
    crypto_kem_xwing_keypair(a0, a1);
    crypto_kem_xwing_seed_keypair(a0, a1, a2);
    crypto_onetimeauth_poly1305(a0, a1, a2, a3);
    crypto_onetimeauth_poly1305_final(a0, a1);
    crypto_onetimeauth_poly1305_init(a0, a1);
    crypto_onetimeauth_poly1305_keygen(a0);
    crypto_onetimeauth_poly1305_update(a0, a1, a2);
    crypto_onetimeauth_poly1305_verify(a0, a1, a2, a3);
    crypto_pwhash_argon2i(a0, a1, a2, a3, a4, a5, a6, a7);
    crypto_pwhash_argon2i_str(a0, a1, a2, a3, a4);
    crypto_pwhash_argon2i_str_verify(a0, a1, a2);
    crypto_pwhash_argon2id(a0, a1, a2, a3, a4, a5, a6, a7);
    crypto_pwhash_argon2id_str(a0, a1, a2, a3, a4);
    crypto_pwhash_argon2id_str_verify(a0, a1, a2);
    crypto_pwhash_scryptsalsa208sha256(a0, a1, a2, a3, a4, a5, a6);
    crypto_pwhash_scryptsalsa208sha256_ll(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    crypto_pwhash_scryptsalsa208sha256_str(a0, a1, a2, a3, a4);
    crypto_pwhash_scryptsalsa208sha256_str_verify(a0, a1, a2);
    crypto_scalarmult_curve25519(a0, a1, a2);
    crypto_scalarmult_curve25519_base(a0, a1);
    crypto_secretbox(a0, a1, a2, a3, a4);
    crypto_secretbox_open(a0, a1, a2, a3, a4);
    crypto_secretbox_xchacha20poly1305_detached(a0, a1, a2, a3, a4, a5);
    crypto_secretbox_xchacha20poly1305_easy(a0, a1, a2, a3, a4);
    crypto_secretbox_xchacha20poly1305_open_detached(a0, a1, a2, a3, a4, a5);
    crypto_secretbox_xchacha20poly1305_open_easy(a0, a1, a2, a3, a4);
    crypto_secretbox_xsalsa20poly1305(a0, a1, a2, a3, a4);
    crypto_secretbox_xsalsa20poly1305_keygen(a0);
    crypto_secretbox_xsalsa20poly1305_open(a0, a1, a2, a3, a4);
    crypto_shorthash_siphash24(a0, a1, a2, a3);
    crypto_shorthash_siphashx24(a0, a1, a2, a3);
    crypto_sign_ed25519(a0, a1, a2, a3, a4);
    crypto_sign_ed25519_detached(a0, a1, a2, a3, a4);
    crypto_sign_ed25519_keypair(a0, a1);
    crypto_sign_ed25519_open(a0, a1, a2, a3, a4);
    crypto_sign_ed25519_seed_keypair(a0, a1, a2);
    crypto_sign_ed25519_verify_detached(a0, a1, a2, a3);
    crypto_sign_ed25519ph_final_create(a0, a1, a2, a3);
    crypto_sign_ed25519ph_final_verify(a0, a1, a2);
    crypto_sign_ed25519ph_init(a0);
    crypto_sign_ed25519ph_update(a0, a1, a2);
    crypto_stream_chacha20(a0, a1, a2, a3);
    crypto_stream_chacha20_ietf(a0, a1, a2, a3);
    crypto_stream_chacha20_ietf_keygen(a0);
    crypto_stream_chacha20_ietf_xor(a0, a1, a2, a3, a4);
    crypto_stream_chacha20_ietf_xor_ic(a0, a1, a2, a3, a4, a5);
    crypto_stream_chacha20_keygen(a0);
    crypto_stream_chacha20_xor(a0, a1, a2, a3, a4);
    crypto_stream_chacha20_xor_ic(a0, a1, a2, a3, a4, a5);
    crypto_stream_salsa20(a0, a1, a2, a3);
    crypto_stream_salsa20_keygen(a0);
    crypto_stream_salsa20_xor(a0, a1, a2, a3, a4);
    crypto_stream_salsa20_xor_ic(a0, a1, a2, a3, a4, a5);
    crypto_stream_xchacha20(a0, a1, a2, a3);
    crypto_stream_xchacha20_keygen(a0);
    crypto_stream_xchacha20_xor(a0, a1, a2, a3, a4);
    crypto_stream_xchacha20_xor_ic(a0, a1, a2, a3, a4, a5);
    crypto_stream_xsalsa20(a0, a1, a2, a3);
    crypto_stream_xsalsa20_keygen(a0);
    crypto_stream_xsalsa20_xor(a0, a1, a2, a3, a4);
    crypto_stream_xsalsa20_xor_ic(a0, a1, a2, a3, a4, a5);
    crypto_xof_shake128(a0, a1, a2, a3);
    crypto_xof_shake128_init(a0);
    crypto_xof_shake128_squeeze(a0, a1, a2);
    crypto_xof_shake128_update(a0, a1, a2);
    crypto_xof_shake256(a0, a1, a2, a3);
    crypto_xof_shake256_init(a0);
    crypto_xof_shake256_squeeze(a0, a1, a2);
    crypto_xof_shake256_update(a0, a1, a2);
    crypto_xof_turboshake128(a0, a1, a2, a3);
    crypto_xof_turboshake128_init(a0);
    crypto_xof_turboshake128_squeeze(a0, a1, a2);
    crypto_xof_turboshake128_update(a0, a1, a2);
    crypto_xof_turboshake256(a0, a1, a2, a3);
    crypto_xof_turboshake256_init(a0);
    crypto_xof_turboshake256_squeeze(a0, a1, a2);
    crypto_xof_turboshake256_update(a0, a1, a2);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9) {
    crypto_kem_keypair(a0, a1);
    crypto_kem_enc(a0, a1, a2);
    crypto_hash_sha256_bytes();
    crypto_kem_mlkem768_publickeybytes();
    crypto_pwhash_argon2id_str_needs_rehash(a0, a1, a2);
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct {
		arity int
		role  string
	}{
		"crypto_aead_aes256gcm_beforenm":                               {2, "factory"},
		"crypto_aead_aes256gcm_decrypt_afternm":                        {9, "operation"},
		"crypto_aead_aes256gcm_decrypt_detached_afternm":               {9, "operation"},
		"crypto_aead_aes256gcm_encrypt_afternm":                        {9, "operation"},
		"crypto_aead_aes256gcm_encrypt_detached_afternm":               {10, "operation"},
		"crypto_auth_hmacsha256":                                       {4, "operation"},
		"crypto_auth_hmacsha256_final":                                 {2, "operation"},
		"crypto_auth_hmacsha256_init":                                  {3, "config"},
		"crypto_auth_hmacsha256_keygen":                                {1, "factory"},
		"crypto_auth_hmacsha256_update":                                {3, "operation"},
		"crypto_auth_hmacsha256_verify":                                {4, "operation"},
		"crypto_auth_hmacsha512":                                       {4, "operation"},
		"crypto_auth_hmacsha512_final":                                 {2, "operation"},
		"crypto_auth_hmacsha512_init":                                  {3, "config"},
		"crypto_auth_hmacsha512_keygen":                                {1, "factory"},
		"crypto_auth_hmacsha512_update":                                {3, "operation"},
		"crypto_auth_hmacsha512_verify":                                {4, "operation"},
		"crypto_auth_hmacsha512256":                                    {4, "operation"},
		"crypto_auth_hmacsha512256_final":                              {2, "operation"},
		"crypto_auth_hmacsha512256_init":                               {3, "config"},
		"crypto_auth_hmacsha512256_keygen":                             {1, "factory"},
		"crypto_auth_hmacsha512256_update":                             {3, "operation"},
		"crypto_auth_hmacsha512256_verify":                             {4, "operation"},
		"crypto_box":                                                   {6, "operation"},
		"crypto_box_afternm":                                           {5, "operation"},
		"crypto_box_open":                                              {6, "operation"},
		"crypto_box_open_afternm":                                      {5, "operation"},
		"crypto_box_curve25519xchacha20poly1305_beforenm":              {3, "factory"},
		"crypto_box_curve25519xchacha20poly1305_detached":              {7, "operation"},
		"crypto_box_curve25519xchacha20poly1305_detached_afternm":      {6, "operation"},
		"crypto_box_curve25519xchacha20poly1305_easy":                  {6, "operation"},
		"crypto_box_curve25519xchacha20poly1305_easy_afternm":          {5, "operation"},
		"crypto_box_curve25519xchacha20poly1305_keypair":               {2, "factory"},
		"crypto_box_curve25519xchacha20poly1305_open_detached":         {7, "operation"},
		"crypto_box_curve25519xchacha20poly1305_open_detached_afternm": {6, "operation"},
		"crypto_box_curve25519xchacha20poly1305_open_easy":             {6, "operation"},
		"crypto_box_curve25519xchacha20poly1305_open_easy_afternm":     {5, "operation"},
		"crypto_box_curve25519xchacha20poly1305_seal":                  {4, "operation"},
		"crypto_box_curve25519xchacha20poly1305_seal_open":             {5, "operation"},
		"crypto_box_curve25519xchacha20poly1305_seed_keypair":          {3, "factory"},
		"crypto_box_curve25519xsalsa20poly1305":                        {6, "operation"},
		"crypto_box_curve25519xsalsa20poly1305_afternm":                {5, "operation"},
		"crypto_box_curve25519xsalsa20poly1305_beforenm":               {3, "factory"},
		"crypto_box_curve25519xsalsa20poly1305_keypair":                {2, "factory"},
		"crypto_box_curve25519xsalsa20poly1305_open":                   {6, "operation"},
		"crypto_box_curve25519xsalsa20poly1305_open_afternm":           {5, "operation"},
		"crypto_box_curve25519xsalsa20poly1305_seed_keypair":           {3, "factory"},
		"crypto_generichash_blake2b":                                   {6, "operation"},
		"crypto_generichash_blake2b_final":                             {3, "operation"},
		"crypto_generichash_blake2b_init":                              {4, "config"},
		"crypto_generichash_blake2b_init_salt_personal":                {6, "config"},
		"crypto_generichash_blake2b_keygen":                            {1, "factory"},
		"crypto_generichash_blake2b_salt_personal":                     {8, "operation"},
		"crypto_generichash_blake2b_update":                            {3, "operation"},
		"crypto_hash_sha256":                                           {3, "operation"},
		"crypto_hash_sha256_final":                                     {2, "operation"},
		"crypto_hash_sha256_init":                                      {1, "config"},
		"crypto_hash_sha256_update":                                    {3, "operation"},
		"crypto_hash_sha3256":                                          {3, "operation"},
		"crypto_hash_sha3256_final":                                    {2, "operation"},
		"crypto_hash_sha3256_init":                                     {1, "config"},
		"crypto_hash_sha3256_update":                                   {3, "operation"},
		"crypto_hash_sha3512":                                          {3, "operation"},
		"crypto_hash_sha3512_final":                                    {2, "operation"},
		"crypto_hash_sha3512_init":                                     {1, "config"},
		"crypto_hash_sha3512_update":                                   {3, "operation"},
		"crypto_hash_sha512":                                           {3, "operation"},
		"crypto_hash_sha512_final":                                     {2, "operation"},
		"crypto_hash_sha512_init":                                      {1, "config"},
		"crypto_hash_sha512_update":                                    {3, "operation"},
		"crypto_ipcrypt_decrypt":                                       {3, "operation"},
		"crypto_ipcrypt_encrypt":                                       {3, "operation"},
		"crypto_ipcrypt_keygen":                                        {1, "factory"},
		"crypto_ipcrypt_nd_decrypt":                                    {3, "operation"},
		"crypto_ipcrypt_nd_encrypt":                                    {4, "operation"},
		"crypto_ipcrypt_nd_keygen":                                     {1, "factory"},
		"crypto_ipcrypt_ndx_decrypt":                                   {3, "operation"},
		"crypto_ipcrypt_ndx_encrypt":                                   {4, "operation"},
		"crypto_ipcrypt_ndx_keygen":                                    {1, "factory"},
		"crypto_ipcrypt_pfx_decrypt":                                   {3, "operation"},
		"crypto_ipcrypt_pfx_encrypt":                                   {3, "operation"},
		"crypto_ipcrypt_pfx_keygen":                                    {1, "factory"},
		"crypto_kdf_blake2b_derive_from_key":                           {5, "operation"},
		"crypto_kdf_hkdf_sha256_expand":                                {5, "operation"},
		"crypto_kdf_hkdf_sha256_extract":                               {5, "operation"},
		"crypto_kdf_hkdf_sha256_extract_final":                         {2, "operation"},
		"crypto_kdf_hkdf_sha256_extract_init":                          {3, "config"},
		"crypto_kdf_hkdf_sha256_extract_update":                        {3, "operation"},
		"crypto_kdf_hkdf_sha256_keygen":                                {1, "factory"},
		"crypto_kdf_hkdf_sha512_expand":                                {5, "operation"},
		"crypto_kdf_hkdf_sha512_extract":                               {5, "operation"},
		"crypto_kdf_hkdf_sha512_extract_final":                         {2, "operation"},
		"crypto_kdf_hkdf_sha512_extract_init":                          {3, "config"},
		"crypto_kdf_hkdf_sha512_extract_update":                        {3, "operation"},
		"crypto_kdf_hkdf_sha512_keygen":                                {1, "factory"},
		"crypto_kem_mlkem768_dec":                                      {3, "operation"},
		"crypto_kem_mlkem768_enc":                                      {3, "operation"},
		"crypto_kem_mlkem768_enc_deterministic":                        {4, "operation"},
		"crypto_kem_mlkem768_keypair":                                  {2, "factory"},
		"crypto_kem_mlkem768_seed_keypair":                             {3, "factory"},
		"crypto_kem_xwing_dec":                                         {3, "operation"},
		"crypto_kem_xwing_enc":                                         {3, "operation"},
		"crypto_kem_xwing_enc_deterministic":                           {4, "operation"},
		"crypto_kem_xwing_keypair":                                     {2, "factory"},
		"crypto_kem_xwing_seed_keypair":                                {3, "factory"},
		"crypto_onetimeauth_poly1305":                                  {4, "operation"},
		"crypto_onetimeauth_poly1305_final":                            {2, "operation"},
		"crypto_onetimeauth_poly1305_init":                             {2, "config"},
		"crypto_onetimeauth_poly1305_keygen":                           {1, "factory"},
		"crypto_onetimeauth_poly1305_update":                           {3, "operation"},
		"crypto_onetimeauth_poly1305_verify":                           {4, "operation"},
		"crypto_pwhash_argon2i":                                        {8, "operation"},
		"crypto_pwhash_argon2i_str":                                    {5, "operation"},
		"crypto_pwhash_argon2i_str_verify":                             {3, "operation"},
		"crypto_pwhash_argon2id":                                       {8, "operation"},
		"crypto_pwhash_argon2id_str":                                   {5, "operation"},
		"crypto_pwhash_argon2id_str_verify":                            {3, "operation"},
		"crypto_pwhash_scryptsalsa208sha256":                           {7, "operation"},
		"crypto_pwhash_scryptsalsa208sha256_ll":                        {9, "operation"},
		"crypto_pwhash_scryptsalsa208sha256_str":                       {5, "operation"},
		"crypto_pwhash_scryptsalsa208sha256_str_verify":                {3, "operation"},
		"crypto_scalarmult_curve25519":                                 {3, "operation"},
		"crypto_scalarmult_curve25519_base":                            {2, "operation"},
		"crypto_secretbox":                                             {5, "operation"},
		"crypto_secretbox_open":                                        {5, "operation"},
		"crypto_secretbox_xchacha20poly1305_detached":                  {6, "operation"},
		"crypto_secretbox_xchacha20poly1305_easy":                      {5, "operation"},
		"crypto_secretbox_xchacha20poly1305_open_detached":             {6, "operation"},
		"crypto_secretbox_xchacha20poly1305_open_easy":                 {5, "operation"},
		"crypto_secretbox_xsalsa20poly1305":                            {5, "operation"},
		"crypto_secretbox_xsalsa20poly1305_keygen":                     {1, "factory"},
		"crypto_secretbox_xsalsa20poly1305_open":                       {5, "operation"},
		"crypto_shorthash_siphash24":                                   {4, "operation"},
		"crypto_shorthash_siphashx24":                                  {4, "operation"},
		"crypto_sign_ed25519":                                          {5, "operation"},
		"crypto_sign_ed25519_detached":                                 {5, "operation"},
		"crypto_sign_ed25519_keypair":                                  {2, "factory"},
		"crypto_sign_ed25519_open":                                     {5, "operation"},
		"crypto_sign_ed25519_seed_keypair":                             {3, "factory"},
		"crypto_sign_ed25519_verify_detached":                          {4, "operation"},
		"crypto_sign_ed25519ph_final_create":                           {4, "operation"},
		"crypto_sign_ed25519ph_final_verify":                           {3, "operation"},
		"crypto_sign_ed25519ph_init":                                   {1, "config"},
		"crypto_sign_ed25519ph_update":                                 {3, "operation"},
		"crypto_stream_chacha20":                                       {4, "operation"},
		"crypto_stream_chacha20_ietf":                                  {4, "operation"},
		"crypto_stream_chacha20_ietf_keygen":                           {1, "factory"},
		"crypto_stream_chacha20_ietf_xor":                              {5, "operation"},
		"crypto_stream_chacha20_ietf_xor_ic":                           {6, "operation"},
		"crypto_stream_chacha20_keygen":                                {1, "factory"},
		"crypto_stream_chacha20_xor":                                   {5, "operation"},
		"crypto_stream_chacha20_xor_ic":                                {6, "operation"},
		"crypto_stream_salsa20":                                        {4, "operation"},
		"crypto_stream_salsa20_keygen":                                 {1, "factory"},
		"crypto_stream_salsa20_xor":                                    {5, "operation"},
		"crypto_stream_salsa20_xor_ic":                                 {6, "operation"},
		"crypto_stream_xchacha20":                                      {4, "operation"},
		"crypto_stream_xchacha20_keygen":                               {1, "factory"},
		"crypto_stream_xchacha20_xor":                                  {5, "operation"},
		"crypto_stream_xchacha20_xor_ic":                               {6, "operation"},
		"crypto_stream_xsalsa20":                                       {4, "operation"},
		"crypto_stream_xsalsa20_keygen":                                {1, "factory"},
		"crypto_stream_xsalsa20_xor":                                   {5, "operation"},
		"crypto_stream_xsalsa20_xor_ic":                                {6, "operation"},
		"crypto_xof_shake128":                                          {4, "operation"},
		"crypto_xof_shake128_init":                                     {1, "config"},
		"crypto_xof_shake128_squeeze":                                  {3, "operation"},
		"crypto_xof_shake128_update":                                   {3, "operation"},
		"crypto_xof_shake256":                                          {4, "operation"},
		"crypto_xof_shake256_init":                                     {1, "config"},
		"crypto_xof_shake256_squeeze":                                  {3, "operation"},
		"crypto_xof_shake256_update":                                   {3, "operation"},
		"crypto_xof_turboshake128":                                     {4, "operation"},
		"crypto_xof_turboshake128_init":                                {1, "config"},
		"crypto_xof_turboshake128_squeeze":                             {3, "operation"},
		"crypto_xof_turboshake128_update":                              {3, "operation"},
		"crypto_xof_turboshake256":                                     {4, "operation"},
		"crypto_xof_turboshake256_init":                                {1, "config"},
		"crypto_xof_turboshake256_squeeze":                             {3, "operation"},
		"crypto_xof_turboshake256_update":                              {3, "operation"},
	}
	negative := []string{"crypto_kem_keypair", "crypto_kem_enc", "crypto_hash_sha256_bytes", "crypto_kem_mlkem768_publickeybytes", "crypto_pwhash_argon2id_str_needs_rehash"}

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

				for _, n := range negative {
					if bare == n {
						if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
							t.Fatalf("%q resolved to %d contract(s), want none", bare, len(got))
						}
						seen[bare] = true
					}
				}

				expect, ok := want[bare]
				if !ok {
					continue
				}
				if len(call.Arguments) != expect.arity {
					t.Fatalf("%s: parsed arity %d, want %d", bare, len(call.Arguments), expect.arity)
				}
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract", method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", bare, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "libsodium" {
					t.Fatalf("%s: library = %q, want libsodium", bare, got[0].SourceLibrary)
				}
				seen[bare] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q", method)
		}
	}
	for _, n := range negative {
		if !seen[n] {
			t.Fatalf("parsed calls did not cover negative %q", n)
		}
	}
}

// The consumer names the algorithm, parameter set or mode at the call site. Each
// call that takes that selector must carry it as operation-determining at the
// right index, or the identity of the finding it supports is unattributed.
func TestLibsodiumExtensionContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"crypto_pwhash_argon2id": {8, 7, "algorithm"},
	}

	for method, want := range selector {
		got := kb.ContractsFor(method, want.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, want.arity, len(got))
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != want.index {
				continue
			}
			found = true
			if p.Role != "operation-determining" {
				t.Errorf("%s: parameters[%d].role = %q, want operation-determining", method, want.index, p.Role)
			}
			if p.Contributes == nil || p.Contributes.Property != want.property {
				t.Errorf("%s: parameters[%d] contributes %#v, want property %s", method, want.index, p.Contributes, want.property)
			}
		}
		if !found {
			t.Errorf("%s: no parameter entry at index %d", method, want.index)
		}
	}
}
