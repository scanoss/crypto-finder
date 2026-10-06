// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// keySizeUnit is the unit of the argument a keySize role reads, as documented by
// the library's own headers or API docs. The derivation must agree with it: a
// byte count read as bits reports AES-128 as a 16-bit key.
type keySizeUnit string

const (
	// unitBits is a count of bits (RSA modulus size, rsa.GenerateKey bits).
	unitBits keySizeUnit = "argument_value"
	// unitBytes is a count of bytes (a key buffer length, wc_AesSetKey len).
	unitBytes keySizeUnit = "argument_byte_length"
	// unitMaterial is the key material itself; its size is measured, not read.
	unitMaterial keySizeUnit = "argument_bit_length"
	// unitCurve is a curve name or constructor (elliptic.P256()); the size is the
	// curve's field size, looked up rather than read.
	unitCurve keySizeUnit = "argument_curve_bits"
	// unitParameterSet is a DSA (L, N) constant; the size is its modulus L.
	unitParameterSet keySizeUnit = "argument_parameter_set_bits"
)

// auditedKeySizeRoles classifies every Go, C and C++ contract parameter that
// contributes keySize, keyed "ecosystem|method|index". A role omitted here, or
// listed with a unit that disagrees with its derivation, fails the test, so a new
// contract cannot ship its keySize unclassified. Where a unit was unclear the
// keySize contribution was removed instead (wolfSSL and LibTomCrypt ECC sizes,
// wc_ed448_make_key).
var auditedKeySizeRoles = map[string]keySizeUnit{
	// go/crypto11.yaml
	"go|github.com/ThalesIgnite/crypto11.(*Context).GenerateRSAKeyPair|1":               unitBits,
	"go|github.com/ThalesIgnite/crypto11.(*Context).GenerateRSAKeyPairWithLabel|2":      unitBits,
	"go|github.com/ThalesIgnite/crypto11.(*Context).GenerateRSAKeyPairWithAttributes|2": unitBits,
	"go|github.com/ThalesIgnite/crypto11.(*Context).GenerateSecretKey|1":                unitBits,
	"go|github.com/ThalesIgnite/crypto11.(*Context).GenerateSecretKeyWithLabel|2":       unitBits,
	// go/go-libp2p.yaml
	"go|github.com/libp2p/go-libp2p/core/crypto.GenerateKeyPair|1":           unitBits,
	"go|github.com/libp2p/go-libp2p/core/crypto.GenerateKeyPairWithReader|1": unitBits,
	"go|github.com/libp2p/go-libp2p/core/crypto.GenerateRSAKeyPair|0":        unitBits,
	// go/golang-fips-openssl-v2.yaml
	"go|github.com/golang-fips/openssl/v2.NewAESCipher|0":        unitMaterial,
	"go|github.com/golang-fips/openssl/v2.NewChaCha20Poly1305|0": unitMaterial,
	"go|github.com/golang-fips/openssl/v2.NewDESCipher|0":        unitMaterial,
	"go|github.com/golang-fips/openssl/v2.NewTripleDESCipher|0":  unitMaterial,
	"go|github.com/golang-fips/openssl/v2.NewHMAC|1":             unitMaterial,
	"go|github.com/golang-fips/openssl/v2.ExpandHKDFOneShot|1":   unitMaterial,
	"go|github.com/golang-fips/openssl/v2.ExpandTLS13KDF|1":      unitMaterial,
	"go|github.com/golang-fips/openssl/v2.PBKDF2|3":              unitBytes,
	"go|github.com/golang-fips/openssl/v2.GenerateKeyRSA|0":      unitBits,
	"go|github.com/golang-fips/openssl/v2.NewRC4Cipher|0":        unitMaterial,
	// go/golang-x-crypto.yaml
	"go|golang.org/x/crypto/blake2b.New256|0":                    unitMaterial,
	"go|golang.org/x/crypto/blake2b.New384|0":                    unitMaterial,
	"go|golang.org/x/crypto/blake2b.New512|0":                    unitMaterial,
	"go|golang.org/x/crypto/blake2b.New|1":                       unitMaterial,
	"go|golang.org/x/crypto/blake2b.NewXOF|1":                    unitMaterial,
	"go|golang.org/x/crypto/blake2s.New128|0":                    unitMaterial,
	"go|golang.org/x/crypto/blake2s.New256|0":                    unitMaterial,
	"go|golang.org/x/crypto/blake2s.NewXOF|1":                    unitMaterial,
	"go|golang.org/x/crypto/poly1305.New|0":                      unitMaterial,
	"go|golang.org/x/crypto/poly1305.Sum|2":                      unitMaterial,
	"go|golang.org/x/crypto/poly1305.Verify|2":                   unitMaterial,
	"go|golang.org/x/crypto/blowfish.NewCipher|0":                unitMaterial,
	"go|golang.org/x/crypto/cast5.NewCipher|0":                   unitMaterial,
	"go|golang.org/x/crypto/twofish.NewCipher|0":                 unitMaterial,
	"go|golang.org/x/crypto/xtea.NewCipher|0":                    unitMaterial,
	"go|golang.org/x/crypto/blowfish.NewSaltedCipher|0":          unitMaterial,
	"go|golang.org/x/crypto/blowfish.ExpandKey|0":                unitMaterial,
	"go|golang.org/x/crypto/tea.NewCipher|0":                     unitMaterial,
	"go|golang.org/x/crypto/tea.NewCipherWithRounds|0":           unitMaterial,
	"go|golang.org/x/crypto/chacha20.NewUnauthenticatedCipher|0": unitMaterial,
	"go|golang.org/x/crypto/chacha20.HChaCha20|0":                unitMaterial,
	"go|golang.org/x/crypto/chacha20poly1305.New|0":              unitMaterial,
	"go|golang.org/x/crypto/chacha20poly1305.NewX|0":             unitMaterial,
	"go|golang.org/x/crypto/xts.NewCipher|1":                     unitMaterial,
	"go|golang.org/x/crypto/nacl/secretbox.Seal|3":               unitMaterial,
	"go|golang.org/x/crypto/nacl/secretbox.Open|3":               unitMaterial,
	"go|golang.org/x/crypto/salsa20/salsa.XORKeyStream|3":        unitMaterial,
	"go|golang.org/x/crypto/salsa20/salsa.HSalsa20|2":            unitMaterial,
	"go|golang.org/x/crypto/nacl/box.SealAfterPrecomputation|3":  unitMaterial,
	"go|golang.org/x/crypto/nacl/box.OpenAfterPrecomputation|3":  unitMaterial,
	"go|golang.org/x/crypto/nacl/auth.Sum|1":                     unitMaterial,
	"go|golang.org/x/crypto/nacl/auth.Verify|2":                  unitMaterial,
	"go|golang.org/x/crypto/salsa20.XORKeyStream|3":              unitMaterial,
	// go/gopenpgp.yaml
	"go|github.com/ProtonMail/gopenpgp/v2/helper.GenerateKey|4": unitBits,
	"go|github.com/ProtonMail/gopenpgp/v2/crypto.GenerateKey|3": unitBits,
	// go/microsoft-go-crypto-openssl.yaml
	"go|github.com/microsoft/go-crypto-openssl/openssl.NewAESCipher|0":        unitMaterial,
	"go|github.com/microsoft/go-crypto-openssl/openssl.NewChaCha20Poly1305|0": unitMaterial,
	"go|github.com/microsoft/go-crypto-openssl/openssl.NewDESCipher|0":        unitMaterial,
	"go|github.com/microsoft/go-crypto-openssl/openssl.NewTripleDESCipher|0":  unitMaterial,
	"go|github.com/microsoft/go-crypto-openssl/openssl.NewHMAC|1":             unitMaterial,
	"go|github.com/microsoft/go-crypto-openssl/openssl.ExpandHKDF|1":          unitMaterial,
	"go|github.com/microsoft/go-crypto-openssl/openssl.ExpandTLS13KDF|1":      unitMaterial,
	"go|github.com/microsoft/go-crypto-openssl/openssl.PBKDF2|3":              unitBytes,
	"go|github.com/microsoft/go-crypto-openssl/openssl.NewRC4Cipher|0":        unitMaterial,
	// go/sigstore.yaml
	"go|github.com/sigstore/sigstore/pkg/signature.NewRSAPKCS1v15SignerVerifier|1": unitBits,
	"go|github.com/sigstore/sigstore/pkg/signature.NewRSAPSSSignerVerifier|1":      unitBits,
	// go/stdlib-crypto.yaml
	"go|crypto/aes.NewCipher|0":              unitMaterial,
	"go|crypto/des.NewCipher|0":              unitMaterial,
	"go|crypto/des.NewTripleDESCipher|0":     unitMaterial,
	"go|crypto/rc4.NewCipher|0":              unitMaterial,
	"go|crypto/ecdh.(Curve).NewPrivateKey|0": unitMaterial,
	// A receiver role reads the curve the method is called on, never an argument.
	"go|crypto/ecdh.(Curve).NewPrivateKey|receiver": unitCurve,
	"go|crypto/ecdh.(Curve).GenerateKey|receiver":   unitCurve,
	"go|crypto/hmac.New|1":                          unitMaterial,
	"go|crypto/rand.Prime|1":                        unitBits,
	"go|crypto/rsa.GenerateKey|1":                   unitBits,
	"go|crypto/ecdsa.GenerateKey|0":                 unitCurve,
	"go|crypto/dsa.GenerateParameters|2":            unitParameterSet,
	"go|crypto/rsa.GenerateMultiPrimeKey|2":         unitBits,
	// go/vault-sdk.yaml
	"go|github.com/hashicorp/vault/sdk/helper/kdf.CounterMode|4": unitBits,
	// c/gnutls.yaml
	"c|gnutls_hmac_init|3":             unitBytes,
	"c|gnutls_hmac_fast|2":             unitBytes,
	"c|gnutls_privkey_generate|2":      unitBits,
	"c|gnutls_privkey_generate2|2":     unitBits,
	"c|gnutls_x509_privkey_generate|2": unitBits,
	// c/hacl-star.yaml
	"c|EverCrypt_HMAC_compute_blake2b|2":            unitBytes,
	"c|EverCrypt_HMAC_compute_blake2s|2":            unitBytes,
	"c|EverCrypt_HMAC_compute_sha1|2":               unitBytes,
	"c|EverCrypt_HMAC_compute_sha2_256|2":           unitBytes,
	"c|EverCrypt_HMAC_compute_sha2_384|2":           unitBytes,
	"c|EverCrypt_HMAC_compute_sha2_512|2":           unitBytes,
	"c|Hacl_HMAC_Blake2b_256_compute_blake2b_256|2": unitBytes,
	"c|Hacl_HMAC_Blake2s_128_compute_blake2s_128|2": unitBytes,
	"c|Hacl_HMAC_compute_blake2b_32|2":              unitBytes,
	"c|Hacl_HMAC_compute_blake2s_32|2":              unitBytes,
	"c|Hacl_HMAC_compute_sha2_256|2":                unitBytes,
	"c|Hacl_HMAC_compute_sha2_384|2":                unitBytes,
	"c|Hacl_HMAC_compute_sha2_512|2":                unitBytes,
	"c|Hacl_HMAC_legacy_compute_sha1|2":             unitBytes,
	// c/libgcrypt.yaml
	"c|gcry_cipher_setkey|2": unitBytes,
	"c|gcry_md_setkey|2":     unitBytes,
	"c|gcry_mac_setkey|2":    unitBytes,
	"c|gcry_kdf_derive|7":    unitBytes,
	// c/libp11.yaml
	"c|PKCS11_generate_key|2": unitBits,
	// c/libsodium.yaml
	"c|crypto_generichash|5":              unitBytes,
	"c|crypto_generichash_init|2":         unitBytes,
	"c|crypto_generichash_blake2b|5":      unitBytes,
	"c|crypto_generichash_blake2b_init|2": unitBytes,
	// c/libssh.yaml
	"c|ssh_pki_generate|1": unitBits,
	// c/libtomcrypt.yaml
	"c|aes_enc_setup|1":                    unitBytes,
	"c|aes_setup|1":                        unitBytes,
	"c|blake2b_init|3":                     unitBytes,
	"c|blake2bmac_file|2":                  unitBytes,
	"c|blake2bmac_init|3":                  unitBytes,
	"c|blake2bmac_memory|1":                unitBytes,
	"c|blake2bmac_memory_multi|1":          unitBytes,
	"c|blake2s_init|3":                     unitBytes,
	"c|blake2smac_file|2":                  unitBytes,
	"c|blake2smac_init|3":                  unitBytes,
	"c|blake2smac_memory|1":                unitBytes,
	"c|blake2smac_memory_multi|1":          unitBytes,
	"c|blowfish_setup|1":                   unitBytes,
	"c|camellia_setup|1":                   unitBytes,
	"c|cast5_setup|1":                      unitBytes,
	"c|cbc_start|3":                        unitBytes,
	"c|ccm_init|3":                         unitBytes,
	"c|ccm_memory|2":                       unitBytes,
	"c|cfb_start|3":                        unitBytes,
	"c|chacha20poly1305_init|2":            unitBytes,
	"c|chacha20poly1305_memory|1":          unitBytes,
	"c|chacha_setup|2":                     unitBytes,
	"c|ctr_start|3":                        unitBytes,
	"c|des3_setup|1":                       unitBytes,
	"c|des_setup|1":                        unitBytes,
	"c|eax_decrypt_verify_memory|2":        unitBytes,
	"c|eax_encrypt_authenticate_memory|2":  unitBytes,
	"c|ecb_start|2":                        unitBytes,
	"c|gcm_init|3":                         unitBytes,
	"c|gcm_memory|2":                       unitBytes,
	"c|hmac_file|3":                        unitBytes,
	"c|hmac_init|3":                        unitBytes,
	"c|hmac_memory|2":                      unitBytes,
	"c|hmac_memory_multi|2":                unitBytes,
	"c|kseed_setup|1":                      unitBytes,
	"c|ocb3_decrypt_verify_memory|2":       unitBytes,
	"c|ocb3_encrypt_authenticate_memory|2": unitBytes,
	"c|ocb_decrypt_verify_memory|2":        unitBytes,
	"c|ocb_encrypt_authenticate_memory|2":  unitBytes,
	"c|ofb_start|3":                        unitBytes,
	"c|omac_file|2":                        unitBytes,
	"c|omac_init|3":                        unitBytes,
	"c|omac_memory|2":                      unitBytes,
	"c|omac_memory_multi|2":                unitBytes,
	"c|pmac_file|2":                        unitBytes,
	"c|pmac_init|3":                        unitBytes,
	"c|pmac_memory|2":                      unitBytes,
	"c|pmac_memory_multi|2":                unitBytes,
	"c|poly1305_file|2":                    unitBytes,
	"c|poly1305_init|2":                    unitBytes,
	"c|poly1305_memory|1":                  unitBytes,
	"c|poly1305_memory_multi|1":            unitBytes,
	"c|rc2_setup|1":                        unitBytes,
	"c|rc2_setup_ex|1":                     unitBytes,
	"c|rc4_stream_setup|2":                 unitBytes,
	"c|rc5_setup|1":                        unitBytes,
	"c|rc6_setup|1":                        unitBytes,
	"c|rijndael_enc_setup|1":               unitBytes,
	"c|rijndael_setup|1":                   unitBytes,
	"c|rsa_make_key|2":                     unitBytes,
	"c|skipjack_setup|1":                   unitBytes,
	"c|twofish_setup|1":                    unitBytes,
	"c|xcbc_file|2":                        unitBytes,
	"c|xcbc_init|3":                        unitBytes,
	"c|xcbc_memory|2":                      unitBytes,
	"c|xcbc_memory_multi|2":                unitBytes,
	"c|xts_start|3":                        unitBytes,
	// c/mbedtls.yaml
	"c|mbedtls_rsa_gen_key|3": unitBits,
	// c/monocypher.yaml
	"c|crypto_blake2b_general|3":      unitBytes,
	"c|crypto_blake2b_general_init|3": unitBytes,
	"c|crypto_blake2b_keyed|3":        unitBytes,
	"c|crypto_blake2b_keyed_init|3":   unitBytes,
	// c/nettle.yaml
	"c|rsa_generate_keypair|6": unitBits,
	// c/nss.yaml
	"c|PK11_UnwrapSymKey|6":           unitBytes,
	"c|PK11_KeyGen|3":                 unitBytes,
	"c|PK11_TokenKeyGen|3":            unitBytes,
	"c|PK11_Derive|5":                 unitBytes,
	"c|PK11_CreatePBEV2AlgorithmID|3": unitBytes,
	"c|SECKEY_CreateRSAPrivateKey|0":  unitBits,
	// c/opensc.yaml
	"c|sc_pkcs15init_generate_key|3": unitBits,
	// c/openssl-evp.yaml
	"c|EVP_RSA_gen|0":                            unitBits,
	"c|EVP_PKEY_CTX_set_rsa_keygen_bits|1":       unitBits,
	"c|EVP_PKEY_CTX_set_dsa_paramgen_bits|1":     unitBits,
	"c|RSA_generate_key_ex|1":                    unitBits,
	"c|RSA_generate_key|0":                       unitBits,
	"c|DSA_generate_parameters_ex|1":             unitBits,
	"c|EVP_PKEY_CTX_set_dh_paramgen_prime_len|1": unitBits,
	"c|DH_generate_parameters_ex|1":              unitBits,
	"c|DH_generate_parameters|0":                 unitBits,
	// c/rnp.yaml
	"c|rnp_op_generate_set_bits|1": unitBits,
	"c|rnp_generate_key_rsa|1":     unitBits,
	"c|rnp_generate_key_dsa_eg|1":  unitBits,
	"c|rnp_generate_key_ex|3":      unitBits,
	// c/tinycrypt.yaml
	"c|tc_hmac_set_key|2": unitBytes,
	// c/wolfssl-wolfcrypt.yaml
	"c|wc_AesCcmSetKey|2":              unitBytes,
	"c|wc_AesCtrSetKey|2":              unitBytes,
	"c|wc_AesEaxDecryptAuth|1":         unitBytes,
	"c|wc_AesEaxEncryptAuth|1":         unitBytes,
	"c|wc_AesEaxInit|2":                unitBytes,
	"c|wc_AesGcmSetKey|2":              unitBytes,
	"c|wc_AesGcmSetKey_ex|2":           unitBytes,
	"c|wc_AesKeyUnWrap|1":              unitBytes,
	"c|wc_AesKeyWrap|1":                unitBytes,
	"c|wc_AesSetKey|2":                 unitBytes,
	"c|wc_AesSetKeyDirect|2":           unitBytes,
	"c|wc_AesSivDecrypt|1":             unitBytes,
	"c|wc_AesSivDecrypt_ex|1":          unitBytes,
	"c|wc_AesSivEncrypt|1":             unitBytes,
	"c|wc_AesSivEncrypt_ex|1":          unitBytes,
	"c|wc_AesXtsSetKey|2":              unitBytes,
	"c|wc_AesXtsSetKeyNoInit|2":        unitBytes,
	"c|wc_Gmac|1":                      unitBytes,
	"c|wc_GmacSetKey|2":                unitBytes,
	"c|wc_GmacVerify|1":                unitBytes,
	"c|wc_Arc4SetKey|2":                unitBytes,
	"c|wc_Blake2bHmacInit|2":           unitBytes,
	"c|wc_Blake2sHmacInit|2":           unitBytes,
	"c|wc_InitBlake2b_WithKey|3":       unitBytes,
	"c|wc_InitBlake2s_WithKey|3":       unitBytes,
	"c|wc_CamelliaSetKey|2":            unitBytes,
	"c|wc_Chacha_SetKey|2":             unitBytes,
	"c|wc_XChacha_SetKey|2":            unitBytes,
	"c|wc_XChaCha20Poly1305_Decrypt|9": unitBytes,
	"c|wc_XChaCha20Poly1305_Encrypt|9": unitBytes,
	"c|wc_XChaCha20Poly1305_Init|6":    unitBytes,
	"c|wc_AesCmacGenerate|5":           unitBytes,
	"c|wc_AesCmacGenerate_ex|6":        unitBytes,
	"c|wc_AesCmacVerify|5":             unitBytes,
	"c|wc_AesCmacVerify_ex|6":          unitBytes,
	"c|wc_InitCmac|2":                  unitBytes,
	"c|wc_InitCmac_Id|2":               unitBytes,
	"c|wc_InitCmac_Label|2":            unitBytes,
	"c|wc_InitCmac_ex|2":               unitBytes,
	"c|wc_curve25519_make_key|1":       unitBytes,
	"c|wc_curve25519_make_priv|1":      unitBytes,
	"c|wc_curve448_make_key|1":         unitBytes,
	"c|wc_ed25519_make_key|1":          unitBytes,
	"c|wc_HKDF|2":                      unitBytes,
	"c|wc_HKDF_Expand|2":               unitBytes,
	"c|wc_HKDF_Expand_ex|2":            unitBytes,
	"c|wc_HKDF_Extract|4":              unitBytes,
	"c|wc_HKDF_Extract_ex|4":           unitBytes,
	"c|wc_HKDF_ex|2":                   unitBytes,
	"c|wc_HmacSetKey|3":                unitBytes,
	"c|wc_HmacSetKey_Software|3":       unitBytes,
	"c|wc_HmacSetKey_ex|3":             unitBytes,
	"c|wc_Rc2SetKey|2":                 unitBytes,
	"c|wc_MakeRsaKey|1":                unitBits,
}

func TestKeySizeRolesAreUnitAudited(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool, len(auditedKeySizeRoles))
	for _, ecosystem := range []string{"go", "c", "cpp"} {
		kb, err := contracts.LoadEmbedded(ecosystem)
		if err != nil {
			t.Fatalf("LoadEmbedded(%s): %v", ecosystem, err)
		}
		for _, group := range kb.Contracts {
			for _, contract := range group {
				for _, parameter := range contract.Parameters {
					if (parameter.Index == nil && !parameter.Receiver) || parameter.Contributes == nil || parameter.Contributes.Property != "keySize" {
						continue
					}
					position := "receiver"
					if !parameter.Receiver {
						position = fmt.Sprint(*parameter.Index)
					}
					key := fmt.Sprintf("%s|%s|%s", ecosystem, contract.Method, position)
					unit, ok := auditedKeySizeRoles[key]
					if !ok {
						t.Errorf("%s contributes keySize but is not in auditedKeySizeRoles: add it with the unit its library documents", key)
						continue
					}
					seen[key] = true
					if string(unit) != parameter.Contributes.Derivation {
						t.Errorf("%s derivation = %s, audited unit requires %s", key, parameter.Contributes.Derivation, unit)
					}
				}
			}
		}
	}
	for key := range auditedKeySizeRoles {
		if !seen[key] {
			t.Errorf("%s is audited but no contract contributes keySize there any more", key)
		}
	}
}
