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

// THE WHOLE dryoc CONTRACT, RENDERED AND COMPARED AS A SET.
//
// A per-key `ContractsFor` assertion cannot see three things that have all
// shipped on this campaign: an entry that should not be there, an entry that
// was dropped, and a field that was corrupted. This compares every loaded
// dryoc contract against the literal below, INCLUDING the `parameters:` block
// -- renaming a contributed property (keySize -> nonceSize) loads cleanly
// through the schema's presence checks and would pass an otherwise-exact test
// while feeding `resolvedKeyLengthFromContract` the wrong field.
//
// The `library:` block is asserted separately, in
// TestDryocLibraryBlock, because `version_range`, `coordinates`, `name` and
// `description` are parsed and then never consulted by any other assertion.
func TestDryocContractExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type row struct {
		method string
		arity  int
		role   string
		ret    string
		params []string
		conf   string
		pblock []string
	}

	want := []row{
		{"dryoc::auth::Auth.compute", 2, "operation", "dryoc::auth::Mac", []string{}, "low", []string{}},
		{"dryoc::auth::Auth.compute_and_verify", 3, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::auth::Auth.compute_to_vec", 2, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::auth::Auth.finalize", 0, "operation", "dryoc::auth::Mac", []string{}, "low", []string{}},
		{"dryoc::auth::Auth.finalize_to_vec", 0, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::auth::Auth.new", 1, "factory", "dryoc::auth::Auth", []string{}, "high", []string{}},
		{"dryoc::auth::Auth.update", 1, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::auth::Auth.verify", 1, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::auth::Key.gen", 0, "factory", "dryoc::auth::Key", []string{}, "high", []string{}},
		{"dryoc::auth::Key.generate", 0, "factory", "dryoc::auth::Key", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_auth.crypto_auth", 3, "operation", "()", []string{"&mut Mac", "&[u8]", "&Key"}, "high", []string{"2:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_auth.crypto_auth_final", 2, "operation", "()", []string{"AuthState", "&mut [u8; CRYPTO_AUTH_BYTES]"}, "high", []string{}},
		{"dryoc::classic::crypto_auth.crypto_auth_init", 1, "factory", "dryoc::classic::crypto_auth::AuthState", []string{"&Key"}, "high", []string{"0:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_auth.crypto_auth_keygen", 0, "factory", "dryoc::classic::crypto_auth::Key", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_auth.crypto_auth_update", 2, "operation", "()", []string{"&mut AuthState", "&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_auth.crypto_auth_verify", 3, "operation", "Result<(), dryoc::Error>", []string{"&Mac", "&[u8]", "&Key"}, "high", []string{"2:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_beforenm", 2, "operation", "dryoc::classic::crypto_box::Key", []string{"&PublicKey", "&SecretKey"}, "high", []string{"0:public_key:metadata-contributing:keySize:argument_bit_length", "1:secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_detached", 6, "operation", "()", []string{"&mut [u8]", "&mut Mac", "&[u8]", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"3:nonce:metadata-contributing:nonceSize:argument_bit_length", "4:recipient_public_key:metadata-contributing:keySize:argument_bit_length", "5:sender_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_detached_afternm", 5, "operation", "()", []string{"&mut [u8]", "&mut Mac", "&[u8]", "&Nonce", "&Key"}, "high", []string{"3:nonce:metadata-contributing:nonceSize:argument_bit_length", "4:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_detached_afternm_inplace", 4, "operation", "()", []string{"&mut [u8]", "&mut Mac", "&Nonce", "&Key"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_detached_inplace", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&mut Mac", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:recipient_public_key:metadata-contributing:keySize:argument_bit_length", "4:sender_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_easy", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:recipient_public_key:metadata-contributing:keySize:argument_bit_length", "4:sender_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_easy_inplace", 4, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"1:nonce:metadata-contributing:nonceSize:argument_bit_length", "2:recipient_public_key:metadata-contributing:keySize:argument_bit_length", "3:sender_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_keypair", 0, "factory", "(dryoc::classic::crypto_box::PublicKey, dryoc::classic::crypto_box::SecretKey)", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_box.crypto_box_keypair_inplace", 2, "factory", "()", []string{"&mut PublicKey", "&mut SecretKey"}, "high", []string{"0:public_key:metadata-contributing:keySize:argument_bit_length", "1:secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_open_detached", 6, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Mac", "&[u8]", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"3:nonce:metadata-contributing:nonceSize:argument_bit_length", "4:recipient_public_key:metadata-contributing:keySize:argument_bit_length", "5:sender_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_open_detached_afternm", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Mac", "&[u8]", "&Nonce", "&Key"}, "high", []string{"3:nonce:metadata-contributing:nonceSize:argument_bit_length", "4:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_open_detached_afternm_inplace", 4, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Mac", "&Nonce", "&Key"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_open_detached_inplace", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Mac", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:recipient_public_key:metadata-contributing:keySize:argument_bit_length", "4:sender_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_open_easy", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:sender_public_key:metadata-contributing:keySize:argument_bit_length", "4:recipient_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_open_easy_inplace", 4, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Nonce", "&PublicKey", "&SecretKey"}, "high", []string{"1:nonce:metadata-contributing:nonceSize:argument_bit_length", "2:sender_public_key:metadata-contributing:keySize:argument_bit_length", "3:recipient_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_seal", 3, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&PublicKey"}, "high", []string{"2:recipient_public_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_seal_open", 4, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&PublicKey", "&SecretKey"}, "high", []string{"2:recipient_public_key:metadata-contributing:keySize:argument_bit_length", "3:recipient_secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_box.crypto_box_seed_keypair", 1, "factory", "(dryoc::classic::crypto_box::PublicKey, dryoc::classic::crypto_box::SecretKey)", []string{"&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_box.crypto_box_seed_keypair_inplace", 3, "factory", "()", []string{"&mut PublicKey", "&mut SecretKey", "&[u8]"}, "high", []string{"0:public_key:metadata-contributing:keySize:argument_bit_length", "1:secret_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_core.crypto_core_ed25519_is_valid_point", 1, "operation", "bool", []string{"&Ed25519Point"}, "high", []string{}},
		{"dryoc::classic::crypto_core.crypto_core_ed25519_is_valid_point_relaxed", 1, "operation", "bool", []string{"&Ed25519Point"}, "high", []string{}},
		{"dryoc::classic::crypto_core.crypto_core_hchacha20", 4, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_core.crypto_core_hsalsa20", 4, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_core.crypto_scalarmult", 3, "operation", "()", []string{"&mut [u8; CRYPTO_SCALARMULT_BYTES]", "&[u8; CRYPTO_SCALARMULT_SCALARBYTES]", "&[u8; CRYPTO_SCALARMULT_BYTES]"}, "high", []string{}},
		{"dryoc::classic::crypto_core.crypto_scalarmult_base", 2, "operation", "()", []string{"&mut [u8; CRYPTO_SCALARMULT_BYTES]", "&[u8; CRYPTO_SCALARMULT_SCALARBYTES]"}, "high", []string{}},
		{"dryoc::classic::crypto_generichash.crypto_generichash", 3, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_generichash.crypto_generichash_final", 2, "operation", "Result<(), dryoc::Error>", []string{"GenericHashState", "&mut [u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_generichash.crypto_generichash_init", 2, "factory", "Result<dryoc::classic::crypto_generichash::GenericHashState, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_generichash.crypto_generichash_keygen", 0, "factory", "[u8; CRYPTO_GENERICHASH_KEYBYTES]", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_generichash.crypto_generichash_update", 2, "operation", "()", []string{"&mut GenericHashState", "&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_hash.crypto_hash_sha512", 2, "operation", "()", []string{"&mut Digest", "&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_hash.crypto_hash_sha512_final", 2, "operation", "()", []string{"Sha512State", "&mut Digest"}, "high", []string{}},
		{"dryoc::classic::crypto_hash.crypto_hash_sha512_init", 0, "factory", "dryoc::classic::crypto_hash::Sha512State", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_hash.crypto_hash_sha512_update", 2, "operation", "()", []string{"&mut Sha512State", "&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_kdf.crypto_kdf_derive_from_key", 4, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "u64", "&Context", "&Key"}, "high", []string{"3:main_key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_kdf.crypto_kdf_keygen", 0, "factory", "dryoc::classic::crypto_kdf::Key", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_kx.crypto_kx_client_session_keys", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut SessionKey", "&mut SessionKey", "&PublicKey", "&SecretKey", "&PublicKey"}, "high", []string{"0:rx:metadata-contributing:keySize:argument_bit_length", "1:tx:metadata-contributing:keySize:argument_bit_length", "2:client_pk:metadata-contributing:keySize:argument_bit_length", "3:client_sk:metadata-contributing:keySize:argument_bit_length", "4:server_pk:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_kx.crypto_kx_keypair", 0, "factory", "(dryoc::classic::crypto_kx::PublicKey, dryoc::classic::crypto_kx::SecretKey)", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_kx.crypto_kx_seed_keypair", 1, "factory", "Result<(dryoc::classic::crypto_kx::PublicKey, dryoc::classic::crypto_kx::SecretKey), dryoc::Error>", []string{"&[u8; CRYPTO_KX_SEEDBYTES]"}, "high", []string{}},
		{"dryoc::classic::crypto_kx.crypto_kx_server_session_keys", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut SessionKey", "&mut SessionKey", "&PublicKey", "&SecretKey", "&PublicKey"}, "high", []string{"0:rx:metadata-contributing:keySize:argument_bit_length", "1:tx:metadata-contributing:keySize:argument_bit_length", "2:server_pk:metadata-contributing:keySize:argument_bit_length", "3:server_sk:metadata-contributing:keySize:argument_bit_length", "4:client_pk:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_onetimeauth.crypto_onetimeauth", 3, "operation", "()", []string{"&mut Mac", "&[u8]", "&Key"}, "high", []string{"2:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_onetimeauth.crypto_onetimeauth_final", 2, "operation", "()", []string{"OnetimeauthState", "&mut [u8; CRYPTO_ONETIMEAUTH_BYTES]"}, "high", []string{}},
		{"dryoc::classic::crypto_onetimeauth.crypto_onetimeauth_init", 1, "factory", "dryoc::classic::crypto_onetimeauth::OnetimeauthState", []string{"&[u8; CRYPTO_ONETIMEAUTH_KEYBYTES]"}, "high", []string{}},
		{"dryoc::classic::crypto_onetimeauth.crypto_onetimeauth_keygen", 0, "factory", "dryoc::classic::crypto_onetimeauth::Key", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_onetimeauth.crypto_onetimeauth_update", 2, "operation", "()", []string{"&mut OnetimeauthState", "&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_onetimeauth.crypto_onetimeauth_verify", 3, "operation", "Result<(), dryoc::Error>", []string{"&Mac", "&[u8]", "&Key"}, "high", []string{"2:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_pwhash.crypto_pwhash", 6, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&[u8]", "u64", "usize", "PasswordHashAlgorithm"}, "high", []string{}},
		{"dryoc::classic::crypto_pwhash.crypto_pwhash_str", 3, "operation", "Result<String, dryoc::Error>", []string{"&[u8]", "u64", "usize"}, "high", []string{}},
		{"dryoc::classic::crypto_pwhash.crypto_pwhash_str_needs_rehash", 3, "operation", "Result<bool, dryoc::Error>", []string{"&str", "u64", "usize"}, "high", []string{}},
		{"dryoc::classic::crypto_pwhash.crypto_pwhash_str_verify", 2, "operation", "Result<(), dryoc::Error>", []string{"&str", "&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_detached", 5, "operation", "()", []string{"&mut [u8]", "&mut Mac", "&[u8]", "&Nonce", "&Key"}, "high", []string{"3:nonce:metadata-contributing:nonceSize:argument_bit_length", "4:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_easy", 4, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&Nonce", "&Key"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_easy_inplace", 3, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Nonce", "&Key"}, "high", []string{"1:nonce:metadata-contributing:nonceSize:argument_bit_length", "2:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_keygen", 0, "factory", "dryoc::classic::crypto_secretbox::Key", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_keygen_inplace", 1, "factory", "()", []string{"&mut Key"}, "high", []string{"0:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_open_detached", 5, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Mac", "&[u8]", "&Nonce", "&Key"}, "high", []string{"3:nonce:metadata-contributing:nonceSize:argument_bit_length", "4:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_open_easy", 4, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&Nonce", "&Key"}, "high", []string{"2:nonce:metadata-contributing:nonceSize:argument_bit_length", "3:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretbox.crypto_secretbox_open_easy_inplace", 3, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&Nonce", "&Key"}, "high", []string{"1:nonce:metadata-contributing:nonceSize:argument_bit_length", "2:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretstream_xchacha20poly1305.crypto_secretstream_xchacha20poly1305_init_pull", 3, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_secretstream_xchacha20poly1305.crypto_secretstream_xchacha20poly1305_init_push", 3, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_secretstream_xchacha20poly1305.crypto_secretstream_xchacha20poly1305_keygen", 1, "factory", "()", []string{"&mut Key"}, "high", []string{"0:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_secretstream_xchacha20poly1305.crypto_secretstream_xchacha20poly1305_pull", 5, "operation", "Result<usize, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_secretstream_xchacha20poly1305.crypto_secretstream_xchacha20poly1305_push", 5, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_secretstream_xchacha20poly1305.crypto_secretstream_xchacha20poly1305_rekey", 1, "operation", "()", []string{"&mut State"}, "high", []string{}},
		{"dryoc::classic::crypto_shorthash.crypto_shorthash", 3, "operation", "()", []string{"&mut Hash", "&[u8]", "&Key"}, "high", []string{"2:key:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_shorthash.crypto_shorthash_keygen", 0, "factory", "dryoc::classic::crypto_shorthash::Key", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign", 3, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&SecretKey"}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_detached", 3, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_final_create", 3, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_final_verify", 3, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_init", 0, "factory", "dryoc::classic::crypto_sign::SignerState", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_keypair", 0, "factory", "(dryoc::classic::crypto_sign::PublicKey, dryoc::classic::crypto_sign::SecretKey)", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_keypair_inplace", 2, "factory", "()", []string{"&mut PublicKey", "&mut SecretKey"}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_open", 3, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8]", "&[u8]", "&PublicKey"}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_seed_keypair", 1, "factory", "(dryoc::classic::crypto_sign::PublicKey, dryoc::classic::crypto_sign::SecretKey)", []string{"&[u8; 32]"}, "high", []string{"0:seed:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_sign.crypto_sign_seed_keypair_inplace", 3, "factory", "()", []string{"&mut PublicKey", "&mut SecretKey", "&[u8; 32]"}, "high", []string{"2:seed:metadata-contributing:keySize:argument_bit_length"}},
		{"dryoc::classic::crypto_sign.crypto_sign_update", 2, "operation", "()", []string{"&mut SignerState", "&[u8]"}, "high", []string{}},
		{"dryoc::classic::crypto_sign.crypto_sign_verify_detached", 3, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::classic::crypto_sign_ed25519.crypto_sign_ed25519_pk_to_curve25519", 2, "operation", "Result<(), dryoc::Error>", []string{"&mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES]", "&PublicKey"}, "high", []string{}},
		{"dryoc::classic::crypto_sign_ed25519.crypto_sign_ed25519_sk_to_curve25519", 2, "operation", "()", []string{"&mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES]", "&SecretKey"}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_beforenm", 2, "operation", "SecretBoxKeyBase", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_detached", 4, "operation", "Result<DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_detached_afternm", 3, "operation", "Result<DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_detached_afternm_inplace", 3, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_detached_inplace", 4, "operation", "Result<DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_easy", 4, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_easy_inplace", 4, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_keypair", 0, "factory", "KeyPair", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_open_detached", 5, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_open_detached_afternm", 4, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_open_detached_afternm_inplace", 4, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_open_detached_inplace", 5, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_open_easy", 4, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_open_easy_inplace", 4, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_box.crypto_box_seed_keypair", 1, "factory", "KeyPair", []string{}, "high", []string{}},
		{"dryoc::crypto_core.crypto_scalarmult_base", 1, "operation", "[u8; CRYPTO_SCALARMULT_BYTES]", []string{}, "high", []string{}},
		{"dryoc::crypto_hash.crypto_hash_sha512", 1, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::crypto_hash.crypto_hash_sha512_final", 1, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::crypto_hash.crypto_hash_sha512_init", 0, "factory", "Sha512", []string{}, "high", []string{}},
		{"dryoc::crypto_hash.crypto_hash_sha512_update", 2, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::crypto_secretbox.crypto_secretbox_detached", 3, "operation", "DryocSecretBox", []string{}, "high", []string{}},
		{"dryoc::crypto_secretbox.crypto_secretbox_easy", 3, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_secretbox.crypto_secretbox_easy_inplace", 3, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_secretbox.crypto_secretbox_keygen", 0, "factory", "SecretBoxKeyBase", []string{}, "high", []string{}},
		{"dryoc::crypto_secretbox.crypto_secretbox_open_detached", 4, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_secretbox.crypto_secretbox_open_easy", 3, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::crypto_secretbox.crypto_secretbox_open_easy_inplace", 3, "operation", "Result<OutputBase, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.decrypt", 3, "operation", "Result<std::vec::Vec<u8>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocbox::DryocBox.decrypt_to_vec", 3, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.encrypt", 4, "operation", "Result<dryoc::dryocbox::DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.encrypt_to_vecbox", 4, "operation", "Result<dryoc::dryocbox::DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.precalc_decrypt", 2, "operation", "Result<std::vec::Vec<u8>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocbox::DryocBox.precalc_decrypt_to_vec", 2, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.precalc_encrypt", 3, "operation", "Result<dryoc::dryocbox::DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.precalc_encrypt_to_vecbox", 3, "operation", "Result<dryoc::dryocbox::DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.seal", 2, "operation", "Result<dryoc::dryocbox::DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.seal_to_vecbox", 2, "operation", "Result<dryoc::dryocbox::DryocBox, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::DryocBox.unseal", 1, "operation", "Result<std::vec::Vec<u8>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocbox::DryocBox.unseal_to_vec", 1, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.from_secret_key", 1, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.from_seed", 1, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.from_slices", 2, "factory", "Result<dryoc::keypair::KeyPair, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.gen", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.gen_with_defaults", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.generate", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.generate_with_defaults", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.is_valid_ed25519_key", 1, "operation", "bool", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.is_valid_public_key", 1, "operation", "bool", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.kx_new_client_session", 1, "operation", "Result<kx::Session<dryoc::kx::SessionKey>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocbox::KeyPair.kx_new_server_session", 1, "operation", "Result<kx::Session<dryoc::kx::SessionKey>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocbox::KeyPair.new", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::dryocbox::KeyPair.precalculate", 1, "operation", "PrecalcSecretKey<StackByteArray<CRYPTO_BOX_BEFORENMBYTES>>", []string{}, "high", []string{}},
		{"dryoc::dryocbox::Nonce.gen", 0, "factory", "dryoc::dryocbox::Nonce", []string{}, "high", []string{}},
		{"dryoc::dryocbox::Nonce.generate", 0, "factory", "dryoc::dryocbox::Nonce", []string{}, "high", []string{}},
		{"dryoc::dryocsecretbox::DryocSecretBox.decrypt", 2, "operation", "Result<std::vec::Vec<u8>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocsecretbox::DryocSecretBox.decrypt_to_vec", 2, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocsecretbox::DryocSecretBox.encrypt", 3, "operation", "dryoc::dryocsecretbox::DryocSecretBox", []string{}, "high", []string{}},
		{"dryoc::dryocsecretbox::DryocSecretBox.encrypt_to_vecbox", 3, "operation", "dryoc::dryocsecretbox::DryocSecretBox", []string{}, "high", []string{}},
		{"dryoc::dryocsecretbox::Key.gen", 0, "factory", "dryoc::dryocsecretbox::Key", []string{}, "high", []string{}},
		{"dryoc::dryocsecretbox::Key.generate", 0, "factory", "dryoc::dryocsecretbox::Key", []string{}, "high", []string{}},
		{"dryoc::dryocsecretbox::Nonce.gen", 0, "factory", "dryoc::dryocsecretbox::Nonce", []string{}, "high", []string{}},
		{"dryoc::dryocsecretbox::Nonce.generate", 0, "factory", "dryoc::dryocsecretbox::Nonce", []string{}, "high", []string{}},
		{"dryoc::dryocstream::DryocStream.init_pull", 2, "factory", "dryoc::dryocstream::DryocStream", []string{}, "high", []string{}},
		{"dryoc::dryocstream::DryocStream.init_push", 1, "factory", "(dryoc::dryocstream::DryocStream, Header)", []string{}, "high", []string{}},
		{"dryoc::dryocstream::DryocStream.pull", 2, "operation", "Result<(std::vec::Vec<u8>, Tag), dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocstream::DryocStream.pull_to_vec", 2, "operation", "Result<(Vec<u8>, Tag), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocstream::DryocStream.push", 3, "operation", "Result<std::vec::Vec<u8>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::dryocstream::DryocStream.push_to_vec", 3, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::dryocstream::DryocStream.rekey", 0, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::dryocstream::Header.gen", 0, "factory", "dryoc::dryocstream::Header", []string{}, "high", []string{}},
		{"dryoc::dryocstream::Header.generate", 0, "factory", "dryoc::dryocstream::Header", []string{}, "high", []string{}},
		{"dryoc::dryocstream::Key.gen", 0, "factory", "dryoc::dryocstream::Key", []string{}, "high", []string{}},
		{"dryoc::dryocstream::Key.generate", 0, "factory", "dryoc::dryocstream::Key", []string{}, "high", []string{}},
		{"dryoc::dryocstream::Nonce.gen", 0, "factory", "dryoc::dryocstream::Nonce", []string{}, "high", []string{}},
		{"dryoc::dryocstream::Nonce.generate", 0, "factory", "dryoc::dryocstream::Nonce", []string{}, "high", []string{}},
		{"dryoc::generichash::GenericHash.finalize", 0, "operation", "Result<dryoc::generichash::Hash, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::generichash::GenericHash.finalize_to_vec", 0, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::generichash::GenericHash.hash", 2, "operation", "Result<dryoc::generichash::Hash, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::generichash::GenericHash.hash_to_vec", 2, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::generichash::GenericHash.hash_with_defaults", 2, "operation", "Result<dryoc::generichash::Hash, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::generichash::GenericHash.hash_with_defaults_to_vec", 2, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::generichash::GenericHash.new", 1, "factory", "Result<dryoc::generichash::GenericHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::generichash::GenericHash.new_with_defaults", 1, "factory", "Result<dryoc::generichash::GenericHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::generichash::GenericHash.update", 1, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::generichash::Key.gen", 0, "factory", "dryoc::generichash::Key", []string{}, "high", []string{}},
		{"dryoc::generichash::Key.generate", 0, "factory", "dryoc::generichash::Key", []string{}, "high", []string{}},
		{"dryoc::kdf::Kdf.derive_subkey", 1, "operation", "Result<dryoc::kdf::Key, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::kdf::Kdf.derive_subkey_to_vec", 1, "operation", "Result<Vec<u8>, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::kdf::Kdf.gen", 0, "factory", "dryoc::kdf::Kdf", []string{}, "high", []string{}},
		{"dryoc::kdf::Kdf.gen_with_defaults", 0, "factory", "dryoc::kdf::Kdf", []string{}, "high", []string{}},
		{"dryoc::kdf::Kdf.generate", 0, "factory", "dryoc::kdf::Kdf", []string{}, "high", []string{}},
		{"dryoc::kdf::Kdf.generate_with_defaults", 0, "factory", "dryoc::kdf::Kdf", []string{}, "high", []string{}},
		{"dryoc::kdf::Key.gen", 0, "factory", "dryoc::kdf::Key", []string{}, "high", []string{}},
		{"dryoc::kdf::Key.generate", 0, "factory", "dryoc::kdf::Key", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.from_secret_key", 1, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.from_seed", 1, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.from_slices", 2, "factory", "Result<dryoc::keypair::KeyPair, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.gen", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.gen_with_defaults", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.generate", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.generate_with_defaults", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.is_valid_ed25519_key", 1, "operation", "bool", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.is_valid_public_key", 1, "operation", "bool", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.kx_new_client_session", 1, "operation", "Result<kx::Session<dryoc::kx::SessionKey>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::keypair::KeyPair.kx_new_server_session", 1, "operation", "Result<kx::Session<dryoc::kx::SessionKey>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::keypair::KeyPair.new", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::keypair::KeyPair.precalculate", 1, "operation", "PrecalcSecretKey<StackByteArray<CRYPTO_BOX_BEFORENMBYTES>>", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.from_secret_key", 1, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.from_seed", 1, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.from_slices", 2, "factory", "Result<dryoc::keypair::KeyPair, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.gen", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.gen_with_defaults", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.generate", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.generate_with_defaults", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.is_valid_ed25519_key", 1, "operation", "bool", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.is_valid_public_key", 1, "operation", "bool", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.kx_new_client_session", 1, "operation", "Result<kx::Session<dryoc::kx::SessionKey>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::kx::KeyPair.kx_new_server_session", 1, "operation", "Result<kx::Session<dryoc::kx::SessionKey>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::kx::KeyPair.new", 0, "factory", "dryoc::keypair::KeyPair", []string{}, "high", []string{}},
		{"dryoc::kx::KeyPair.precalculate", 1, "operation", "PrecalcSecretKey<StackByteArray<CRYPTO_BOX_BEFORENMBYTES>>", []string{}, "high", []string{}},
		{"dryoc::kx::Session.new_client", 2, "operation", "Result<dryoc::kx::Session, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::kx::Session.new_client_with_defaults", 2, "operation", "Result<dryoc::kx::Session, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::kx::Session.new_server", 2, "operation", "Result<dryoc::kx::Session, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::kx::Session.new_server_with_defaults", 2, "operation", "Result<dryoc::kx::Session, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::Key.gen", 0, "factory", "dryoc::onetimeauth::Key", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::Key.generate", 0, "factory", "dryoc::onetimeauth::Key", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.compute", 2, "operation", "dryoc::onetimeauth::Mac", []string{}, "low", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.compute_and_verify", 3, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.compute_to_vec", 2, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.finalize", 0, "operation", "dryoc::onetimeauth::Mac", []string{}, "low", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.finalize_to_vec", 0, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.new", 1, "factory", "dryoc::onetimeauth::OnetimeAuth", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.update", 1, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::onetimeauth::OnetimeAuth.verify", 1, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::precalc::PrecalcSecretKey.precalculate", 2, "operation", "dryoc::precalc::PrecalcSecretKey", []string{}, "high", []string{}},
		{"dryoc::pwhash::Config.interactive", 0, "config", "dryoc::pwhash::Config", []string{}, "high", []string{}},
		{"dryoc::pwhash::Config.moderate", 0, "config", "dryoc::pwhash::Config", []string{}, "high", []string{}},
		{"dryoc::pwhash::Config.sensitive", 0, "config", "dryoc::pwhash::Config", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.derive_keypair", 3, "factory", "Result<keypair::KeyPair<dryoc::keypair::PublicKey, dryoc::keypair::SecretKey>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::pwhash::PwHash.from_string", 1, "factory", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.from_string_with_defaults", 1, "factory", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.hash", 2, "operation", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.hash_interactive", 1, "operation", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.hash_moderate", 1, "operation", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.hash_sensitive", 1, "operation", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.hash_with_defaults", 1, "operation", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.hash_with_salt", 3, "operation", "Result<dryoc::pwhash::PwHash, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::pwhash::PwHash.verify", 1, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::sha512::Sha512.compute", 1, "operation", "dryoc::sha512::Digest", []string{}, "low", []string{}},
		{"dryoc::sha512::Sha512.compute_into_bytes", 2, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::sha512::Sha512.compute_to_vec", 1, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::sha512::Sha512.finalize", 0, "operation", "dryoc::sha512::Digest", []string{}, "low", []string{}},
		{"dryoc::sha512::Sha512.finalize_into_bytes", 1, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::sha512::Sha512.finalize_to_vec", 0, "operation", "Vec<u8>", []string{}, "high", []string{}},
		{"dryoc::sha512::Sha512.new", 0, "factory", "dryoc::sha512::Sha512", []string{}, "high", []string{}},
		{"dryoc::sha512::Sha512.update", 1, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::sign::IncrementalSigner.finalize", 1, "operation", "Result<dryoc::sign::Signature, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::sign::IncrementalSigner.new", 0, "factory", "dryoc::sign::IncrementalSigner", []string{}, "high", []string{}},
		{"dryoc::sign::IncrementalSigner.update", 1, "operation", "()", []string{}, "high", []string{}},
		{"dryoc::sign::IncrementalSigner.verify", 2, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::sign::SignedMessage.verify", 1, "operation", "Result<(), dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.from_secret_key", 1, "factory", "dryoc::sign::SigningKeyPair", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.from_seed", 1, "factory", "dryoc::sign::SigningKeyPair", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.from_slices", 2, "factory", "Result<dryoc::sign::SigningKeyPair, dryoc::Error>", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.gen", 0, "factory", "dryoc::sign::SigningKeyPair", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.gen_with_defaults", 0, "factory", "dryoc::sign::SigningKeyPair", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.generate", 0, "factory", "dryoc::sign::SigningKeyPair", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.generate_with_defaults", 0, "factory", "dryoc::sign::SigningKeyPair", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.new", 0, "factory", "dryoc::sign::SigningKeyPair", []string{}, "high", []string{}},
		{"dryoc::sign::SigningKeyPair.sign", 1, "operation", "Result<SignedMessage<dryoc::sign::Signature, dryoc::sign::Message>, dryoc::Error>", []string{}, "low", []string{}},
		{"dryoc::sign::SigningKeyPair.sign_with_defaults", 1, "operation", "Result<SignedMessage<StackByteArray<CRYPTO_SIGN_BYTES>, Vec<u8>>, dryoc::Error>", []string{}, "high", []string{}},
	}

	render := func(method string, arity int, role, ret string, params []string, conf string, pblock []string) string {
		return fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=%s parameters=[%s]",
			method, arity, role, ret, strings.Join(params, ","), conf,
			strings.Join(pblock, ";"))
	}

	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[render(r.method, r.arity, r.role, r.ret, r.params, r.conf, r.pblock)] = true
	}
	if len(wantSet) != len(want) {
		t.Fatalf("the literal contains %d duplicate rows", len(want)-len(wantSet))
	}

	gotSet := map[string]bool{}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "dryoc" {
				continue
			}
			var pblock []string
			for _, p := range c.Parameters {
				idx := -1
				if p.Index != nil {
					idx = *p.Index
				}
				pblock = append(pblock, fmt.Sprintf("%d:%s:%s:%s:%s",
					idx, p.Name, p.Role, p.Contributes.Property, p.Contributes.Derivation))
			}
			sort.Strings(pblock)
			gotSet[render(c.Method, c.Arity, c.Role, c.Return.Type,
				c.ParameterTypes, c.Return.Confidence, pblock)] = true
		}
	}

	if len(gotSet) == 0 {
		t.Fatal("no dryoc contracts loaded at all -- every comparison below would be vacuous")
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
}

// `version_range`, `coordinates`, `name` and `description` are parsed and then
// consulted by nothing else, so corrupting any of them leaves every other
// assertion in this file green. This is the one that notices.
func TestDryocLibraryBlock(t *testing.T) {
	t.Parallel()

	// LoadEmbedded merges every rust library, and Merge() clears the
	// per-library block, so the single file is loaded on its own here.
	data, err := os.ReadFile(filepath.Join("contracts", "rust", "dryoc.yaml"))
	if err != nil {
		t.Fatalf("read dryoc.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(dryoc.yaml): %v", err)
	}
	got := kb.Library
	if got == nil {
		t.Fatal("no library block named dryoc")
	}
	if got.Name != "dryoc" {
		t.Errorf("library.name = %q, want %q", got.Name, "dryoc")
	}
	if want := ">=0.2.2,<0.9.0"; got.VersionRange != want {
		t.Errorf("version_range = %q, want %q", got.VersionRange, want)
	}
	if want := []string{"dryoc"}; strings.Join(got.Coordinates, ",") != strings.Join(want, ",") {
		t.Errorf("coordinates = %v, want %v", got.Coordinates, want)
	}
	if want := "dryoc: a pure-Rust libsodium/NaCl implementation, in a classic C-shaped API and a rustaceous one"; got.Description != want {
		t.Errorf("description = %q, want %q", got.Description, want)
	}
}

// THE PROTECTED-MEMORY SURFACE MUST STAY OUT. dryoc's `protected` module is
// mlock/mprotect page management and performs no cryptography (0.8.0
// src/protected.rs), and the family note excludes it explicitly. An entry here
// would make a hardening call read as a crypto asset.
func TestDryocProtectedMemoryIsAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "dryoc" {
				continue
			}
			bad := []string{
				"::protected::", ".mlock", ".mprotect", "HeapBytes",
				"HeapByteArray", "Locked", "gen_locked_keypair",
				"new_locked_keypair", "gen_readonly_locked_keypair",
			}
			for _, bad := range bad {
				if strings.Contains(c.Method, bad) {
					t.Errorf("protected-memory API contracted as crypto: %s", c.Method)
				}
			}
		}
	}
}

// The keys must be authored in the shape `rustAuthoredKey` normalises the
// call-site FQN ONTO, not the shape the call graph prints. A method key is
// `dryoc::<module path>::<Type>.<method>`; a free-function key carries ONE dot
// and is `dryoc::<module path>.<function>`, because rustAuthoredKey returns a
// key with fewer than two dots unchanged (contracts.go:267).
func TestDryocKeysUseTheAuthoredShape(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	n := 0
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "dryoc" {
				continue
			}
			n++
			if !strings.HasPrefix(c.Method, "dryoc::") && !strings.HasPrefix(c.Method, "dryoc.") {
				t.Errorf("%s is not rooted at the crate", c.Method)
			}
			if strings.Count(c.Method, ".") != 1 {
				t.Errorf("%s carries %d dots; exactly one belongs, in front of the method",
					c.Method, strings.Count(c.Method, "."))
			}
		}
	}
	if n == 0 {
		t.Fatal("no dryoc contracts loaded -- the assertions above are vacuous")
	}
}
