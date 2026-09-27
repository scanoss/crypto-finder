package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The GnuTLS contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: teardown and transport calls share the gnutls_ prefix and must
// not resolve to a contract.
func TestGnuTLSContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/dtls.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9) {
    gnutls_init(a0, a1);
    gnutls_priority_init(a0, a1, a2);
    gnutls_priority_set_direct(a0, a1, a2);
    gnutls_priority_set(a0, a1);
    gnutls_set_default_priority(a0);
    gnutls_certificate_allocate_credentials(a0);
    gnutls_certificate_set_x509_key_file(a0, a1, a2, a3);
    gnutls_certificate_set_x509_trust_file(a0, a1, a2);
    gnutls_certificate_set_x509_system_trust(a0);
    gnutls_credentials_set(a0, a1, a2);
    gnutls_session_set_verify_cert(a0, a1, a2);
    gnutls_handshake(a0);
    gnutls_record_send(a0, a1, a2);
    gnutls_record_recv(a0, a1, a2);
    gnutls_protocol_get_version(a0);
    gnutls_cipher_get(a0);
    gnutls_mac_get(a0);
    gnutls_kx_get(a0);
    gnutls_dtls_cookie_send(a0, a1, a2, a3, a4, a5);
    gnutls_dtls_cookie_verify(a0, a1, a2, a3, a4, a5);
    gnutls_dtls_prestate_set(a0, a1);
    gnutls_cipher_init(a0, a1, a2, a3);
    gnutls_cipher_encrypt(a0, a1, a2);
    gnutls_cipher_decrypt(a0, a1, a2);
    gnutls_cipher_encrypt2(a0, a1, a2, a3, a4);
    gnutls_cipher_decrypt2(a0, a1, a2, a3, a4);
    gnutls_aead_cipher_init(a0, a1, a2);
    gnutls_aead_cipher_encrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    gnutls_aead_cipher_decrypt(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    gnutls_hash_init(a0, a1);
    gnutls_hash(a0, a1, a2);
    gnutls_hash_output(a0, a1);
    gnutls_hash_fast(a0, a1, a2, a3);
    gnutls_fingerprint(a0, a1, a2, a3);
    gnutls_hmac_init(a0, a1, a2, a3);
    gnutls_hmac(a0, a1, a2);
    gnutls_hmac_output(a0, a1);
    gnutls_hmac_fast(a0, a1, a2, a3, a4, a5);
    gnutls_pbkdf2(a0, a1, a2, a3, a4, a5);
    gnutls_hkdf_extract(a0, a1, a2, a3);
    gnutls_hkdf_expand(a0, a1, a2, a3, a4);
    gnutls_privkey_init(a0);
    gnutls_privkey_generate(a0, a1, a2, a3);
    gnutls_privkey_generate2(a0, a1, a2, a3, a4, a5);
    gnutls_privkey_import_rsa_raw(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    gnutls_privkey_import_x509(a0, a1, a2);
    gnutls_privkey_sign_hash(a0, a1, a2, a3, a4);
    gnutls_privkey_sign_data(a0, a1, a2, a3, a4);
    gnutls_pubkey_init(a0);
    gnutls_pubkey_import_rsa_raw(a0, a1, a2);
    gnutls_pubkey_import_x509(a0, a1, a2);
    gnutls_pubkey_verify_hash2(a0, a1, a2, a3, a4);
    gnutls_pubkey_verify_data2(a0, a1, a2, a3, a4);
    gnutls_x509_crt_init(a0);
    gnutls_x509_crt_import(a0, a1, a2);
    gnutls_x509_crt_export(a0, a1, a2, a3);
    gnutls_x509_crt_verify(a0, a1, a2, a3, a4);
    gnutls_x509_crt_sign2(a0, a1, a2, a3, a4);
    gnutls_x509_crt_get_pk_algorithm(a0, a1);
    gnutls_x509_privkey_init(a0);
    gnutls_x509_privkey_generate(a0, a1, a2, a3);
    gnutls_x509_privkey_import(a0, a1, a2);
    gnutls_x509_privkey_export(a0, a1, a2, a3);
    gnutls_rnd(a0, a1, a2);
    gnutls_rnd_refresh();
}

void not_contracted(gnutls_session_t session, gnutls_cipher_hd_t h) {
    gnutls_bye(session, GNUTLS_SHUT_RDWR);
    gnutls_cipher_deinit(h);
    gnutls_deinit(session);
    gnutls_transport_set_int(session, 3);
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
		"gnutls_init":                              {2, "factory"},
		"gnutls_priority_init":                     {3, "factory"},
		"gnutls_priority_set_direct":               {3, "config"},
		"gnutls_priority_set":                      {2, "config"},
		"gnutls_set_default_priority":              {1, "config"},
		"gnutls_certificate_allocate_credentials":  {1, "factory"},
		"gnutls_certificate_set_x509_key_file":     {4, "config"},
		"gnutls_certificate_set_x509_trust_file":   {3, "config"},
		"gnutls_certificate_set_x509_system_trust": {1, "config"},
		"gnutls_credentials_set":                   {3, "config"},
		"gnutls_session_set_verify_cert":           {3, "config"},
		"gnutls_handshake":                         {1, "operation"},
		"gnutls_record_send":                       {3, "operation"},
		"gnutls_record_recv":                       {3, "operation"},
		"gnutls_protocol_get_version":              {1, "output"},
		"gnutls_cipher_get":                        {1, "output"},
		"gnutls_mac_get":                           {1, "output"},
		"gnutls_kx_get":                            {1, "output"},
		"gnutls_dtls_cookie_send":                  {6, "operation"},
		"gnutls_dtls_cookie_verify":                {6, "operation"},
		"gnutls_dtls_prestate_set":                 {2, "config"},
		"gnutls_cipher_init":                       {4, "factory"},
		"gnutls_cipher_encrypt":                    {3, "operation"},
		"gnutls_cipher_decrypt":                    {3, "operation"},
		"gnutls_cipher_encrypt2":                   {5, "operation"},
		"gnutls_cipher_decrypt2":                   {5, "operation"},
		"gnutls_aead_cipher_init":                  {3, "factory"},
		"gnutls_aead_cipher_encrypt":               {10, "operation"},
		"gnutls_aead_cipher_decrypt":               {10, "operation"},
		"gnutls_hash_init":                         {2, "factory"},
		"gnutls_hash":                              {3, "operation"},
		"gnutls_hash_output":                       {2, "output"},
		"gnutls_hash_fast":                         {4, "operation"},
		"gnutls_fingerprint":                       {4, "operation"},
		"gnutls_hmac_init":                         {4, "factory"},
		"gnutls_hmac":                              {3, "operation"},
		"gnutls_hmac_output":                       {2, "output"},
		"gnutls_hmac_fast":                         {6, "operation"},
		"gnutls_pbkdf2":                            {6, "operation"},
		"gnutls_hkdf_extract":                      {4, "operation"},
		"gnutls_hkdf_expand":                       {5, "operation"},
		"gnutls_privkey_init":                      {1, "factory"},
		"gnutls_privkey_generate":                  {4, "operation"},
		"gnutls_privkey_generate2":                 {6, "operation"},
		"gnutls_privkey_import_rsa_raw":            {9, "factory"},
		"gnutls_privkey_import_x509":               {3, "factory"},
		"gnutls_privkey_sign_hash":                 {5, "operation"},
		"gnutls_privkey_sign_data":                 {5, "operation"},
		"gnutls_pubkey_init":                       {1, "factory"},
		"gnutls_pubkey_import_rsa_raw":             {3, "factory"},
		"gnutls_pubkey_import_x509":                {3, "factory"},
		"gnutls_pubkey_verify_hash2":               {5, "operation"},
		"gnutls_pubkey_verify_data2":               {5, "operation"},
		"gnutls_x509_crt_init":                     {1, "factory"},
		"gnutls_x509_crt_import":                   {3, "factory"},
		"gnutls_x509_crt_export":                   {4, "output"},
		"gnutls_x509_crt_verify":                   {5, "operation"},
		"gnutls_x509_crt_sign2":                    {5, "operation"},
		"gnutls_x509_crt_get_pk_algorithm":         {2, "output"},
		"gnutls_x509_privkey_init":                 {1, "factory"},
		"gnutls_x509_privkey_generate":             {4, "operation"},
		"gnutls_x509_privkey_import":               {3, "factory"},
		"gnutls_x509_privkey_export":               {4, "output"},
		"gnutls_rnd":                               {3, "operation"},
		"gnutls_rnd_refresh":                       {0, "config"},
	}
	negative := []string{"gnutls_bye", "gnutls_cipher_deinit", "gnutls_deinit", "gnutls_transport_set_int"}

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
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract",
						method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", bare, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "gnutls" {
					t.Fatalf("%s: library = %q, want gnutls", bare, got[0].SourceLibrary)
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

// The consumer names the cipher, digest, MAC, key algorithm or TLS mode at the
// call site. Each call that takes that selector must carry it as
// operation-determining at the right index, or the algorithm identity of the
// finding it supports is unattributed.
func TestGnuTLSContractsMarkAlgorithmSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"gnutls_init":                  {2, 1, "protocol"},
		"gnutls_cipher_init":           {4, 1, "algorithm"},
		"gnutls_aead_cipher_init":      {3, 1, "algorithm"},
		"gnutls_hash_init":             {2, 1, "algorithm"},
		"gnutls_hash_fast":             {4, 0, "algorithm"},
		"gnutls_fingerprint":           {4, 0, "algorithm"},
		"gnutls_hmac_init":             {4, 1, "algorithm"},
		"gnutls_hmac_fast":             {6, 0, "algorithm"},
		"gnutls_pbkdf2":                {6, 0, "algorithm"},
		"gnutls_hkdf_extract":          {4, 0, "algorithm"},
		"gnutls_hkdf_expand":           {5, 0, "algorithm"},
		"gnutls_privkey_generate":      {4, 1, "algorithm"},
		"gnutls_privkey_generate2":     {6, 1, "algorithm"},
		"gnutls_privkey_sign_hash":     {5, 1, "algorithm"},
		"gnutls_privkey_sign_data":     {5, 1, "algorithm"},
		"gnutls_pubkey_verify_hash2":   {5, 1, "algorithm"},
		"gnutls_pubkey_verify_data2":   {5, 1, "algorithm"},
		"gnutls_x509_crt_sign2":        {5, 3, "algorithm"},
		"gnutls_x509_privkey_generate": {4, 1, "algorithm"},
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
