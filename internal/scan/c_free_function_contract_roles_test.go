// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// A C library carries its object in the first argument of a free function
// (EVP_DigestUpdate(ctx, ...), crypto_secretstream_..._push(&state, ...)), not
// in a receiver. Each case's finding is the one the detection rules report on
// that file, at the lines and columns a scan reports.
const cEVPDigestConsumer = `#include <openssl/evp.h>

int sha256(const unsigned char *in, size_t inlen, unsigned char *out, unsigned int *outlen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal_ex(ctx, out, outlen);
    EVP_MD_CTX_free(ctx);
    return 1;
}
`

const cSecretstreamConsumer = `#include <sodium.h>

int seal_chunk(unsigned char *c, unsigned long long *clen,
               const unsigned char *m, unsigned long long mlen,
               unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]) {
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(key);
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    return crypto_secretstream_xchacha20poly1305_push(&state, c, clen, m, mlen, NULL, 0,
                                                      crypto_secretstream_xchacha20poly1305_TAG_FINAL);
}
`

const cMbedTLSCSRConsumer = `#include <mbedtls/x509_csr.h>

int load_request(const unsigned char *buf, size_t len) {
    mbedtls_x509_csr csr;
    mbedtls_x509_csr_init(&csr);
    int ret = mbedtls_x509_csr_parse(&csr, buf, len);
    mbedtls_x509_csr_free(&csr);
    return ret;
}
`

// PSA keeps its key attributes and multipart operations in caller-owned structs
// passed by address first, so the attribute setters and the update/finish calls
// share the object the finding's call is made on.
const cPSAKeyGenerationConsumer = `#include <psa/crypto.h>

psa_status_t make_key(psa_key_id_t *key) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_status_t status = psa_generate_key(&attributes, key);
    psa_reset_key_attributes(&attributes);
    return status;
}
`

const cPSAHashConsumer = `#include <psa/crypto.h>

psa_status_t sha256(const uint8_t *in, size_t len, uint8_t *out, size_t *olen) {
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_hash_setup(&op, PSA_ALG_SHA_256);
    psa_hash_update(&op, in, len);
    psa_status_t status = psa_hash_finish(&op, out, 32, olen);
    psa_hash_abort(&op);
    return status;
}
`

func TestCFreeFunctionSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, file, src string
		asset           entities.CryptographicAsset
		want            map[string]string
		absent          []string
		keyBits         map[string]int
	}{
		{
			name: "openssl evp digest context",
			file: "digest.c",
			src:  cEVPDigestConsumer,
			asset: cAsset(5, 5, 5, 38, "EVP_DigestInit(ctx, EVP_sha256());",
				"c.openssl.algorithm.hash.sha-2.digestinit", map[string]string{"assetType": "algorithm", "api": "EVP_DigestInit"}),
			want: map[string]string{
				"EVP_MD_CTX_new":     "factory",
				"EVP_DigestUpdate":   "operation",
				"EVP_DigestFinal_ex": "operation",
				"EVP_MD_CTX_free":    "",
			},
		},
		{
			name: "libsodium secretstream state",
			file: "stream.c",
			src:  cSecretstreamConsumer,
			asset: cAsset(10, 11, 12, 103, "return crypto_secretstream_xchacha20poly1305_push(&state, c, clen, m, mlen, NULL, 0,\n                                                      crypto_secretstream_xchacha20poly1305_TAG_FINAL);",
				"c.libsodium.algorithm.ae.xchacha20-poly1305.secretstream-push",
				map[string]string{"assetType": "algorithm", "api": "sodium.crypto_secretstream_xchacha20poly1305_push"}),
			want: map[string]string{
				"crypto_secretstream_xchacha20poly1305_init_push": "config",
			},
			// The key reaches init_push as an argument; keygen writes it but does
			// not operate on the stream state, so it is data flow, not lifecycle.
			absent: []string{"crypto_secretstream_xchacha20poly1305_keygen"},
		},
		{
			name: "mbedtls csr handle focused by the rule",
			file: "csr.c",
			src:  cMbedTLSCSRConsumer,
			asset: cAsset(6, 6, 38, 42, "int ret = mbedtls_x509_csr_parse(&csr, buf, len);",
				"c.crypto.mbedtls.x509-csr", map[string]string{"assetType": "certificate"}),
			want: map[string]string{
				"mbedtls_x509_csr_init": "factory",
				"mbedtls_x509_csr_free": "",
			},
		},
		{
			name: "psa key attributes configure the generated key",
			file: "keygen.c",
			src:  cPSAKeyGenerationConsumer,
			asset: cAsset(8, 8, 44, 55, "psa_status_t status = psa_generate_key(&attributes, key);",
				"c.crypto.mbedtls.psa-key-generation", map[string]string{"assetType": "algorithm"}),
			want: map[string]string{
				"psa_set_key_usage_flags":  "config",
				"psa_set_key_type":         "config",
				"psa_set_key_bits":         "config",
				"psa_reset_key_attributes": "",
			},
			keyBits: map[string]int{"psa_set_key_bits": 256},
		},
		{
			name: "psa multipart hash operation",
			file: "digest.c",
			src:  cPSAHashConsumer,
			asset: cAsset(5, 5, 25, 40, "psa_hash_setup(&op, PSA_ALG_SHA_256);",
				"c.mbedtls.algorithm.hash.sha-2.psa-alg",
				map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "api": "psa_crypto"}),
			want: map[string]string{
				"psa_hash_update": "operation",
				"psa_hash_finish": "operation",
				"psa_hash_abort":  "",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			graph, err := callgraph.NewBuilderForEcosystem("c", callgraph.NewCParser()).
				BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			report := &entities.InterimReport{
				Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
				Rules: entities.RulesInfo{Version: "v-test"},
				Findings: []entities.Finding{{
					FilePath:            tc.file,
					Language:            "c",
					CryptographicAssets: []entities.CryptographicAsset{tc.asset},
				}},
			}
			engine.EnsureFindingSources(report)
			engine.AssignFindingIDs(report)
			result := &engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: "c"}

			fragment := buildGraphFragmentExport(result)
			got := map[string]string{}
			gotBits := map[string]int{}
			var fragmentIDs []string
			for i := range fragment.SupportingCalls {
				s := &fragment.SupportingCalls[i]
				if s.SupportingCall != nil {
					got[s.SupportingCall.FunctionName] = s.Category
					if kl := s.SupportingCall.ResolvedKeyLength; kl != nil && kl.Bits != nil {
						gotBits[s.SupportingCall.FunctionName] = *kl.Bits
					}
				}
				fragmentIDs = append(fragmentIDs, s.SupportingID)
			}
			for symbol, bits := range tc.keyBits {
				if gotBits[symbol] != bits {
					t.Errorf("%s: resolved key length %d bits, want %d; got %v", symbol, gotBits[symbol], bits, gotBits)
				}
			}
			for symbol, category := range tc.want {
				gotCategory, ok := got[symbol]
				if !ok {
					t.Errorf("no supporting call %s; got %v", symbol, got)
					continue
				}
				if gotCategory != category {
					t.Errorf("%s: category %q, want %q", symbol, gotCategory, category)
				}
			}
			for _, symbol := range tc.absent {
				if _, ok := got[symbol]; ok {
					t.Errorf("%s is a supporting call, want it absent; got %v", symbol, got)
				}
			}
			if len(got) != len(tc.want) {
				t.Errorf("supporting calls = %v, want exactly %v", got, tc.want)
			}

			callgraphExport := buildCallGraphExportV2(result)
			fromCallgraph := map[string]string{}
			for i := range callgraphExport.SupportingCalls {
				s := &callgraphExport.SupportingCalls[i]
				fromCallgraph[s.SupportingCall.FunctionName] = s.Category
			}
			if !equalStringMaps(fromCallgraph, got) {
				t.Errorf("callgraph export supporting calls = %v, graph fragment = %v", fromCallgraph, got)
			}

			cached := decodeFragmentForTest(t, marshalSorted(t, fragment))
			annotate := buildAnnotateExport(prepareOIDFixtureReport(t, report), cached)
			var annotateIDs []string
			for i := range annotate.SupportingCalls {
				annotateIDs = append(annotateIDs, annotate.SupportingCalls[i].SupportingID)
			}
			sort.Strings(fragmentIDs)
			sort.Strings(annotateIDs)
			if len(annotateIDs) != len(fragmentIDs) {
				t.Fatalf("annotate supporting ids = %v, full export = %v", annotateIDs, fragmentIDs)
			}
			for i := range annotateIDs {
				if annotateIDs[i] != fragmentIDs[i] {
					t.Fatalf("annotate supporting ids = %v, full export = %v", annotateIDs, fragmentIDs)
				}
			}
		})
	}
}

func cAsset(startLine, endLine, startCol, endCol int, match, rule string, metadata map[string]string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: startLine,
		EndLine:   endLine,
		StartCol:  startCol,
		EndCol:    endCol,
		Match:     match,
		Rules:     []entities.RuleInfo{{ID: rule}},
		Metadata:  metadata,
	}
}

func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
