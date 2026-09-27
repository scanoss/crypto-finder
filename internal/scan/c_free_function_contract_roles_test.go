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

func TestCFreeFunctionSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, file, src string
		asset           entities.CryptographicAsset
		want            map[string]string
		absent          []string
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
			var fragmentIDs []string
			for i := range fragment.SupportingCalls {
				s := &fragment.SupportingCalls[i]
				if s.SupportingCall != nil {
					got[s.SupportingCall.FunctionName] = s.Category
				}
				fragmentIDs = append(fragmentIDs, s.SupportingID)
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
