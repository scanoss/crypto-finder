//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const annotateCRules = `rules:
- id: acme-digest
  languages: [c]
  message: Acme digest
  severity: INFO
  pattern: EVP_DigestFinal_ex(...)
  metadata:
    crypto:
      assetType: algorithm
      algorithmPrimitive: hash
`

// A digest whose context is set up by an OpenSSL call (a supporting call
// the C KB gives a category and parameter roles), updated through a static
// helper of the file and through a struct field.
const annotateCDigest = `#include <openssl/evp.h>

struct hasher { int (*update)(EVP_MD_CTX *, const void *, size_t); };

static int digest_update(EVP_MD_CTX *ctx, const unsigned char *data, size_t len) {
	return EVP_DigestUpdate(ctx, data, len);
}

int digest(struct hasher *h, const unsigned char *data, size_t len, unsigned char *out) {
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	digest_update(ctx, data, len);
	h->update(ctx, data, len);
	return EVP_DigestFinal_ex(ctx, out, NULL);
}
`

// annotate of a stored C graph, without the source, writes the findings and
// the crypto sections the scan that stored it wrote: the supporting calls
// keep the callee as written, and the category and the parameter roles the
// C KB gives a call of an externally linked function, which a file outside
// the root keys under its directory (lib.EVP_DigestInit_ex).
func TestAnnotateCWritesTheScanCryptoSections(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	sections := annotateCRoundTrip(t, map[string]string{"lib/digest.c": annotateCDigest}, "acme-digest")
	var supporting []struct {
		Category         string `json:"category"`
		MatchedOperation struct {
			Expression string `json:"expression"`
		} `json:"matched_operation"`
	}
	if err := json.Unmarshal(sections["supporting_calls"], &supporting); err != nil {
		t.Fatal(err)
	}
	categories := map[string]string{}
	for _, call := range supporting {
		categories[call.MatchedOperation.Expression] = call.Category
	}
	if categories["EVP_DigestInit_ex"] != "config" {
		t.Errorf("supporting calls by expression = %v, want EVP_DigestInit_ex with category config", categories)
	}
}

// annotateCRoundTrip scans the C files with annotateCRules, annotates the
// structural fragment without the source, as the miner does, and wants the
// scan's findings and crypto sections, among them an asset of each of
// wantRules. It returns the scan's crypto sections.
func annotateCRoundTrip(t *testing.T, files map[string]string, wantRules ...string) map[string]json.RawMessage {
	t.Helper()
	return annotateCFamilyRoundTrip(t, "c", map[string]string{"c": annotateCRules}, files, wantRules...)
}

// annotateCFamilyRoundTrip scans the files in language (c or cpp) with the
// rules, by rules directory language, annotates the structural fragment
// without the source, as the miner does, and wants the scan's findings and
// crypto sections, among them an asset of each of wantRules. It returns the
// scan's crypto sections.
func annotateCFamilyRoundTrip(t *testing.T, language string, rulesByLanguage, files map[string]string, wantRules ...string) map[string]json.RawMessage {
	t.Helper()
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "src")
	for name, content := range files {
		writeAnnotateCardsFile(t, filepath.Join(source, filepath.FromSlash(name)), content)
	}
	rules := filepath.Join(dir, "ruleset")
	for ruleLanguage, content := range rulesByLanguage {
		writeAnnotateCardsFile(t, filepath.Join(rules, "semgrep-rules", ruleLanguage, "x", "rules.yaml"), content)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Env = append(progressTestEnv(dir), "CRYPTO_FINDER_CARDS_C=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	common := []string{"--no-remote-rules", "--rules-dir", rules, "--languages", language}

	scanFindings := filepath.Join(dir, "scan-findings.json")
	fragment := filepath.Join(dir, "fragment.json")
	run(append([]string{"scan", "--output", scanFindings, "--export-graph-fragment", fragment, source}, common...)...)
	structural := filepath.Join(dir, "structural.json")
	writeStructuralFragment(t, fragment, structural)
	annotateFindings := filepath.Join(dir, "annotate-findings.json")
	annotation := filepath.Join(dir, "annotation.json")
	run(append([]string{"annotate", "--import-fragment", structural, "--output", annotation, "--findings-output", annotateFindings}, common...)...)

	want, got := readFindingAssets(t, scanFindings), readFindingAssets(t, annotateFindings)
	if language == "cpp" {
		// A scan names a header's language from its content (c++ for a
		// header with C++ code, c otherwise); annotate reads no source and
		// names it from the extension. The miner compares the assets.
		for _, asset := range slices.Concat(want, got) {
			delete(asset, "language")
		}
	}
	count := map[string]int{}
	for _, asset := range want {
		count[asset["rule"].(string)]++
	}
	for _, rule := range wantRules {
		if count[rule] == 0 {
			t.Fatalf("scan findings = %v, want an asset of %s", want, rule)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("annotate findings:\n%v\nwant the scan's:\n%v", got, want)
	}
	scanned, annotated := readCryptoSections(t, fragment), readCryptoSections(t, annotation)
	for section, value := range scanned {
		if string(annotated[section]) != string(value) {
			t.Errorf("annotation %s:\n%s\nwant the scan's:\n%s", section, annotated[section], value)
		}
	}
	return scanned
}
