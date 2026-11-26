//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"testing"
)

// A digest finished once in live code and once in an #if 0 block, the dead
// call written over two lines, inside a macro and a conditional nested in
// the block.
const annotateCDeadDigest = `#include <openssl/evp.h>

#define CHECK(x) do { if (!(x)) return -1; } while (0)

int finish(EVP_MD_CTX *ctx, unsigned char *out) {
#if 0
#ifdef LEGACY
	CHECK (EVP_DigestFinal_ex(ctx,
		out, NULL));
#endif
#endif
	return EVP_DigestFinal_ex(ctx, out, NULL);
}
`

// annotate of a stored C graph drops the findings inside an #if 0 block, as
// the scan that stored it does by reading the file.
func TestAnnotateCDropsTheFindingsOfIf0Blocks(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	sections := annotateCRoundTrip(t, map[string]string{"lib/finish.c": annotateCDeadDigest}, "acme-digest")
	var operations []struct {
		StartLine int `json:"start_line"`
	}
	if err := json.Unmarshal(sections["crypto_annotations"], &operations); err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].StartLine != 12 {
		t.Fatalf("scan operations = %+v, want the live one at line 12 alone", operations)
	}
}
