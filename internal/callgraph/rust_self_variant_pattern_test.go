// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A `Self::Variant(binding)` match arm must bind the variant's PAYLOAD type,
// exactly as the `Enum::Variant(binding)` spelling already does.
//
// This pins a measurement, not a preference: rustVariantKey built the facts
// key from the written path (`Self::Cha`), the variant's fields are recorded
// under the declared enum name (`Stream::Cha`), and the failed lookup fell
// back to binding the arm's name to the ENUM type. A dispatch wrapper that
// matches on `self` -- the shape keepass-db 0.0.1 writes around its
// salsa20/chacha20 streams -- then had every arm's receiver typed as the
// consumer's own enum, and FilterForeignReceiverAssets dropped the genuine
// dependency calls made through those receivers.
func TestRustSelfVariantPatternBindsThePayloadType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pattern string
	}{
		{"self_qualified", "Self::Cha(c)"},
		{"enum_qualified", "Stream::Cha(c)"}, // the previously working spelling must keep working
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			src := `use chacha20::ChaCha20;
use chacha20::cipher::StreamCipher;

pub enum Stream {
    Cha(ChaCha20),
}

impl Stream {
    pub fn run(&mut self, buf: &mut [u8]) {
        match self {
            ` + tc.pattern + ` => c.apply_keystream(buf),
        }
    }
}
`
			if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			analyses, err := NewRustParser().ParseDirectory(dir, "app")
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for ai := range analyses {
				fns := analyses[ai].Functions
				for fi := range fns {
					calls := fns[fi].Calls
					for ci := range calls {
						callee := calls[ci].Callee
						m, _ := splitMethodArity(&callee)
						seen[m] = true
					}
				}
			}
			if !seen["chacha20.ChaCha20.apply_keystream"] {
				t.Errorf("%s: arm binding not typed as the payload; seen = %v", tc.pattern, seen)
			}
			if seen["app.Stream.apply_keystream"] {
				t.Errorf("%s: arm binding still typed as the local enum; seen = %v", tc.pattern, seen)
			}
		})
	}
}
