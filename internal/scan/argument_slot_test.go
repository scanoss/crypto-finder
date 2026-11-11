// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

func TestArgumentSlot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		index     int
		param     string
		wantSlot  int
		wantFound bool
	}{
		{"positional", []string{`b"x"`, `"sha256"`}, 1, "alg", 1, true},
		{"python keyword in another order", []string{`alg="md5"`, `data=b"x"`}, 1, "alg", 0, true},
		{"python keyword before the slot", []string{`data=b"x"`, `"sha256"`}, 1, "alg", 0, false},
		{"python splat before the slot", []string{`*parts`, `"sha256"`}, 1, "alg", 0, false},
		{"javascript spread before the slot", []string{`...parts`, `"sha256"`}, 1, "alg", 0, false},
		{"javascript arrow before the slot", []string{`s => s.trim()`, `"sha256"`}, 1, "alg", 1, true},
		{"javascript arrow named like the parameter", []string{`alg => alg`, `"sha256"`}, 1, "alg", 1, true},
		{"missing argument", []string{`b"x"`}, 1, "alg", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			slot, ok := argumentSlot(len(tt.args), func(i int) string { return tt.args[i] }, tt.index, tt.param)
			if ok != tt.wantFound || ok && slot != tt.wantSlot {
				t.Fatalf("argumentSlot(%q, %d, %q) = %d, %v; want %d, %v", tt.args, tt.index, tt.param, slot, ok, tt.wantSlot, tt.wantFound)
			}
		})
	}
}
