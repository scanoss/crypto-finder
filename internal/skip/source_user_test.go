// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package skip

import (
	"strings"
	"testing"
)

func TestUserExcludeSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		wantOut  []string
		wantLen  int
		wantNil  bool
	}{
		{
			name:    "emptyInput",
			input:   nil,
			wantOut: []string{},
			wantLen: 0,
		},
		{
			name:    "whitespaceTrimmed",
			input:   []string{" vendor ", "build"},
			wantOut: []string{"vendor", "build"},
			wantLen: 2,
		},
		{
			name:    "emptyAfterTrimDropped",
			input:   []string{"", "   ", "build"},
			wantOut: []string{"build"},
			wantLen: 1,
		},
		{
			name:    "verbatimPatternsPreservedNoDedup",
			input:   []string{"**/*.go", "**/*.go"},
			wantOut: []string{"**/*.go", "**/*.go"},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src := NewUserExcludeSource(tt.input)
			got, err := src.Load()
			if err != nil {
				t.Fatalf("Load() returned unexpected error: %v", err)
			}

			if len(got) != len(tt.wantOut) {
				t.Fatalf("Load() returned %d patterns, want %d: got %v", len(got), len(tt.wantOut), got)
			}

			for i, want := range tt.wantOut {
				if got[i] != want {
					t.Errorf("Load()[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

func TestUserExcludeSource_Name(t *testing.T) {
	t.Parallel()

	// nameContainsFlagName: Name() must contain "--exclude" so log messages are actionable
	src := NewUserExcludeSource(nil)
	name := src.Name()

	if !strings.Contains(name, "--exclude") {
		t.Errorf("UserExcludeSource.Name() = %q, want it to contain \"--exclude\"", name)
	}
}
