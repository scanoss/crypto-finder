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

package main

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/scripts/internal/leakguard"
)

func TestHashCommand(t *testing.T) {
	want, err := leakguard.Hash("Plum-Orchard", true)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run([]string{"hash", "--exact", "--category", "repository", "-"}, strings.NewReader("Plum-Orchard\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if got := strings.TrimSpace(out.String()); got != "repository exact "+want {
		t.Errorf("got %q", got)
	}
	if _, err := leakguard.ParseDenylist(out.String()); err != nil {
		t.Errorf("the printed line does not parse: %v", err)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {"hash"}, {"hash", "a", "b"}, {"hash", "a b c d e"}} {
		var out, errOut strings.Builder
		if code := run(args, strings.NewReader(""), &out, &errOut); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}
