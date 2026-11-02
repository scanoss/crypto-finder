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

package callgraph

import "testing"

// A package belongs to its closest entry, so a dependency package recorded as
// not user code stays the dependency's even under a user ancestor.
func TestIsUserPackage_ClosestEntryWins(t *testing.T) {
	t.Parallel()

	java := map[string]bool{
		"com.acme":        true,
		"com.acme.app":    true,
		"com.acme.crypto": false,
	}
	goModule := map[string]bool{
		"example.com/app":       true,
		"example.com/app/tools": false,
	}
	cases := []struct {
		name string
		pkg  string
		set  map[string]bool
		sep  string
		want bool
	}{
		{"user package", "com.acme.app", java, ".", true},
		{"sub-package of a user package", "com.acme.app.web", java, ".", true},
		{"sibling under a user ancestor", "com.acme.billing", java, ".", true},
		{"dependency package under a user ancestor", "com.acme.crypto", java, ".", false},
		{"sub-package of a dependency package", "com.acme.crypto.internal", java, ".", false},
		{"package nothing declares", "org.bouncycastle", java, ".", false},
		{"parent of a user package", "com", java, ".", false},
		{"go sub-package", "example.com/app/internal/x", goModule, "/", true},
		{"nested go module", "example.com/app/tools/gen", goModule, "/", false},
		{"rust sub-module", "app::crypto::aes", map[string]bool{"app": true}, "::", true},
		{"unnamed root matches itself", "", map[string]bool{"": true}, ".", true},
		{"unnamed root is no ancestor", "Crypto.Cipher", map[string]bool{"": true}, ".", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isUserPackage(tc.pkg, tc.set, tc.sep); got != tc.want {
				t.Fatalf("isUserPackage(%q) = %v, want %v", tc.pkg, got, tc.want)
			}
		})
	}
}
