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

package cardmatch

import "strings"

// The C and C++ ecosystems, as the call graph and the ruleset directories name them.
const (
	ecosystemC   = "c"
	ecosystemCPP = "cpp"
)

// cRule: the rule is read with the C shapes (its languages name c, cpp or
// c++). C rules name both c and cpp; C++ rules name cpp.
func cRule(r *OMap) bool {
	for _, l := range asOr[[]any](r.GetOr("languages")) {
		if s, ok := l.(string); ok {
			switch strings.ToLower(s) {
			case ecosystemC, ecosystemCPP, "c++":
				return true
			}
		}
	}
	return false
}
