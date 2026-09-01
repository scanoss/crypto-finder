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

import (
	"strings"

	"github.com/scanoss/crypto-finder/internal/skip"
)

// skipCallgraphWalkDir mirrors Builder.skipWalkDirectory for tests that
// walk a fixture themselves instead of going through the builder.
func skipCallgraphWalkDir(name string) bool {
	return strings.HasPrefix(name, ".") || skip.DefaultDirMatcher().ShouldSkip(name, true)
}
