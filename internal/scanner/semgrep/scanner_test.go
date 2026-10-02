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

package semgrep

import (
	"slices"
	"testing"
)

func TestBuildCommand_GitIgnoreOverrideOnlyWhenRequested(t *testing.T) {
	for _, include := range []bool{false, true} {
		s := NewScanner()
		s.includeGitIgnored = include
		args := s.buildCommand("/project/node_modules/eta", []string{"/rules/node.yaml"})
		if got := slices.Contains(args, "--no-git-ignore"); got != include {
			t.Errorf("includeGitIgnored=%v: --no-git-ignore present = %v, args %v", include, got, args)
		}
	}
}
