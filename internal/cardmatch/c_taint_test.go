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

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCTaintMatchesAsOpenGrep pins C taint to what OpenGrep 1.33.1
// --taint-intrafile reports for an invented rule on invented files: a value
// reaching the sink through a local, and through parameters callers in the
// same file fill, two and four calls up; not through a caller in another file
// (other.c), nor where the literal does not match (ACME-DES). Same places
// (columns start at the callee, end exclusive) and the named group OpenGrep
// binds. The fragment lists files from the copy's src/, OpenGrep from its root.
func TestCTaintMatchesAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "c_taint"))
	found, stats := matchCStats(assets, newFrag(frag))
	if stats.UnreadableSites != 0 {
		t.Fatalf("stats = %+v, want every site read", stats)
	}
	got := make([]string, 0, len(found))
	exp := make([]string, 0, len(want["value"]))
	for _, f := range found {
		got = append(got, f.File+":"+itoa(f.Line)+":"+itoa(f.Col)+"-"+itoa(f.EndCol)+" "+f.MetadataMap()["algorithmName"].(string))
	}
	for _, h := range want["value"] {
		exp = append(exp, strings.TrimPrefix(h.File, "src/")+":"+itoa(h.Line)+":"+itoa(h.Col)+"-"+itoa(h.EndCol)+" AES-"+h.Metavar["$bits"])
	}
	slices.Sort(got)
	slices.Sort(exp)
	if !slices.Equal(got, exp) {
		t.Errorf("found\n %v\nOpenGrep\n %v", got, exp)
	}
}
