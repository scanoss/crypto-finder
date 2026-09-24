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

//revive:disable:var-naming // scanner is a domain package name and intentionally matches CLI/config terminology.
package scanner

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTargetBatches(t *testing.T) {
	target := filepath.Join("repo", "root")

	require.Equal(t, [][]string{{target}}, TargetBatches(target, nil), "no scope scans the whole target once")
	require.Empty(t, TargetBatches(target, &DetectionScope{}), "an empty scope runs no scanner process")

	scope := &DetectionScope{Paths: []string{"a.go", filepath.Join("pkg", "b.go"), "c.go"}}
	require.Equal(t,
		[][]string{{filepath.Join(target, "a.go"), filepath.Join(target, "pkg", "b.go"), filepath.Join(target, "c.go")}},
		TargetBatches(target, scope), "scoped files are joined onto the target so result paths match a full walk")

	original := maxTargetArgBytes
	t.Cleanup(func() { maxTargetArgBytes = original })
	maxTargetArgBytes = len(filepath.Join(target, "a.go")) + len(filepath.Join(target, "pkg", "b.go")) + 2
	batches := TargetBatches(target, scope)
	require.Equal(t,
		[][]string{{filepath.Join(target, "a.go"), filepath.Join(target, "pkg", "b.go")}, {filepath.Join(target, "c.go")}},
		batches, "a list past the command-line budget is split, never truncated")

	maxTargetArgBytes = 1
	require.Len(t, TargetBatches(target, scope), 3, "a single path longer than the budget still gets its own invocation")
}
