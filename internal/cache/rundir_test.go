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

package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneStaleRuns(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	stale := filepath.Join(parent, "run-stale")
	fresh := filepath.Join(parent, "run-fresh")
	keep := filepath.Join(parent, "not-a-run")
	for _, d := range []string{stale, fresh, keep} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	PruneStaleRuns(parent)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("expected stale run-* pruned, err=%v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("expected fresh run-* kept: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("expected non-run dir untouched: %v", err)
	}
}
