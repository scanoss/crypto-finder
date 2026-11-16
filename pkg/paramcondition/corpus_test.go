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

package paramcondition

import (
	"bufio"
	"os"
	"testing"
)

// TestGrammarCorpusParsesClean guards the fail-fast load abort: every predicate
// shape the grammar accepts (positional, named and positional|named parameters;
// ==, ~= and :type comparisons; quoted, bare, boolean and dotted values) MUST
// parse without error. The corpus is synthetic.
func TestGrammarCorpusParsesClean(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/grammar-corpus.txt")
	if err != nil {
		t.Fatalf("open corpus fixture: %v", err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus fixture: %v", err)
	}

	const wantCount = 27
	if len(lines) != wantCount {
		t.Fatalf("corpus fixture has %d predicates, want %d", len(lines), wantCount)
	}

	for _, line := range lines {
		if _, err := ParseAll(line); err != nil {
			t.Errorf("ParseAll(%q) failed on the grammar corpus: %v", line, err)
		}
	}
}
