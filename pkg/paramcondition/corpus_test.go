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

// TestCorpusV1_18_0ParsesClean guards the fail-fast rule-load abort against
// real data: every parameterCondition predicate shipped in crypto_rules
// v1.18.0 (158 occurrences, extracted verbatim from the deployed rules
// pack) MUST parse without error, or the abort would reject a real ruleset.
func TestCorpusV1_18_0ParsesClean(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/parameter-conditions-v1.18.0.txt")
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

	const wantCount = 158
	if len(lines) != wantCount {
		t.Fatalf("corpus fixture has %d predicates, want %d", len(lines), wantCount)
	}

	for _, line := range lines {
		if _, err := ParseAll(line); err != nil {
			t.Errorf("ParseAll(%q) failed against real v1.18.0 corpus: %v", line, err)
		}
	}
}
