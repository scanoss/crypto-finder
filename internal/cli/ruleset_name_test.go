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

package cli

import "testing"

// scan and annotate fetch crypto-cards unless --ruleset names another.
func TestRulesetFlagDefaultsToCryptoCards(t *testing.T) {
	t.Parallel()

	for _, cmd := range []struct {
		name  string
		value string
	}{
		{"scan", scanCmd.Flags().Lookup(rulesetFlag).DefValue},
		{"annotate", annotateCmd.Flags().Lookup(rulesetFlag).DefValue},
	} {
		if cmd.value != "crypto-cards" {
			t.Errorf("%s --%s default = %q, want crypto-cards", cmd.name, rulesetFlag, cmd.value)
		}
	}
}

func TestResolveRulesetName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ value, want string }{
		{"crypto-cards", "crypto-cards"},
		{" dca ", "dca"},
		{"a_b.c-1", "a_b.c-1"},
	} {
		got, err := resolveRulesetName(tc.value, true, false)
		if err != nil || got != tc.want {
			t.Errorf("resolveRulesetName(%q) = %q, %v; want %q", tc.value, got, err, tc.want)
		}
	}

	// Each of these would otherwise land in the download URL or cache path.
	for _, value := range []string{"", "Crypto-Cards", "..", "a/b", "../dca", "-dca", "dca-", "a..b", "a b"} {
		_, err := resolveRulesetName(value, true, false)
		assertInvalidArguments(t, value, err)
	}
}

func TestResolveRulesetNameRejectsNoRemoteRules(t *testing.T) {
	t.Parallel()

	_, err := resolveRulesetName("dca", true, true)
	assertInvalidArguments(t, "dca with --no-remote-rules", err)

	// The default value is not an explicit request, so local-only scans keep working.
	got, err := resolveRulesetName(defaultRulesetName, false, true)
	if err != nil || got != defaultRulesetName {
		t.Fatalf("default with --no-remote-rules = %q, %v; want %q, nil", got, err, defaultRulesetName)
	}
}
