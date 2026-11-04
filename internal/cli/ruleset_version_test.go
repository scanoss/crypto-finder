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

import (
	"errors"
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
)

func TestResolveRulesetVersion(t *testing.T) {
	t.Parallel()

	accepted := []struct {
		value string
		want  string
	}{
		{value: "latest", want: "latest"},
		{value: "v1.39.0", want: "v1.39.0"},
		{value: "1.39.0", want: "v1.39.0"},
		{value: " v2.0.10 ", want: "v2.0.10"},
	}
	for _, tc := range accepted {
		got, err := resolveRulesetVersion(tc.value, true, false)
		if err != nil {
			t.Errorf("resolveRulesetVersion(%q) error = %v", tc.value, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveRulesetVersion(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}

	// Each of these would otherwise land in the download URL or cache path.
	for _, value := range []string{"", "Latest", "v1.39", "../../etc", "v1.39.0/../x", "v1.39.0-rc1"} {
		_, err := resolveRulesetVersion(value, true, false)
		assertInvalidArguments(t, value, err)
	}
}

func TestResolveRulesetVersionRejectsNoRemoteRules(t *testing.T) {
	t.Parallel()

	_, err := resolveRulesetVersion("v1.39.0", true, true)
	assertInvalidArguments(t, "v1.39.0 with --no-remote-rules", err)

	// The default value is not an explicit request, so local-only scans keep working.
	got, err := resolveRulesetVersion(defaultRulesetVersion, false, true)
	if err != nil || got != defaultRulesetVersion {
		t.Fatalf("default with --no-remote-rules = %q, %v; want %q, nil", got, err, defaultRulesetVersion)
	}
}

func assertInvalidArguments(t *testing.T, input string, err error) {
	t.Helper()
	var ferr *failure.Error
	if !errors.As(err, &ferr) || ferr.Code != failure.CodeInvalidArguments {
		t.Errorf("%s: error = %v, want %s", input, err, failure.CodeInvalidArguments)
	}
}
