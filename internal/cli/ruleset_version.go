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
	"fmt"
	"regexp"
	"strings"

	"github.com/scanoss/static-engine/failure"
)

const rulesetVersionFlag = "ruleset-version"

// The version becomes a segment of the API download URL and of the cache
// directory, so anything other than "latest" or a release version is refused.
var rulesetVersionPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// resolveRulesetVersion returns the remote ruleset version to request: "latest"
// or a release version normalized to its "v" prefix ("1.39.0" -> "v1.39.0").
// Setting the flag together with --no-remote-rules is rejected, since no remote
// ruleset would be fetched to honor it.
func resolveRulesetVersion(value string, changed, noRemoteRules bool) (string, error) {
	if changed && noRemoteRules {
		return "", failure.New(
			failure.CodeInvalidArguments,
			failure.StageInput,
			fmt.Sprintf("--%s cannot be combined with --no-remote-rules", rulesetVersionFlag),
		)
	}

	version := strings.TrimSpace(value)
	if version == defaultRulesetVersion {
		return version, nil
	}
	if !rulesetVersionPattern.MatchString(version) {
		return "", failure.New(
			failure.CodeInvalidArguments,
			failure.StageInput,
			fmt.Sprintf("invalid --%s %q (use \"latest\" or a release version such as v1.39.0)", rulesetVersionFlag, value),
			failure.WithDetail("ruleset_version", value),
		)
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return version, nil
}
