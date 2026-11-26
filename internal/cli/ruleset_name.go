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

	"github.com/spf13/pflag"

	"github.com/scanoss/crypto-finder/internal/failure"
)

const (
	rulesetFlag = "ruleset"
	// defaultRulesetName is the remote ruleset a scan fetches unless
	// --ruleset names another: the card ruleset the cards detector of this
	// version matches.
	defaultRulesetName = "crypto-cards"
	rulesetUsage       = "Remote ruleset to fetch; crypto-cards holds the cards this version detects with"
)

// The name becomes a segment of the API download URL and of the cache
// directory, so it is lowercase letters and digits joined by single '-',
// '_' or '.'.
var rulesetNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:[-_.][a-z0-9]+)*$`)

// resolveRulesetName returns the remote ruleset to fetch. Setting the flag
// together with --no-remote-rules is rejected, since no remote ruleset would
// be fetched to honor it.
func resolveRulesetName(value string, changed, noRemoteRules bool) (string, error) {
	if changed && noRemoteRules {
		return "", failure.New(
			failure.CodeInvalidArguments,
			failure.StageInput,
			fmt.Sprintf("--%s cannot be combined with --no-remote-rules", rulesetFlag),
		)
	}
	name := strings.TrimSpace(value)
	if !rulesetNamePattern.MatchString(name) {
		return "", failure.New(
			failure.CodeInvalidArguments,
			failure.StageInput,
			fmt.Sprintf("invalid --%s %q (use a ruleset name such as %s)", rulesetFlag, value, defaultRulesetName),
			failure.WithDetail("ruleset", value),
		)
	}
	return name, nil
}

// resolveRemoteRuleset resolves the --ruleset and --ruleset-version values
// of flags into the remote ruleset name and version to fetch.
func resolveRemoteRuleset(flags *pflag.FlagSet, name, version string, noRemoteRules bool) (resolvedName, resolvedVersion string, err error) {
	resolvedName, err = resolveRulesetName(name, flags.Changed(rulesetFlag), noRemoteRules)
	if err != nil {
		return "", "", err
	}
	resolvedVersion, err = resolveRulesetVersion(version, flags.Changed(rulesetVersionFlag), noRemoteRules)
	if err != nil {
		return "", "", err
	}
	return resolvedName, resolvedVersion, nil
}
