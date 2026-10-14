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
	"fmt"
	"strings"
)

// OpengrepMode selects how the OpenGrep adapter runs the engine.
type OpengrepMode uint8

const (
	// OpengrepModeCLI runs the opengrep command-line wrapper. It is the zero
	// value; the crypto-finder CLI defaults to OpengrepModeCore instead.
	OpengrepModeCLI OpengrepMode = iota
	// OpengrepModeCore runs opengrep-core directly, bypassing the Python
	// wrapper, and falls back to the CLI when it cannot.
	OpengrepModeCore
)

// String returns the flag spelling of the mode.
func (m OpengrepMode) String() string {
	if m == OpengrepModeCore {
		return "core"
	}
	return "cli"
}

// ParseOpengrepMode reads a --opengrep-mode value. An empty value is the
// zero-value CLI mode; the crypto-finder CLI resolves an unset mode to core
// before parsing.
func ParseOpengrepMode(value string) (OpengrepMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "cli":
		return OpengrepModeCLI, nil
	case "core":
		return OpengrepModeCore, nil
	default:
		return OpengrepModeCLI, fmt.Errorf("unknown opengrep mode %q (want cli or core)", value)
	}
}

// RulePrefilter selects how rules are narrowed per scanned unit before the
// scanner loads them.
type RulePrefilter uint8

const (
	// RulePrefilterOff runs every rule (the default).
	RulePrefilterOff RulePrefilter = iota
	// RulePrefilterImports drops the rules whose import requirement the
	// unit's sources cannot meet, keeping every rule whose requirement is
	// unknown.
	RulePrefilterImports
)

// String returns the flag spelling of the prefilter.
func (p RulePrefilter) String() string {
	if p == RulePrefilterImports {
		return "imports"
	}
	return "off"
}

// ParseRulePrefilter reads a --rule-prefilter value. An empty value is off.
func ParseRulePrefilter(value string) (RulePrefilter, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off":
		return RulePrefilterOff, nil
	case "imports":
		return RulePrefilterImports, nil
	default:
		return RulePrefilterOff, fmt.Errorf("unknown rule prefilter %q (want off or imports)", value)
	}
}
