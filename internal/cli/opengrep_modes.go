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
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

const (
	// opengrepModeEnv sets --opengrep-mode when the flag is not given.
	opengrepModeEnv = "SCANOSS_OPENGREP_MODE"
	// rulePrefilterEnv sets --rule-prefilter when the flag is not given.
	rulePrefilterEnv = "SCANOSS_RULE_PREFILTER"
	// opengrepCoreRulesCacheDirName holds the rules files core mode hands
	// opengrep-core, under the crypto-finder cache directory.
	opengrepCoreRulesCacheDirName = "opengrep-core-rules"
)

// resolveOpengrepMode returns the OpenGrep execution mode: an explicit
// --opengrep-mode wins over SCANOSS_OPENGREP_MODE; neither runs
// opengrep-core, which itself falls back to the CLI whenever it cannot run.
// --opengrep-mode cli or SCANOSS_OPENGREP_MODE=cli opts out.
func resolveOpengrepMode(flagSet bool, flagValue string, lookupEnv func(string) (string, bool)) (scanner.OpengrepMode, error) {
	source, value := "--opengrep-mode", flagValue
	if !flagSet {
		raw, ok := lookupEnv(opengrepModeEnv)
		if !ok || strings.TrimSpace(raw) == "" {
			return scanner.OpengrepModeCore, nil
		}
		source, value = opengrepModeEnv, raw
	}
	mode, err := scanner.ParseOpengrepMode(value)
	if err != nil {
		return scanner.OpengrepModeCLI, fmt.Errorf("%s: %w", source, err)
	}
	return mode, nil
}

// opengrepModeExplicit reports whether the user chose an OpenGrep mode, by
// flag or SCANOSS_OPENGREP_MODE, rather than leaving the default.
func opengrepModeExplicit(flagSet bool, lookupEnv func(string) (string, bool)) bool {
	if flagSet {
		return true
	}
	raw, ok := lookupEnv(opengrepModeEnv)
	return ok && strings.TrimSpace(raw) != ""
}

// resolveRulePrefilter returns the rule prefilter: an explicit
// --rule-prefilter wins over SCANOSS_RULE_PREFILTER; neither keeps it off.
func resolveRulePrefilter(flagSet bool, flagValue string, lookupEnv func(string) (string, bool)) (scanner.RulePrefilter, error) {
	source, value := "--rule-prefilter", flagValue
	if !flagSet {
		raw, ok := lookupEnv(rulePrefilterEnv)
		if !ok || strings.TrimSpace(raw) == "" {
			return scanner.RulePrefilterOff, nil
		}
		source, value = rulePrefilterEnv, raw
	}
	prefilter, err := scanner.ParseRulePrefilter(value)
	if err != nil {
		return scanner.RulePrefilterOff, fmt.Errorf("%s: %w", source, err)
	}
	return prefilter, nil
}

// opengrepCoreRulesCacheDir returns where core mode keeps opengrep-core
// rules files, or "" to write one per scan when the cache directory is
// unavailable.
func opengrepCoreRulesCacheDir() string {
	cacheDir, err := config.GetCacheDir()
	if err != nil {
		log.Debug().Err(err).Msg("cache directory unavailable; opengrep-core rules files will not persist")
		return ""
	}
	return filepath.Join(cacheDir, opengrepCoreRulesCacheDirName)
}
