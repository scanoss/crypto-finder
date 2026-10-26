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
	"context"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/rules/prefilter"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/skip"
)

// remoteFilterOptions are the scan settings that decide whether the remote
// ruleset is filtered to the target before download.
type remoteFilterOptions struct {
	scanner          string
	prefilter        scanner.RulePrefilter
	scanDependencies bool
	noRemoteFilter   bool
}

// remoteFilterProfile returns the profile builder for the remote ruleset,
// or nil when the whole ruleset must be downloaded: the import prefilter
// is off, the scanner is not OpenGrep, --no-remote-filter is set, or
// dependencies are scanned, whose units have imports of their own. The
// builder reads the target tree once, with the scan's skip patterns, and
// matches it against the ruleset index.
func remoteFilterProfile(target string, skipMatcher skip.SkipMatcher, opts remoteFilterOptions) rules.ProfileBuilder {
	switch {
	case opts.noRemoteFilter, opts.prefilter != scanner.RulePrefilterImports, opts.scanner != opengrep.ScannerName:
		return nil
	case opts.scanDependencies:
		log.Debug().Msg("Dependency scan: downloading the whole remote ruleset")
		return nil
	}
	return func(_ context.Context, index *prefilter.Index) (prefilter.Profile, error) {
		evidence, err := prefilter.EvidenceFromTree(target, skipMatcher.ShouldSkip)
		if err != nil {
			return prefilter.Profile{}, err
		}
		profile := prefilter.BuildProfile(evidence, index)
		log.Debug().
			Int("files", evidence.Files()).
			Strs("languages", profile.Languages).
			Int("modules", profile.ModuleCount()).
			Msg("Remote ruleset profile built from the target's sources")
		return profile, nil
	}
}
