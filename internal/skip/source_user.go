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

package skip

import "strings"

// UserExcludeSource provides skip patterns supplied directly via the CLI
// (--exclude <pattern> flag, repeatable). Patterns are taken verbatim and
// only trimmed; empty entries (e.g. from accidental --exclude "") are
// dropped to avoid emitting meaningless arguments to downstream scanners.
//
// Deduplication is intentionally NOT performed here — MultiSource.Load()
// deduplicates across all sources, keeping the single-responsibility
// principle: sources provide raw data, MultiSource normalises it.
type UserExcludeSource struct {
	patterns []string
}

// NewUserExcludeSource creates a source wrapping CLI --exclude patterns.
//
// Parameters:
//   - patterns: Raw pattern strings as received from the cobra flag.
//
// Returns:
//   - *UserExcludeSource: Source ready to be added to a MultiSource.
func NewUserExcludeSource(patterns []string) *UserExcludeSource {
	return &UserExcludeSource{patterns: patterns}
}

// Load returns the user-supplied patterns with whitespace trimmed and empty
// entries removed. This source never fails — it does no I/O.
//
// Returns:
//   - []string: Trimmed, non-empty patterns
//   - error: Always nil (included for interface compatibility)
func (u *UserExcludeSource) Load() ([]string, error) {
	out := make([]string, 0, len(u.patterns))
	for _, p := range u.patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Name returns a descriptive name for this pattern source.
// The flag name "--exclude" is embedded so that log messages like
// "Using N skip patterns from cli-flags(--exclude)" are immediately
// actionable — users can search their invocation for "--exclude".
func (u *UserExcludeSource) Name() string {
	return "cli-flags(--exclude)"
}
