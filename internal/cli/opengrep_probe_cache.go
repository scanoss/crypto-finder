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
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
)

// opengrepProbeCacheDirName holds OpenGrep version and help probe results
// under the crypto-finder cache directory.
const opengrepProbeCacheDirName = "opengrep-probes"

// opengrepProbeCacheDir returns where OpenGrep probe results persist, or ""
// to probe in every process when the cache directory is unavailable.
func opengrepProbeCacheDir() string {
	cacheDir, err := config.GetCacheDir()
	if err != nil {
		log.Debug().Err(err).Msg("cache directory unavailable; OpenGrep probes will not persist")
		return ""
	}
	return filepath.Join(cacheDir, opengrepProbeCacheDirName)
}
