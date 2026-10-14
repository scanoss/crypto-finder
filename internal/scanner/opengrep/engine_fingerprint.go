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

package opengrep

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

// engineDigests memoizes the content digest of each engine file, keyed by
// its resolved path, size, modification time and mode, so one process
// hashes the executable once however many scanners it initializes.
var engineDigests sync.Map

// EngineFingerprint returns the SHA-256 of the opengrep executable's
// content and, in core mode with CoreBinaryEnv set, of the opengrep-core
// binary it names. Without CoreBinaryEnv, core mode runs the opengrep-core
// the executable unpacks (or one beside it reporting the same version), so
// the executable's content stands for it.
func (s *Scanner) EngineFingerprint() (string, error) {
	fingerprint, err := engineFileDigest(s.executablePath)
	if err != nil {
		return "", err
	}
	if s.mode == scanner.OpengrepModeCore {
		if core := os.Getenv(CoreBinaryEnv); core != "" {
			coreDigest, err := engineFileDigest(core)
			if err != nil {
				return "", err
			}
			fingerprint += "+core:" + coreDigest
		}
	}
	return fingerprint, nil
}

// engineFileDigest returns the hex SHA-256 of the file path resolves to.
func engineFileDigest(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("opengrep: fingerprint %s: %w", path, err)
	}
	info, err := os.Stat(resolved) // #nosec G703 -- The scanner's own executable.
	if err != nil {
		return "", fmt.Errorf("opengrep: fingerprint %s: %w", path, err)
	}
	key := fmt.Sprintf("%s\x00%d\x00%d\x00%d", resolved, info.Size(), info.ModTime().UnixNano(), info.Mode())
	if digest, ok := engineDigests.Load(key); ok {
		return digest.(string), nil //nolint:errcheck,forcetypeassert // Only strings are stored.
	}
	file, err := os.Open(resolved) // #nosec G304,G703 -- The scanner's own executable.
	if err != nil {
		return "", fmt.Errorf("opengrep: fingerprint %s: %w", path, err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // Read-only close cannot change the digest.
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("opengrep: fingerprint %s: %w", path, err)
	}
	digest := fmt.Sprintf("%x", hash.Sum(nil))
	engineDigests.Store(key, digest)
	return digest, nil
}
