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
	"context"
	"crypto/sha256"
	"errors"
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

// coreFingerprintPrefix marks a fingerprint of an opengrep-core binary, so
// it never reads as the digest of an opengrep executable.
const coreFingerprintPrefix = "core:"

// EngineFingerprint returns the SHA-256 of the content of the engine the
// scan will run. In core mode that is the opengrep-core binary coreBinary
// resolves, prefixed to tell it from an executable's digest; when core mode
// cannot run (an unverified version, no opengrep-core found) the scan runs
// the opengrep executable and the fingerprint is its digest, as in CLI
// mode. A core run that fails during the scan falls back to the executable
// too, which no fingerprint computed beforehand can foresee.
func (s *Scanner) EngineFingerprint(ctx context.Context) (string, error) {
	if s.mode == scanner.OpengrepModeCore {
		core, err := s.coreBinary(ctx)
		switch {
		case err == nil:
			digest, err := engineFileDigest(core)
			if err != nil {
				return "", err
			}
			return coreFingerprintPrefix + digest, nil
		case !errors.Is(err, errCoreUnavailable):
			return "", err
		}
	}
	return engineFileDigest(s.executablePath)
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
