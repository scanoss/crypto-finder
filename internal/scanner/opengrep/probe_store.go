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
package opengrep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// probeStoreSchema versions the entry format; a different value is a miss.
const probeStoreSchema = 1

// probeStore keeps the results of `opengrep --version` and `opengrep scan
// --help` on disk, so a new process skips probes an identical binary already
// answered. Entries are keyed by the binary fingerprint from discoveryKeys,
// so a replaced or updated binary never reuses them. Many processes may share
// the directory: each entry is written to a temporary file and renamed into
// place, so a reader sees a whole entry or none.
type probeStore struct {
	dir string
}

type probeEntry struct {
	Schema int    `json:"schema"`
	Kind   string `json:"kind"`
	Binary string `json:"binary"`
	Value  string `json:"value"`
}

func (s *probeStore) path(kind, binary string) string {
	return filepath.Join(s.dir, kind+"-"+binary+".json")
}

func (s *probeStore) load(kind, binary string) (string, bool) {
	if s == nil {
		return "", false
	}
	data, err := os.ReadFile(s.path(kind, binary))
	if err != nil {
		return "", false
	}
	var entry probeEntry
	if json.Unmarshal(data, &entry) != nil || entry.Schema != probeStoreSchema || entry.Kind != kind || entry.Binary != binary || entry.Value == "" {
		return "", false
	}
	return entry.Value, true
}

func (s *probeStore) save(kind, binary, value string) (err error) {
	if s == nil || value == "" {
		return nil
	}
	data, err := json.Marshal(probeEntry{Schema: probeStoreSchema, Kind: kind, Binary: binary, Value: value})
	if err != nil {
		return fmt.Errorf("opengrep: encode probe entry: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("opengrep: create probe cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, kind+"-*.tmp")
	if err != nil {
		return fmt.Errorf("opengrep: create probe cache file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name()) //nolint:errcheck,gosec // Best-effort cleanup of the temporary file CreateTemp made in the cache dir.
		}
	}()
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("opengrep: write probe cache file: %w", err)
	}
	//nolint:gosec // Both paths are in the probe cache dir the CLI chose; kind is a constant and binary a hex digest.
	if err = os.Rename(tmp.Name(), s.path(kind, binary)); err != nil {
		return fmt.Errorf("opengrep: publish probe cache file: %w", err)
	}
	return nil
}
