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

package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Metadata represents the .cache-meta.json file stored with each cached ruleset.
type Metadata struct {
	RulesetName    string    `json:"ruleset_name"`
	Version        string    `json:"version"`
	DownloadedAt   time.Time `json:"downloaded_at"`
	LastAccessed   time.Time `json:"last_accessed"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	TTLSeconds     int64     `json:"ttl_seconds"`
}

// IsExpired checks if the cache has expired based on TTL.
func (m *Metadata) IsExpired() bool {
	expiryTime := m.DownloadedAt.Add(time.Duration(m.TTLSeconds) * time.Second)
	return time.Now().After(expiryTime)
}

// Age returns the age of the cache (time since download).
func (m *Metadata) Age() time.Duration {
	return time.Since(m.DownloadedAt)
}

// IsTooStale checks if the cache is older than the specified maximum age.
func (m *Metadata) IsTooStale(maxAge time.Duration) bool {
	return m.Age() > maxAge
}

// UpdateLastAccessed updates the last accessed timestamp.
func (m *Metadata) UpdateLastAccessed() {
	m.LastAccessed = time.Now()
}

// LoadMetadata loads metadata from a .cache-meta.json file.
func LoadMetadata(path string) (*Metadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	return &meta, nil
}

// Save saves the metadata to a .cache-meta.json file.
func (m *Metadata) Save(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	return nil
}

// NewMetadata creates a new metadata instance.
func NewMetadata(rulesetName, version, checksum string, ttlSeconds int64) *Metadata {
	now := time.Now()
	return &Metadata{
		RulesetName:    rulesetName,
		Version:        version,
		DownloadedAt:   now,
		LastAccessed:   now,
		ChecksumSHA256: checksum,
		TTLSeconds:     ttlSeconds,
	}
}
