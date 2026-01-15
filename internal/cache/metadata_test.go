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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetadata_IsExpired(t *testing.T) {
	tests := []struct {
		name            string
		downloadedAt    time.Time
		ttlSeconds      int64
		expectedExpired bool
	}{
		{
			name:            "not expired - downloaded 1 hour ago with 24h TTL",
			downloadedAt:    time.Now().Add(-1 * time.Hour),
			ttlSeconds:      int64((24 * time.Hour).Seconds()),
			expectedExpired: false,
		},
		{
			name:            "expired - downloaded 8 days ago with 7 day TTL",
			downloadedAt:    time.Now().Add(-8 * 24 * time.Hour),
			ttlSeconds:      int64((7 * 24 * time.Hour).Seconds()),
			expectedExpired: true,
		},
		{
			name:            "not expired - downloaded just now",
			downloadedAt:    time.Now(),
			ttlSeconds:      int64((1 * time.Hour).Seconds()),
			expectedExpired: false,
		},
		{
			name:            "expired - downloaded 2 days ago with 1 day TTL",
			downloadedAt:    time.Now().Add(-48 * time.Hour),
			ttlSeconds:      int64((24 * time.Hour).Seconds()),
			expectedExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &Metadata{
				RulesetName:    "test",
				Version:        "latest",
				DownloadedAt:   tt.downloadedAt,
				LastAccessed:   time.Now(),
				ChecksumSHA256: "test-checksum",
				TTLSeconds:     tt.ttlSeconds,
			}

			if expired := meta.IsExpired(); expired != tt.expectedExpired {
				t.Errorf("IsExpired() = %v, want %v", expired, tt.expectedExpired)
			}
		})
	}
}

func TestMetadata_UpdateLastAccessed(t *testing.T) {
	meta := &Metadata{
		RulesetName:    "test",
		Version:        "latest",
		DownloadedAt:   time.Now(),
		LastAccessed:   time.Now().Add(-1 * time.Hour),
		ChecksumSHA256: "test-checksum",
		TTLSeconds:     3600,
	}

	oldLastAccessed := meta.LastAccessed
	time.Sleep(10 * time.Millisecond)

	meta.UpdateLastAccessed()

	if !meta.LastAccessed.After(oldLastAccessed) {
		t.Error("UpdateLastAccessed() did not update the timestamp")
	}
}

func TestMetadata_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	metadataPath := filepath.Join(tempDir, ".cache-meta.json")

	// Create metadata
	original := NewMetadata("dca", "latest", "abc123checksum", 86400)

	// Save it
	if err := original.Save(metadataPath); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		t.Fatal("Metadata file was not created")
	}

	// Load it back
	loaded, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatalf("LoadMetadata() failed: %v", err)
	}

	// Compare fields
	if loaded.RulesetName != original.RulesetName {
		t.Errorf("RulesetName mismatch: got %v, want %v", loaded.RulesetName, original.RulesetName)
	}
	if loaded.Version != original.Version {
		t.Errorf("Version mismatch: got %v, want %v", loaded.Version, original.Version)
	}
	if loaded.ChecksumSHA256 != original.ChecksumSHA256 {
		t.Errorf("ChecksumSHA256 mismatch: got %v, want %v", loaded.ChecksumSHA256, original.ChecksumSHA256)
	}
	if loaded.TTLSeconds != original.TTLSeconds {
		t.Errorf("TTLSeconds mismatch: got %v, want %v", loaded.TTLSeconds, original.TTLSeconds)
	}
}

func TestNewMetadata(t *testing.T) {
	before := time.Now()
	meta := NewMetadata("dca", "v1.0.0", "checksum123", 604800)
	after := time.Now()

	if meta.RulesetName != "dca" {
		t.Errorf("RulesetName = %v, want 'dca'", meta.RulesetName)
	}
	if meta.Version != "v1.0.0" {
		t.Errorf("Version = %v, want 'v1.0.0'", meta.Version)
	}
	if meta.ChecksumSHA256 != "checksum123" {
		t.Errorf("ChecksumSHA256 = %v, want 'checksum123'", meta.ChecksumSHA256)
	}
	if meta.TTLSeconds != 604800 {
		t.Errorf("TTLSeconds = %v, want 604800", meta.TTLSeconds)
	}

	// Verify timestamps are set to now
	if meta.DownloadedAt.Before(before) || meta.DownloadedAt.After(after) {
		t.Error("DownloadedAt timestamp not set correctly")
	}
	if meta.LastAccessed.Before(before) || meta.LastAccessed.After(after) {
		t.Error("LastAccessed timestamp not set correctly")
	}
}

func TestMetadata_Age(t *testing.T) {
	tests := []struct {
		name         string
		downloadedAt time.Time
		expectedAge  time.Duration
		tolerance    time.Duration
	}{
		{
			name:         "5 days old",
			downloadedAt: time.Now().Add(-5 * 24 * time.Hour),
			expectedAge:  5 * 24 * time.Hour,
			tolerance:    1 * time.Second,
		},
		{
			name:         "1 hour old",
			downloadedAt: time.Now().Add(-1 * time.Hour),
			expectedAge:  1 * time.Hour,
			tolerance:    1 * time.Second,
		},
		{
			name:         "30 days old",
			downloadedAt: time.Now().Add(-30 * 24 * time.Hour),
			expectedAge:  30 * 24 * time.Hour,
			tolerance:    1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &Metadata{
				RulesetName:    "test",
				Version:        "latest",
				DownloadedAt:   tt.downloadedAt,
				LastAccessed:   time.Now(),
				ChecksumSHA256: "test-checksum",
				TTLSeconds:     3600,
			}

			age := meta.Age()

			// Check if age is within tolerance of expected age
			diff := age - tt.expectedAge
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.tolerance {
				t.Errorf("Age() = %v, want %v (±%v), diff = %v", age, tt.expectedAge, tt.tolerance, diff)
			}
		})
	}
}

func TestMetadata_IsTooStale(t *testing.T) {
	tests := []struct {
		name         string
		downloadedAt time.Time
		maxAge       time.Duration
		expectStale  bool
	}{
		{
			name:         "within limit - 5 days old, 30 day max",
			downloadedAt: time.Now().Add(-5 * 24 * time.Hour),
			maxAge:       30 * 24 * time.Hour,
			expectStale:  false,
		},
		{
			name:         "exceeds limit - 40 days old, 30 day max",
			downloadedAt: time.Now().Add(-40 * 24 * time.Hour),
			maxAge:       30 * 24 * time.Hour,
			expectStale:  true,
		},
		{
			name:         "just under limit - 29d 23h old, 30 day max",
			downloadedAt: time.Now().Add(-29*24*time.Hour - 23*time.Hour),
			maxAge:       30 * 24 * time.Hour,
			expectStale:  false, // Just under limit should be OK
		},
		{
			name:         "just over limit - 30d + 1h old, 30 day max",
			downloadedAt: time.Now().Add(-30*24*time.Hour - 1*time.Hour),
			maxAge:       30 * 24 * time.Hour,
			expectStale:  true,
		},
		{
			name:         "very old - 90 days old, 30 day max",
			downloadedAt: time.Now().Add(-90 * 24 * time.Hour),
			maxAge:       30 * 24 * time.Hour,
			expectStale:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &Metadata{
				RulesetName:    "test",
				Version:        "latest",
				DownloadedAt:   tt.downloadedAt,
				LastAccessed:   time.Now(),
				ChecksumSHA256: "test-checksum",
				TTLSeconds:     3600,
			}

			isStale := meta.IsTooStale(tt.maxAge)

			if isStale != tt.expectStale {
				t.Errorf("IsTooStale(%v) = %v, want %v (age: %v)", tt.maxAge, isStale, tt.expectStale, meta.Age())
			}
		})
	}
}
