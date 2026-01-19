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
