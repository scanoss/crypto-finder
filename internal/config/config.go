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

// Package config provides configuration management for the application.
package config

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Default configuration values.
const (
	DefaultAPIURL           = "https://api.scanoss.com"
	DefaultTimeout          = 30 * time.Second
	DefaultMaxRetries       = 3
	DefaultRetryDelay       = 5 * time.Second
	DefaultCacheTTL         = 7 * 24 * time.Hour  // 7 days for pinned versions
	DefaultLatestCacheTTL   = 24 * time.Hour      // 24 hours for @latest
	DefaultMaxStaleCacheAge = 30 * 24 * time.Hour // 30 days for stale cache fallback
	MaxStaleCacheAge        = 90 * 24 * time.Hour // Maximum allowed: 90 days
)

// Config manages application configuration.
type Config struct {
	apiKey string
	apiURL string
	mu     sync.RWMutex
}

var (
	instance   *Config
	instanceMu sync.RWMutex
	once       sync.Once
)

// GetInstance returns the singleton config instance.
func GetInstance() *Config {
	once.Do(func() {
		instance = &Config{}
	})
	return instance
}

// ResetInstance resets the singleton instance.
// Only for testing purposes.
func ResetInstance() {
	instanceMu.Lock()
	defer instanceMu.Unlock()
	instance = nil
	once = sync.Once{}
}

// GetAPIKey returns the configured API key.
func (c *Config) GetAPIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

// GetAPIURL returns the configured API URL.
func (c *Config) GetAPIURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiURL
}

// SetAPIKey updates the API key and persists to config file.
func (c *Config) SetAPIKey(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.apiKey = key
	viper.Set("api_key", key)

	return c.writeConfig()
}

// SetAPIURL updates the API URL and persists to config file.
func (c *Config) SetAPIURL(url string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.apiURL = url
	viper.Set("api_url", url)

	return c.writeConfig()
}

// Initialize loads configuration from multiple sources.
// Viper automatically handles priority (highest to lowest):
// 1. Set() calls (used for CLI flags) - highest
// 2. Environment variables (SCANOSS_API_KEY, SCANOSS_API_URL)
// 3. Config file (~/.scanoss/crypto-finder/config.json)
// 4. Defaults (SetDefault) - lowest
//
// The order of setup below doesn't affect priority - viper handles it automatically.
func (c *Config) Initialize(apiKeyFlag, apiURLFlag string) error {
	// Only setup config file path if not already set.
	if viper.ConfigFileUsed() == "" {
		configPath, err := GetConfigFilePath()
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}

		configDir, err := GetAppDir()
		if err != nil {
			return fmt.Errorf("failed to get app directory: %w", err)
		}

		if err := os.MkdirAll(configDir, 0o750); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		// Setup viper
		viper.SetConfigFile(configPath)
		viper.SetConfigType("json")
		viper.SetConfigPermissions(0o600)
	}

	// Set defaults (lowest priority)
	viper.SetDefault("api_url", DefaultAPIURL)

	// Bind environment variables (2nd priority)
	viper.SetEnvPrefix("SCANOSS")
	if err := viper.BindEnv("api_key"); err != nil {
		return fmt.Errorf("failed to bind API key env var: %w", err)
	}
	if err := viper.BindEnv("api_url"); err != nil {
		return fmt.Errorf("failed to bind API URL env var: %w", err)
	}

	// Read config file (3rd priority)
	//nolint:errcheck // Ignore errors - file might not exist yet, we will create it later
	_ = viper.ReadInConfig()

	if err := c.ensureConfigPermissions(); err != nil {
		log.Warn().Err(err).Msg("Failed to ensure config file permissions")
	}

	// Apply CLI flags (highest priority)
	if apiKeyFlag != "" {
		viper.Set("api_key", apiKeyFlag)
	}
	if apiURLFlag != "" {
		viper.Set("api_url", apiURLFlag)
	}

	c.mu.Lock()
	c.apiKey = viper.GetString("api_key")
	c.apiURL = viper.GetString("api_url")
	c.mu.Unlock()

	return nil
}

// writeConfig writes the current viper configuration to the config file.
// Handles both creating new config files and updating existing ones.
// Ensures the config file has secure permissions (0o600) after writing.
func (c *Config) writeConfig() error {
	configPath := viper.ConfigFileUsed()

	//nolint:nestif // Config file creation requires nested error handling for WriteConfig fallback to SafeWriteConfig
	if err := viper.WriteConfig(); err != nil {
		// If file doesn't exist, use SafeWriteConfig
		var configNotFoundErr viper.ConfigFileNotFoundError
		if errors.As(err, &configNotFoundErr) {
			if err := viper.SafeWriteConfig(); err != nil {
				return fmt.Errorf("failed to create config file: %w", err)
			}
			// File was just created, ensure it has correct permissions
			if err := os.Chmod(configPath, 0o600); err != nil {
				return fmt.Errorf("failed to set config file permissions: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Ensure permissions are correct after write (in case file already existed)
	if err := os.Chmod(configPath, 0o600); err != nil {
		return fmt.Errorf("failed to set config file permissions: %w", err)
	}

	return nil
}

// ensureConfigPermissions checks and fixes permissions on the config file.
// Config files contain sensitive API keys and must be readable only by the owner (0o600).
// If permissions are too open, it automatically fixes them and logs a warning.
func (c *Config) ensureConfigPermissions() error {
	configPath := viper.ConfigFileUsed()
	if configPath == "" {
		// No config file path set, nothing to check
		return nil
	}

	// Check if file exists
	info, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, will be created with correct permissions
			return nil
		}
		// Unable to stat file, but don't fail - just return the error for logging
		return fmt.Errorf("unable to check config file permissions: %w", err)
	}

	// Check current permissions
	currentPerm := info.Mode().Perm()
	expectedPerm := os.FileMode(0o600)

	// If permissions are already correct, nothing to do
	if currentPerm == expectedPerm {
		return nil
	}

	// Permissions are too open, fix them
	if err := os.Chmod(configPath, expectedPerm); err != nil {
		return fmt.Errorf("unable to fix config file permissions: %w", err)
	}

	// Log warning about the fix
	log.Warn().
		Str("file", configPath).
		Str("old_permissions", currentPerm.String()).
		Str("new_permissions", expectedPerm.String()).
		Msg("Config file had insecure permissions, automatically fixed")

	return nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.apiURL == "" {
		return fmt.Errorf("api_url cannot be empty")
	}
	return nil
}
