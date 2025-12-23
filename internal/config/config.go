// Package config provides configuration management for the application.
package config

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/viper"
)

// Default configuration values.
const (
	DefaultAPIURL         = "https://api.scanoss.com"
	DefaultTimeout        = 30 * time.Second
	DefaultMaxRetries     = 3
	DefaultRetryDelay     = 5 * time.Second
	DefaultCacheTTL       = 7 * 24 * time.Hour // 7 days for pinned versions
	DefaultLatestCacheTTL = 24 * time.Hour     // 24 hours for @latest
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
	c.apiKey = key
	viper.Set("api_key", key)
	c.mu.Unlock()

	return c.writeConfig()
}

// SetAPIURL updates the API URL and persists to config file.
func (c *Config) SetAPIURL(url string) error {
	c.mu.Lock()
	c.apiURL = url
	viper.Set("api_url", url)
	c.mu.Unlock()

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
func (c *Config) writeConfig() error {
	if err := viper.WriteConfig(); err != nil {
		// If file doesn't exist, use SafeWriteConfig
		var configNotFoundErr viper.ConfigFileNotFoundError
		if errors.As(err, &configNotFoundErr) {
			if err := viper.SafeWriteConfig(); err != nil {
				return fmt.Errorf("failed to create config file: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to write config file: %w", err)
	}
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
