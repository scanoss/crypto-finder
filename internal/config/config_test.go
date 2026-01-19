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

package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

// setupTest prepares a clean test environment.
func setupTest(t *testing.T) func() {
	t.Helper()

	// Reset singleton
	ResetInstance()

	// Create temp config directory
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// Override config file path for testing
	oldConfigFile := viper.ConfigFileUsed()

	// Clear environment variables
	os.Unsetenv("SCANOSS_API_KEY")
	os.Unsetenv("SCANOSS_API_URL")

	// Reset viper
	viper.Reset()
	viper.SetConfigFile(configPath)
	viper.SetConfigType("json")

	return func() {
		// Cleanup
		viper.Reset()
		if oldConfigFile != "" {
			viper.SetConfigFile(oldConfigFile)
		}
		ResetInstance()
	}
}

func TestGetInstance_Singleton(t *testing.T) {
	defer setupTest(t)()

	instance1 := GetInstance()
	instance2 := GetInstance()

	if instance1 != instance2 {
		t.Error("GetInstance() should return the same instance")
	}
}

func TestGetInstance_ThreadSafe(t *testing.T) {
	defer setupTest(t)()

	const goroutines = 100
	instances := make([]*Config, goroutines)
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(index int) {
			defer wg.Done()
			instances[index] = GetInstance()
		}(i)
	}
	wg.Wait()

	// All instances should be the same
	first := instances[0]
	for i := 1; i < goroutines; i++ {
		if instances[i] != first {
			t.Errorf("Instance %d is different from first instance", i)
		}
	}
}

func TestInitialize_Priority_CLIFlags(t *testing.T) {
	defer setupTest(t)()

	// Set environment variables
	os.Setenv("SCANOSS_API_KEY", "env-key")
	os.Setenv("SCANOSS_API_URL", "https://env.example.com")
	defer os.Unsetenv("SCANOSS_API_KEY")
	defer os.Unsetenv("SCANOSS_API_URL")

	cfg := GetInstance()
	err := cfg.Initialize("cli-key", "https://cli.example.com")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// CLI flags should override environment variables
	if cfg.GetAPIKey() != "cli-key" {
		t.Errorf("Expected API key 'cli-key', got '%s'", cfg.GetAPIKey())
	}
	if cfg.GetAPIURL() != "https://cli.example.com" {
		t.Errorf("Expected API URL 'https://cli.example.com', got '%s'", cfg.GetAPIURL())
	}
}

func TestInitialize_Priority_EnvVars(t *testing.T) {
	defer setupTest(t)()

	// Set environment variables
	os.Setenv("SCANOSS_API_KEY", "env-key")
	os.Setenv("SCANOSS_API_URL", "https://env.example.com")
	defer os.Unsetenv("SCANOSS_API_KEY")
	defer os.Unsetenv("SCANOSS_API_URL")

	cfg := GetInstance()
	// Initialize without CLI flags
	err := cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Environment variables should be used
	if cfg.GetAPIKey() != "env-key" {
		t.Errorf("Expected API key 'env-key', got '%s'", cfg.GetAPIKey())
	}
	if cfg.GetAPIURL() != "https://env.example.com" {
		t.Errorf("Expected API URL 'https://env.example.com', got '%s'", cfg.GetAPIURL())
	}
}

func TestInitialize_Priority_ConfigFile(t *testing.T) {
	defer setupTest(t)()

	// Write config file directly
	configFile := viper.ConfigFileUsed()
	viper.Set("api_key", "file-key")
	viper.Set("api_url", "https://file.example.com")
	if err := viper.WriteConfigAs(configFile); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Reset viper state and reload config file
	viper.Reset()
	viper.SetConfigFile(configFile)
	viper.SetConfigType("json")
	viper.SetEnvPrefix("SCANOSS")
	_ = viper.BindEnv("api_key")
	_ = viper.BindEnv("api_url")

	cfg := GetInstance()
	// Initialize without CLI flags or env vars
	err := cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Config file values should be used
	if cfg.GetAPIKey() != "file-key" {
		t.Errorf("Expected API key 'file-key', got '%s'", cfg.GetAPIKey())
	}
	if cfg.GetAPIURL() != "https://file.example.com" {
		t.Errorf("Expected API URL 'https://file.example.com', got '%s'", cfg.GetAPIURL())
	}
}

func TestInitialize_Priority_Defaults(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	err := cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// API URL should have default value
	if cfg.GetAPIURL() != DefaultAPIURL {
		t.Errorf("Expected default API URL '%s', got '%s'", DefaultAPIURL, cfg.GetAPIURL())
	}

	// API key should be empty (no default)
	if cfg.GetAPIKey() != "" {
		t.Errorf("Expected empty API key, got '%s'", cfg.GetAPIKey())
	}
}

func TestInitialize_Priority_FullChain(t *testing.T) {
	defer setupTest(t)()

	// Setup all priority levels
	// 1. Config file (lowest)
	configFile := viper.ConfigFileUsed()
	viper.Set("api_key", "file-key")
	viper.Set("api_url", "https://file.example.com")
	if err := viper.WriteConfigAs(configFile); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Reset and reload
	viper.Reset()
	viper.SetConfigFile(configFile)
	viper.SetConfigType("json")
	viper.SetEnvPrefix("SCANOSS")
	_ = viper.BindEnv("api_key")
	_ = viper.BindEnv("api_url")

	// 2. Environment variables (middle)
	os.Setenv("SCANOSS_API_KEY", "env-key")
	defer os.Unsetenv("SCANOSS_API_KEY")

	// 3. CLI flags (highest)
	cfg := GetInstance()
	err := cfg.Initialize("cli-key", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// CLI flag should override env var
	if cfg.GetAPIKey() != "cli-key" {
		t.Errorf("Expected API key 'cli-key' (CLI flag), got '%s'", cfg.GetAPIKey())
	}

	// Env var should override config file
	// (but we provided CLI flag for key, so URL should come from file)
	if cfg.GetAPIURL() != "https://file.example.com" {
		t.Errorf("Expected API URL 'https://file.example.com' (file), got '%s'", cfg.GetAPIURL())
	}
}

func TestSetAPIKey_Persistence(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	err := cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set API key
	err = cfg.SetAPIKey("new-key")
	if err != nil {
		t.Fatalf("SetAPIKey failed: %v", err)
	}

	// Verify it's set in memory
	if cfg.GetAPIKey() != "new-key" {
		t.Errorf("Expected API key 'new-key', got '%s'", cfg.GetAPIKey())
	}

	// Verify it's persisted to viper
	if viper.GetString("api_key") != "new-key" {
		t.Errorf("Expected viper api_key 'new-key', got '%s'", viper.GetString("api_key"))
	}

	// Reset viper and reload from file
	configFile := viper.ConfigFileUsed()
	viper.Reset()
	viper.SetConfigFile(configFile)
	viper.SetConfigType("json")
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	// Verify it's persisted to file
	if viper.GetString("api_key") != "new-key" {
		t.Errorf("Expected persisted api_key 'new-key', got '%s'", viper.GetString("api_key"))
	}
}

func TestSetAPIURL_Persistence(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	err := cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set API URL
	newURL := "https://new.example.com"
	err = cfg.SetAPIURL(newURL)
	if err != nil {
		t.Fatalf("SetAPIURL failed: %v", err)
	}

	// Verify it's set in memory
	if cfg.GetAPIURL() != newURL {
		t.Errorf("Expected API URL '%s', got '%s'", newURL, cfg.GetAPIURL())
	}

	// Verify it's persisted to viper
	if viper.GetString("api_url") != newURL {
		t.Errorf("Expected viper api_url '%s', got '%s'", newURL, viper.GetString("api_url"))
	}
}

func TestGetters_ThreadSafe(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	err := cfg.Initialize("test-key", "https://test.example.com")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	const goroutines = 100
	var wg sync.WaitGroup

	// Concurrent reads
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			key := cfg.GetAPIKey()
			url := cfg.GetAPIURL()
			if key != "test-key" {
				t.Errorf("Expected API key 'test-key', got '%s'", key)
			}
			if url != "https://test.example.com" {
				t.Errorf("Expected API URL 'https://test.example.com', got '%s'", url)
			}
		}()
	}
	wg.Wait()
}

func TestSetters_ThreadSafe(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	err := cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup

	// Concurrent writes
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(index int) {
			defer wg.Done()
			// Each goroutine writes a different value
			// (we don't care which one wins, just that it doesn't crash)
			_ = cfg.SetAPIKey("key-" + string(rune('0'+index)))
		}(i)
	}
	wg.Wait()

	// Final value should be one of the written values
	finalKey := cfg.GetAPIKey()
	if finalKey == "" {
		t.Error("Expected non-empty API key after concurrent writes")
	}
}

func TestValidate_EmptyAPIURL(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	// Don't initialize - fields will be empty

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for empty API URL")
	}
}

func TestValidate_Success(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	err := cfg.Initialize("test-key", "https://test.example.com")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = cfg.Validate()
	if err != nil {
		t.Errorf("Validation should pass, got error: %v", err)
	}
}

// TestConfigFilePermissions_NewFile verifies that new config files are created with 0o600 permissions.
func TestConfigFilePermissions_NewFile(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()
	err := cfg.Initialize("test-key", "https://test.example.com")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Write config file
	err = cfg.SetAPIKey("new-test-key")
	if err != nil {
		t.Fatalf("SetAPIKey failed: %v", err)
	}

	// Verify file permissions
	configPath := viper.ConfigFileUsed()
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}

	actualPerm := info.Mode().Perm()
	expectedPerm := os.FileMode(0o600)

	if actualPerm != expectedPerm {
		t.Errorf("Expected config file permissions %s, got %s", expectedPerm, actualPerm)
	}
}

// TestConfigFilePermissions_ExistingFileWithWrongPermissions verifies that existing config files
// with incorrect permissions are automatically fixed.
func TestConfigFilePermissions_ExistingFileWithWrongPermissions(t *testing.T) {
	defer setupTest(t)()

	// Create config file with wrong permissions (0o644 - world readable)
	configPath := viper.ConfigFileUsed()
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	configContent := []byte(`{"api_key":"test-key","api_url":"https://test.example.com"}`)
	if err := os.WriteFile(configPath, configContent, 0o644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Verify file was created with wrong permissions
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("Test setup failed: expected 0o644, got %s", info.Mode().Perm())
	}

	// Initialize config - should automatically fix permissions
	cfg := GetInstance()
	err = cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Verify permissions were fixed
	info, err = os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file after fix: %v", err)
	}

	actualPerm := info.Mode().Perm()
	expectedPerm := os.FileMode(0o600)

	if actualPerm != expectedPerm {
		t.Errorf("Expected config file permissions %s after auto-fix, got %s", expectedPerm, actualPerm)
	}
}

// TestConfigFilePermissions_CorrectPermissions verifies that files with correct permissions
// are not modified.
func TestConfigFilePermissions_CorrectPermissions(t *testing.T) {
	defer setupTest(t)()

	// Create config file with correct permissions (0o600)
	configPath := viper.ConfigFileUsed()
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	configContent := []byte(`{"api_key":"test-key","api_url":"https://test.example.com"}`)
	if err := os.WriteFile(configPath, configContent, 0o600); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Get initial mod time
	initialInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}
	initialModTime := initialInfo.ModTime()

	// Initialize config - should not modify file
	cfg := GetInstance()
	err = cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Verify permissions are still correct
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}

	actualPerm := info.Mode().Perm()
	expectedPerm := os.FileMode(0o600)

	if actualPerm != expectedPerm {
		t.Errorf("Expected config file permissions %s, got %s", expectedPerm, actualPerm)
	}

	// Verify file was not modified (modtime should be the same)
	if !info.ModTime().Equal(initialModTime) {
		t.Errorf("File was modified when it shouldn't have been")
	}
}

// TestEnsureConfigPermissions_NonExistentFile verifies that ensureConfigPermissions handles
// non-existent files gracefully.
func TestEnsureConfigPermissions_NonExistentFile(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()

	// Call ensureConfigPermissions without initializing viper or creating a file
	err := cfg.ensureConfigPermissions()
	if err != nil {
		t.Errorf("ensureConfigPermissions should not error on non-existent file, got: %v", err)
	}
}

// TestEnsureConfigPermissions_Integration verifies the full lifecycle of config file
// permission handling.
func TestEnsureConfigPermissions_Integration(t *testing.T) {
	defer setupTest(t)()

	cfg := GetInstance()

	// Step 1: Initialize with new config - should create file with correct permissions
	err := cfg.Initialize("initial-key", "https://initial.example.com")
	if err != nil {
		t.Fatalf("Initial initialization failed: %v", err)
	}

	err = cfg.SetAPIKey("step1-key")
	if err != nil {
		t.Fatalf("SetAPIKey failed: %v", err)
	}

	configPath := viper.ConfigFileUsed()
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Errorf("Step 1: Expected permissions 0o600, got %s", info.Mode().Perm())
	}

	// Step 2: Manually change permissions to simulate wrong permissions
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatalf("Failed to change permissions for test: %v", err)
	}

	// Step 3: Reset and re-initialize - should auto-fix permissions
	ResetInstance()
	viper.Reset()
	viper.SetConfigFile(configPath)
	viper.SetConfigType("json")

	cfg = GetInstance()
	err = cfg.Initialize("", "")
	if err != nil {
		t.Fatalf("Re-initialization failed: %v", err)
	}

	// Step 4: Verify permissions were auto-fixed
	info, err = os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file after re-init: %v", err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Errorf("Step 4: Expected permissions 0o600 after auto-fix, got %s", info.Mode().Perm())
	}

	// Step 5: Verify API key was preserved through the permission fix
	if cfg.GetAPIKey() != "step1-key" {
		t.Errorf("API key was not preserved, expected 'step1-key', got '%s'", cfg.GetAPIKey())
	}
}
