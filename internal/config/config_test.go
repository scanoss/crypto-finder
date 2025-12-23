package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

// setupTest prepares a clean test environment
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
	if len(finalKey) == 0 {
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
