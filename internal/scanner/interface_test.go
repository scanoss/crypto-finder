package scanner_test

import (
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config scanner.Config
		valid  bool
	}{
		{
			name: "valid config with all fields",
			config: scanner.Config{
				ExecutablePath: "/usr/bin/semgrep",
				Timeout:        10 * time.Minute,
				WorkDir:        "/tmp",
				Env:            map[string]string{"KEY": "value"},
				ExtraArgs:      []string{"--verbose"},
			},
			valid: true,
		},
		{
			name: "valid config with minimal fields",
			config: scanner.Config{
				ExecutablePath: "/usr/bin/semgrep",
			},
			valid: true,
		},
		{
			name: "valid config with empty path (will search PATH)",
			config: scanner.Config{
				Timeout: 5 * time.Minute,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify config can be created and fields are accessible
			if tt.config.ExecutablePath == "" && tt.name != "valid config with empty path (will search PATH)" {
				t.Errorf("ExecutablePath should not be empty for %s", tt.name)
			}

			// Verify Env map is accessible
			if tt.config.Env != nil {
				if _, ok := tt.config.Env["KEY"]; !ok && len(tt.config.Env) > 0 {
					t.Errorf("Env map should be accessible")
				}
			}

			// Verify ExtraArgs slice is accessible
			if tt.config.ExtraArgs != nil && len(tt.config.ExtraArgs) == 0 {
				t.Log("ExtraArgs is empty but initialized")
			}
		})
	}
}

func TestInfo_Fields(t *testing.T) {
	info := scanner.Info{
		Name:        "semgrep",
		Version:     "1.45.0",
		Description: "Static analysis tool",
	}

	if info.Name != "semgrep" {
		t.Errorf("Expected Name to be 'semgrep', got '%s'", info.Name)
	}

	if info.Version != "1.45.0" {
		t.Errorf("Expected Version to be '1.45.0', got '%s'", info.Version)
	}

	if info.Description != "Static analysis tool" {
		t.Errorf("Expected Description to be 'Static analysis tool', got '%s'", info.Description)
	}
}

func TestInfo_EmptyFields(t *testing.T) {
	// Test that Info can be created with empty fields
	info := scanner.Info{}

	if info.Name != "" {
		t.Errorf("Expected empty Name, got '%s'", info.Name)
	}

	if info.Version != "" {
		t.Errorf("Expected empty Version, got '%s'", info.Version)
	}

	if info.Description != "" {
		t.Errorf("Expected empty Description, got '%s'", info.Description)
	}
}

func TestConfig_TimeoutZeroValue(t *testing.T) {
	config := scanner.Config{
		Timeout: 0, // Zero value - should use default
	}

	if config.Timeout != 0 {
		t.Errorf("Expected Timeout to be 0 (zero value), got %v", config.Timeout)
	}
}

func TestConfig_EnvMapNil(t *testing.T) {
	config := scanner.Config{
		Env: nil,
	}

	if config.Env != nil {
		t.Errorf("Expected Env to be nil, got %v", config.Env)
	}
}

func TestConfig_ExtraArgsNil(t *testing.T) {
	config := scanner.Config{
		ExtraArgs: nil,
	}

	if config.ExtraArgs != nil {
		t.Errorf("Expected ExtraArgs to be nil, got %v", config.ExtraArgs)
	}
}

func TestConfig_ExtraArgsMultiple(t *testing.T) {
	args := []string{"--verbose", "--debug", "--max-memory=4096"}
	config := scanner.Config{
		ExtraArgs: args,
	}

	if len(config.ExtraArgs) != 3 {
		t.Errorf("Expected 3 extra args, got %d", len(config.ExtraArgs))
	}

	if config.ExtraArgs[0] != "--verbose" {
		t.Errorf("Expected first arg to be '--verbose', got '%s'", config.ExtraArgs[0])
	}
}

func TestConfig_EnvMapMultiple(t *testing.T) {
	env := map[string]string{
		"KEY1": "value1",
		"KEY2": "value2",
		"KEY3": "value3",
	}
	config := scanner.Config{
		Env: env,
	}

	if len(config.Env) != 3 {
		t.Errorf("Expected 3 env vars, got %d", len(config.Env))
	}

	if config.Env["KEY1"] != "value1" {
		t.Errorf("Expected KEY1 to be 'value1', got '%s'", config.Env["KEY1"])
	}
}
