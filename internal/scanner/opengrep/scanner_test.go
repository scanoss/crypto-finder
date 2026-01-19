package opengrep

import (
	"context"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

func TestNewScanner(t *testing.T) {
	s := NewScanner()

	if s.executablePath != "opengrep" {
		t.Errorf("Expected default executable path 'opengrep', got '%s'", s.executablePath)
	}

	if s.timeout != 10*time.Minute {
		t.Errorf("Expected default timeout 10 minutes, got %v", s.timeout)
	}
}

func TestGetInfo(t *testing.T) {
	s := NewScanner()
	s.version = "1.12.1"

	info := s.GetInfo()

	if info.Name != ScannerName {
		t.Errorf("Expected scanner name '%s', got '%s'", ScannerName, info.Name)
	}

	if info.Version != "1.12.1" {
		t.Errorf("Expected version '1.12.1', got '%s'", info.Version)
	}

	if info.Description == "" {
		t.Error("Expected non-empty description")
	}
}

func TestBuildCommand(t *testing.T) {
	s := NewScanner()
	s.skipPatterns = []string{"*.test", "vendor/*"}
	s.extraArgs = []string{"--debug"}

	rulePaths := []string{"/rules/crypto.yaml", "/rules/hash.yaml"}
	target := "/tmp/target"

	args := s.buildCommand(target, rulePaths)

	// Verify required arguments
	expectedArgs := map[string]bool{
		"--json":             false,
		"--no-git-ignore":    false,
		"--taint-intrafile":  false,
		"--config":           false,
		"/rules/crypto.yaml": false,
		"/rules/hash.yaml":   false,
		"--exclude":          false,
		"*.test":             false,
		"vendor/*":           false,
		"--debug":            false,
		"/tmp/target":        false,
	}

	for _, arg := range args {
		if _, ok := expectedArgs[arg]; ok {
			expectedArgs[arg] = true
		}
	}

	// Check that all expected arguments were found
	for arg, found := range expectedArgs {
		if !found {
			t.Errorf("Expected argument '%s' not found in command", arg)
		}
	}

	// Verify --taint-intrafile is included (default for OpenGrep)
	hasTaintIntrafile := false
	for _, arg := range args {
		if arg == "--taint-intrafile" {
			hasTaintIntrafile = true
			break
		}
	}
	if !hasTaintIntrafile {
		t.Error("Expected --taint-intrafile argument to be included")
	}

	// Verify target is the last argument
	if args[len(args)-1] != target {
		t.Errorf("Expected target '%s' to be last argument, got '%s'", target, args[len(args)-1])
	}
}

func TestInitialize_WithConfig(t *testing.T) {
	// Mock the exec functions to avoid needing real opengrep
	originalLookPath := lookPath
	originalCommandOutput := commandOutput
	defer func() {
		lookPath = originalLookPath
		commandOutput = originalCommandOutput
	}()

	// Mock exec.LookPath to return success
	lookPath = func(_ string) (string, error) {
		return "/usr/local/bin/opengrep", nil
	}

	// Mock command output to return a valid version
	commandOutput = func(_ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--version" {
			return []byte("1.12.1"), nil
		}
		return nil, nil
	}

	s := NewScanner()

	config := scanner.Config{
		Timeout:      5 * time.Minute,
		WorkDir:      "/tmp/work",
		Env:          map[string]string{"FOO": "bar"},
		ExtraArgs:    []string{"--verbose"},
		SkipPatterns: []string{"*.test"},
	}

	err := s.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Verify configuration was applied
	if s.timeout != 5*time.Minute {
		t.Errorf("Expected timeout 5 minutes, got %v", s.timeout)
	}

	if s.workDir != "/tmp/work" {
		t.Errorf("Expected workDir '/tmp/work', got '%s'", s.workDir)
	}

	if s.env["FOO"] != "bar" {
		t.Errorf("Expected env FOO='bar', got '%s'", s.env["FOO"])
	}

	if len(s.extraArgs) != 1 || s.extraArgs[0] != "--verbose" {
		t.Errorf("Expected extraArgs ['--verbose'], got %v", s.extraArgs)
	}

	if len(s.skipPatterns) != 1 || s.skipPatterns[0] != "*.test" {
		t.Errorf("Expected skipPatterns ['*.test'], got %v", s.skipPatterns)
	}

	// Verify version was detected
	if s.version != "1.12.1" {
		t.Errorf("Expected version '1.12.1', got '%s'", s.version)
	}

	// Verify executable path was set
	if s.executablePath != "/usr/local/bin/opengrep" {
		t.Errorf("Expected executablePath '/usr/local/bin/opengrep', got '%s'", s.executablePath)
	}
}

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		shouldError bool
	}{
		{
			name:        "Exact minimum version",
			version:     "1.12.1",
			shouldError: false,
		},
		{
			name:        "Higher version",
			version:     "1.13.0",
			shouldError: false,
		},
		{
			name:        "Much higher version",
			version:     "2.0.0",
			shouldError: false,
		},
		{
			name:        "Below minimum - patch",
			version:     "1.12.0",
			shouldError: true,
		},
		{
			name:        "Below minimum - minor",
			version:     "1.11.5",
			shouldError: true,
		},
		{
			name:        "Below minimum - major",
			version:     "0.99.0",
			shouldError: true,
		},
		{
			name:        "Unknown version",
			version:     "unknown",
			shouldError: true, // Should error when version cannot be determined
		},
		{
			name:        "Empty version",
			version:     "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner()
			s.version = tt.version

			err := s.validateVersion()

			if tt.shouldError && err == nil {
				t.Errorf("Expected error for version %s, got nil", tt.version)
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error for version %s, got: %v", tt.version, err)
			}
		})
	}
}

func TestMapToEnvSlice(t *testing.T) {
	envMap := map[string]string{
		"PATH":   "/usr/bin",
		"HOME":   "/home/user",
		"CUSTOM": "value",
	}

	envSlice := mapToEnvSlice(envMap)

	if len(envSlice) != 3 {
		t.Errorf("Expected 3 environment variables, got %d", len(envSlice))
	}

	// Convert slice back to map for easier verification
	resultMap := make(map[string]string)
	for _, env := range envSlice {
		// Split on first '=' only
		parts := splitOnce(env, "=")
		if len(parts) == 2 {
			resultMap[parts[0]] = parts[1]
		}
	}

	for key, expectedValue := range envMap {
		if actualValue, ok := resultMap[key]; !ok {
			t.Errorf("Expected key '%s' not found in result", key)
		} else if actualValue != expectedValue {
			t.Errorf("For key '%s', expected value '%s', got '%s'", key, expectedValue, actualValue)
		}
	}
}

func TestScan_NoRulePaths(t *testing.T) {
	s := NewScanner()
	ctx := context.Background()

	_, err := s.Scan(ctx, "/tmp/target", []string{}, mockToolInfo())

	if err == nil {
		t.Error("Expected error when no rule paths provided")
	}

	if err.Error() != "no rule paths provided" {
		t.Errorf("Expected 'no rule paths provided' error, got: %v", err)
	}
}

// Helper function to split string on first occurrence of separator.
func splitOnce(s, sep string) []string {
	parts := make([]string, 0, 2)
	if idx := findFirst(s, sep); idx >= 0 {
		parts = append(parts, s[:idx], s[idx+len(sep):])
	} else {
		parts = append(parts, s)
	}
	return parts
}

// Helper function to find first occurrence of substring.
func findFirst(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// mockToolInfo creates a mock ToolInfo for testing.
func mockToolInfo() entities.ToolInfo {
	return entities.ToolInfo{
		Name:    "crypto-finder",
		Version: "test",
	}
}
