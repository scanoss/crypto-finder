package cli

import (
	"testing"
)

func TestScanCommandFlags(t *testing.T) {
	// Reset scannerArgs to empty before each test
	scannerArgs = []string{}

	// Test that the --scanner-args flag is properly registered
	flag := scanCmd.Flags().Lookup("scanner-args")
	if flag == nil {
		t.Fatal("--scanner-args flag is not registered")
	}

	// Verify flag properties
	if flag.Usage != "Pass additional arguments directly to the scanner (repeatable)" {
		t.Errorf("Unexpected flag usage: %s", flag.Usage)
	}

	// Test single scanner arg
	err := scanCmd.Flags().Set("scanner-args", "--verbose")
	if err != nil {
		t.Fatalf("Failed to set scanner-args flag: %v", err)
	}

	if len(scannerArgs) != 1 {
		t.Errorf("Expected 1 scanner arg, got %d", len(scannerArgs))
	}

	if scannerArgs[0] != "--verbose" {
		t.Errorf("Expected scanner arg '--verbose', got '%s'", scannerArgs[0])
	}

	// Test multiple scanner args (repeatable flag)
	scannerArgs = []string{} // Reset
	err = scanCmd.Flags().Set("scanner-args", "--verbose")
	if err != nil {
		t.Fatalf("Failed to set scanner-args flag: %v", err)
	}
	err = scanCmd.Flags().Set("scanner-args", "--debug")
	if err != nil {
		t.Fatalf("Failed to set scanner-args flag: %v", err)
	}

	if len(scannerArgs) != 2 {
		t.Errorf("Expected 2 scanner args, got %d", len(scannerArgs))
	}

	expectedArgs := map[string]bool{
		"--verbose": false,
		"--debug":   false,
	}

	for _, arg := range scannerArgs {
		if _, ok := expectedArgs[arg]; ok {
			expectedArgs[arg] = true
		}
	}

	for arg, found := range expectedArgs {
		if !found {
			t.Errorf("Expected scanner arg '%s' not found", arg)
		}
	}
}

func TestScanCommandFlagsExist(t *testing.T) {
	// Verify all expected flags are registered
	expectedFlags := map[string]string{
		"rules":            "Rule file path (repeatable)",
		"rules-dir":        "Rule directory path (repeatable)",
		"scanner":          "Scanner to use (default: opengrep)",
		"format":           "Output format: json, cyclonedx (default: json)",
		"output":           "Output file path (default: stdout)",
		"languages":        "Override language detection (comma-separated)",
		"fail-on-findings": "Exit with error if findings detected",
		"timeout":          "Scan timeout (e.g., 10m, 1h)",
		"scanner-args":     "Pass additional arguments directly to the scanner (repeatable)",
	}

	for flagName, expectedUsage := range expectedFlags {
		flag := scanCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag --%s to be registered", flagName)
			continue
		}

		if flag.Usage != expectedUsage {
			t.Errorf("Flag --%s has unexpected usage.\nExpected: %s\nGot: %s",
				flagName, expectedUsage, flag.Usage)
		}
	}
}
