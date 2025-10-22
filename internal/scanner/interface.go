// Package scanner provides the core abstraction for cryptographic scanner implementations.
// It defines the Scanner interface that all scanner adapters (Semgrep, OpenGrep, CBOM Toolkit)
// must implement, along with configuration and metadata types.
package scanner

import (
	"context"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// Scanner defines the contract that all scanner adapters (Semgrep, OpenGrep, CBOM Toolkit) must implement,
// providing a unified interface for executing different scanning tools.
//
// Each scanner implementation is responsible for:
//   - Validating the scanner executable is available and properly configured
//   - Executing the scanner against target paths with specified rules
//   - Transforming scanner-specific output into the standardized interim format
//
// Example usage:
//
//	scanner := semgrep.NewSemgrepScanner()
//	config := scanner.Config{
//	    ExecutablePath: "/usr/local/bin/semgrep",
//	    Timeout:        10 * time.Minute,
//	}
//	if err := scanner.Initialize(config); err != nil {
//	    log.Fatal(err)
//	}
//	report, err := scanner.Scan(ctx, "/path/to/code", []string{"./rules"})
type Scanner interface {
	// Initialize validates the scanner is available and properly configured.
	// This method should be called once before any scanning operations.
	//
	// It verifies:
	//   - The scanner executable exists and is executable
	//   - Required dependencies are available
	//   - Configuration parameters are valid
	//
	// Returns an error if initialization fails.
	Initialize(config Config) error

	// Scan executes the scanner against the target with given rule paths.
	// Returns an interim format report containing all findings.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - target: Path to the directory or file to scan
	//   - rulePaths: Paths to rule files or directories containing rules
	//   - toolInfo: Information about the crypto-finder tool (name and version)
	//
	// The scan results are transformed into the standardized schema.InterimReport format,
	// which includes cryptographic assets, API surface information, and metadata.
	//
	// Returns an error if the scan fails or if the scanner process encounters an error.
	Scan(ctx context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error)

	// GetInfo returns metadata about this scanner implementation.
	// This includes the scanner's name, version, and description.
	//
	// This method can be called before Initialize() to query scanner capabilities.
	GetInfo() Info
}

// Config holds the configuration parameters for initializing a scanner.
// Each scanner adapter receives this configuration during initialization.
type Config struct {
	// ExecutablePath is the absolute path to the scanner executable.
	// If empty, the scanner will attempt to find the executable in PATH.
	ExecutablePath string

	// Timeout specifies the maximum duration for a scan operation.
	// If zero, a default timeout of 10 minutes is used.
	// Use context.WithTimeout for more granular control per scan.
	Timeout time.Duration

	// WorkDir is the working directory for the scanner process.
	// If empty, the current working directory is used.
	WorkDir string

	// Env contains environment variables to set for the scanner process.
	// These are added to the existing environment, not replacing it.
	// Example: map[string]string{"SEMGREP_TIMEOUT": "600"}
	Env map[string]string

	// ExtraArgs contains additional command-line arguments to pass to the scanner.
	// These are appended to the scanner's default arguments.
	// Example: []string{"--verbose", "--max-memory=4096"}
	ExtraArgs []string

	// SkipPatterns contains gitignore-style patterns for files/directories to exclude.
	// These patterns are passed to the scanner's exclude mechanism (e.g., --exclude for Semgrep).
	// Example: []string{"node_modules/", "*.min.js", "test/"}
	SkipPatterns []string
}

// Info contains metadata about a scanner implementation.
// This information is used for reporting, debugging, and determining scanner capabilities.
type Info struct {
	// Name is the unique identifier for the scanner.
	// Examples: "semgrep", "opengrep", "cbom-toolkit"
	Name string

	// Version is the version of the scanner implementation or executable.
	// This should match the actual version of the underlying tool.
	// Example: "1.45.0"
	Version string

	// Description provides a brief explanation of what the scanner detects.
	// Example: "Static analysis tool for detecting cryptographic algorithm usage"
	Description string
}
