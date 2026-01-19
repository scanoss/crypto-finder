// Package version provides version information for the crypto-finder tool.
// This package is separate to avoid circular dependencies between cli and engine packages.
package version

var (
	// ToolName is the name of the tool.
	ToolName = "crypto-finder"
	// Version is the application version (set by build flags).
	Version = "dev"
	// GitCommit is the git commit hash (set by build flags).
	GitCommit = "unknown"
	// BuildDate is the build timestamp (set by build flags).
	BuildDate = "unknown"
)
