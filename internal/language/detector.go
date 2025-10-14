// Package language provides automatic programming language detection for source code.
// It uses go-enry to accurately identify languages in target directories.
package language

// Detector analyzes source code to automatically detect programming languages
// present in the target directory.
type Detector interface {
	// Detect analyzes the target directory and returns detected languages.
	// Returns language names in lowercase (e.g., "java", "python", "go").
	//
	// The detector recursively scans all files in the target path,
	// automatically excluding common non-source directories like
	// vendor/, node_modules/, .git/, etc.
	//
	// Parameters:
	//   - targetPath: Absolute or relative path to the directory to analyze
	//
	// Returns:
	//   - []string: Slice of detected language names (lowercase, deduplicated)
	//   - error: Error if path doesn't exist or cannot be read
	Detect(targetPath string) ([]string, error)
}

// DefaultExcludedDirs lists common directories that should be excluded
// from language detection to avoid scanning dependencies and build artifacts.
var DefaultExcludedDirs = []string{
	"vendor",
	"node_modules",
	".git",
	"venv",
	"__pycache__",
	".venv",
	"env",
	"build",
	"dist",
	"target",
	".idea",
	".vscode",
}
