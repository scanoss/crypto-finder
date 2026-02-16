package scan

import (
	"os"
	"path/filepath"
)

const (
	ecosystemGo     = "go"
	ecosystemJava   = "java"
	ecosystemRust   = "rust"
	ecosystemPython = "python"
)

// DetectEcosystem checks the target directory for known manifest files
// and returns the corresponding ecosystem name ("go", "python", "java", "rust").
// Returns empty string if no ecosystem is detected.
func DetectEcosystem(target string) string {
	// Check for Go
	if _, err := os.Stat(filepath.Join(target, "go.mod")); err == nil {
		return ecosystemGo
	}
	// Check for Java (Maven)
	if _, err := os.Stat(filepath.Join(target, "pom.xml")); err == nil {
		return ecosystemJava
	}
	// Check for Rust (Cargo)
	if _, err := os.Stat(filepath.Join(target, "Cargo.toml")); err == nil {
		return ecosystemRust
	}
	// Check for Python (in priority order)
	for _, manifest := range []string{"pyproject.toml", "requirements.txt", "Pipfile", "setup.py"} {
		if _, err := os.Stat(filepath.Join(target, manifest)); err == nil {
			return ecosystemPython
		}
	}
	return ""
}
