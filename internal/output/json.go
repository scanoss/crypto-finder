// Package output handles formatting and writing scan results to various output formats
// including JSON, SARIF, and HTML.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// JSONWriter implements the Writer interface for JSON output format.
// It produces pretty-printed JSON with 2-space indentation.
type JSONWriter struct {
	// PrettyPrint enables indented formatting. Default: true
	PrettyPrint bool

	// Indent specifies the indentation string. Default: "  " (2 spaces)
	Indent string
}

// NewJSONWriter creates a new JSON writer with default settings.
func NewJSONWriter() *JSONWriter {
	return &JSONWriter{
		PrettyPrint: true,
		Indent:      "  ", // 2 spaces
	}
}

// NewCompactJSONWriter creates a new JSON writer without pretty-printing.
func NewCompactJSONWriter() *JSONWriter {
	return &JSONWriter{
		PrettyPrint: false,
	}
}

// Write writes the interim report to a JSON file.
//
// The file is created with permissions 0644 (rw-r--r--).
// If the file already exists, it will be overwritten.
// If the parent directory doesn't exist, an error is returned.
func (w *JSONWriter) Write(report *entities.InterimReport, destination string) error {
	// Validate report
	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}

	// Validate destination path
	if destination == "" {
		return fmt.Errorf("destination path cannot be empty")
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("failed to resolve destination path: %w", err)
	}

	// Check parent directory exists
	parentDir := filepath.Dir(absPath)
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		return fmt.Errorf("parent directory does not exist: %s", parentDir)
	}

	// Marshal to JSON
	var data []byte
	if w.PrettyPrint {
		data, err = json.MarshalIndent(report, "", w.Indent)
	} else {
		data, err = json.Marshal(report)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	// Write to file
	// 0644 = rw-r--r-- (owner can read/write, others can read)
	if err := os.WriteFile(absPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}
