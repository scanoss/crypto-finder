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

package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func createTestReport() *entities.InterimReport {
	return &entities.InterimReport{
		Version: "1.0",
		Tool: entities.ToolInfo{
			Name:    "crypto-finder",
			Version: "1.0.0",
		},
		Findings: []entities.Finding{
			{
				FilePath:     "test.go",
				Language:     "go",
				TimestampUTC: time.Now().UTC().Format(time.RFC3339),
				CryptographicAssets: []entities.CryptographicAsset{
					{
						MatchType: "semgrep",
						StartLine: 10,
						EndLine:   10,
						Match:     "AES.encrypt",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes",
							Message:  "AES usage detected",
							Severity: "INFO",
						}},
						Status: "pending",
						Metadata: map[string]string{
							"assetType": "algorithm",
							"algorithm": "AES",
							"mode":      "CBC",
							"keyLength": "256",
						},
					},
				},
			},
		},
	}
}

func TestJSONWriter_WriteToFile(t *testing.T) {
	t.Parallel()

	report := createTestReport()
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "output.json")

	writer := &JSONWriter{}
	err := writer.Write(report, outputFile)
	if err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}

	// Verify content is valid JSON
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var parsedReport entities.InterimReport
	if err := json.Unmarshal(data, &parsedReport); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify basic structure
	if parsedReport.Version != report.Version {
		t.Errorf("Version mismatch: expected %s, got %s", report.Version, parsedReport.Version)
	}

	if len(parsedReport.Findings) != len(report.Findings) {
		t.Errorf("Findings count mismatch: expected %d, got %d", len(report.Findings), len(parsedReport.Findings))
	}
}

func TestJSONWriter_WriteToStdout(t *testing.T) {
	t.Parallel()

	report := createTestReport()

	writer := &JSONWriter{}
	// Write to stdout (empty string)
	err := writer.Write(report, "")
	if err != nil {
		t.Fatalf("Write() to stdout failed: %v", err)
	}
}

func TestJSONWriter_WriteNilReport(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "output.json")

	writer := &JSONWriter{}
	err := writer.Write(nil, outputFile)

	if err == nil {
		t.Fatal("Expected error for nil report")
	}
}

func TestJSONWriter_CompactFormat(t *testing.T) {
	t.Parallel()

	report := createTestReport()
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "compact.json")

	writer := NewCompactJSONWriter()
	err := writer.Write(report, outputFile)
	if err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Read and verify it's compact (no extra whitespace)
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	// Compact JSON should not have newlines within the structure
	// (only the final newline added by Write())
	dataStr := string(data)
	// Remove the trailing newline for this check
	dataStr = dataStr[:len(dataStr)-1]

	// Count newlines - compact JSON shouldn't have any internal newlines
	newlineCount := 0
	for _, ch := range dataStr {
		if ch == '\n' {
			newlineCount++
		}
	}

	if newlineCount > 0 {
		t.Errorf("Expected compact JSON with no internal newlines, found %d newlines", newlineCount)
	}
}

func TestJSONWriter_ParentDirNotExist(t *testing.T) {
	t.Parallel()

	report := createTestReport()
	// Use a path with non-existent parent directory
	outputFile := "/nonexistent/directory/output.json"

	writer := NewJSONWriter()
	err := writer.Write(report, outputFile)

	if err == nil {
		t.Fatal("Expected error for non-existent parent directory")
	}

	if !os.IsNotExist(err) && err.Error() == "" {
		t.Errorf("Expected error mentioning parent directory, got: %v", err)
	}
}

func TestJSONWriter_WriteFileError(t *testing.T) {
	t.Parallel()

	report := createTestReport()
	tempDir := t.TempDir()
	// Create a subdirectory and use it as the output path (not a file inside it)
	dirPath := filepath.Join(tempDir, "outputdir")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	writer := NewJSONWriter()
	// Attempting to write to a directory path will fail deterministically
	err := writer.Write(report, dirPath)
	if err == nil {
		t.Fatal("Expected error when writing to directory path")
	}
}

func TestCycloneDXWriter_ParentDirNotExist(t *testing.T) {
	t.Parallel()

	report := createTestReport()
	outputFile := "/nonexistent/directory/output.cdx.json"

	writer := NewCycloneDXWriter()
	err := writer.Write(report, outputFile)

	if err == nil {
		t.Fatal("Expected error for non-existent parent directory")
	}
}

func TestCycloneDXWriter_WriteFileError(t *testing.T) {
	t.Parallel()

	report := createTestReport()
	tempDir := t.TempDir()
	// Create a subdirectory and use it as the output path (not a file inside it)
	dirPath := filepath.Join(tempDir, "outputdir")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	writer := NewCycloneDXWriter()
	// Attempting to write to a directory path will fail deterministically
	err := writer.Write(report, dirPath)
	if err == nil {
		t.Fatal("Expected error when writing to directory path")
	}
}

func TestCycloneDXWriter_WriteToFile(t *testing.T) {
	t.Parallel()

	report := createTestReport()
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "output.cdx.json")

	writer := NewCycloneDXWriter()
	err := writer.Write(report, outputFile)
	if err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}

	// Verify content is valid JSON
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var cdxBom map[string]interface{}
	if err := json.Unmarshal(data, &cdxBom); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify basic CycloneDX structure
	if cdxBom["bomFormat"] != "CycloneDX" {
		t.Error("Missing or incorrect bomFormat field")
	}

	if cdxBom["specVersion"] == nil {
		t.Error("Missing specVersion field")
	}

	if cdxBom["components"] == nil {
		t.Error("Missing components field")
	}
}

func TestCycloneDXWriter_WriteToStdout(t *testing.T) {
	t.Parallel()

	report := createTestReport()

	writer := NewCycloneDXWriter()
	// Write to stdout (empty string)
	err := writer.Write(report, "")
	if err != nil {
		t.Fatalf("Write() to stdout failed: %v", err)
	}
}

func TestCycloneDXWriter_WriteNilReport(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "output.cdx.json")

	writer := NewCycloneDXWriter()
	err := writer.Write(nil, outputFile)

	if err == nil {
		t.Fatal("Expected error for nil report")
	}
}

func TestWriterFactory_GetJSONWriter(t *testing.T) {
	t.Parallel()

	factory := NewWriterFactory()
	writer, err := factory.GetWriter("json")
	if err != nil {
		t.Fatalf("GetWriter(\"json\") failed: %v", err)
	}

	if writer == nil {
		t.Fatal("GetWriter(\"json\") returned nil")
	}

	// Verify it's a JSONWriter
	if _, ok := writer.(*JSONWriter); !ok {
		t.Error("Expected JSONWriter type")
	}
}

func TestWriterFactory_GetCycloneDXWriter(t *testing.T) {
	t.Parallel()

	factory := NewWriterFactory()
	writer, err := factory.GetWriter("cyclonedx")
	if err != nil {
		t.Fatalf("GetWriter(\"cyclonedx\") failed: %v", err)
	}

	if writer == nil {
		t.Fatal("GetWriter(\"cyclonedx\") returned nil")
	}

	// Verify it's a CycloneDXWriter
	if _, ok := writer.(*CycloneDXWriter); !ok {
		t.Error("Expected CycloneDXWriter type")
	}
}

func TestWriterFactory_GetUnsupportedFormat(t *testing.T) {
	t.Parallel()

	factory := NewWriterFactory()
	_, err := factory.GetWriter("unsupported")

	if err == nil {
		t.Fatal("Expected error for unsupported format")
	}
}

func TestJSONWriter_EmptyFindings(t *testing.T) {
	t.Parallel()

	report := &entities.InterimReport{
		Version: "1.0",
		Tool: entities.ToolInfo{
			Name:    "crypto-finder",
			Version: "1.0.0",
		},
		Findings: []entities.Finding{},
	}

	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "empty.json")

	writer := &JSONWriter{}
	err := writer.Write(report, outputFile)
	if err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var parsedReport entities.InterimReport
	if err := json.Unmarshal(data, &parsedReport); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if len(parsedReport.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(parsedReport.Findings))
	}
}

func TestCycloneDXWriter_EmptyFindings(t *testing.T) {
	t.Parallel()

	report := &entities.InterimReport{
		Version: "1.0",
		Tool: entities.ToolInfo{
			Name:    "crypto-finder",
			Version: "1.0.0",
		},
		Findings: []entities.Finding{},
	}

	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "empty.cdx.json")

	writer := NewCycloneDXWriter()
	err := writer.Write(report, outputFile)
	if err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify file was created with valid structure
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var cdxBom map[string]interface{}
	if err := json.Unmarshal(data, &cdxBom); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Should have valid structure even with no findings
	if cdxBom["bomFormat"] != "CycloneDX" {
		t.Error("Missing or incorrect bomFormat field")
	}
}
