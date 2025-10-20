package converter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestConverter_Convert(t *testing.T) {
	converter := NewConverter()

	tests := []struct {
		name           string
		fixtureFile    string
		wantComponents int
		wantSkipped    int
		wantErr        bool
	}{
		{
			name:           "AES-256-GCM algorithm",
			fixtureFile:    "algorithm_aes256_gcm.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "RSA-2048 algorithm",
			fixtureFile:    "algorithm_rsa_2048.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "ECDSA P-256 algorithm",
			fixtureFile:    "algorithm_ecdsa_p256.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "SHA-256 hash algorithm",
			fixtureFile:    "algorithm_sha256.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "SHA-256 digest asset",
			fixtureFile:    "digest_sha256.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "Incomplete asset - missing primitive",
			fixtureFile:    "incomplete_missing_primitive.json",
			wantComponents: 0,
			wantSkipped:    1,
			wantErr:        false,
		},
		{
			name:           "Multiple assets in multiple files",
			fixtureFile:    "multi_assets.json",
			wantComponents: 4,
			wantSkipped:    0,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load test fixture
			report := loadFixture(t, tt.fixtureFile)

			// Run conversion
			bom, err := converter.Convert(report)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("Convert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return // Expected error, test passed
			}

			// Validate BOM structure
			if bom == nil {
				t.Fatal("Convert() returned nil BOM")
			}

			// Check BOM format
			if bom.BOMFormat != "CycloneDX" {
				t.Errorf("BOM format = %q, want %q", bom.BOMFormat, "CycloneDX")
			}

			// Check spec version
			if bom.SpecVersion.String() != "1.6" {
				t.Errorf("Spec version = %q, want %q", bom.SpecVersion, "1.6")
			}

			// Check serial number
			if bom.SerialNumber == "" {
				t.Error("Serial number is empty")
			}

			// Check components count
			componentCount := 0
			if bom.Components != nil {
				componentCount = len(*bom.Components)
			}

			if componentCount != tt.wantComponents {
				t.Errorf("Component count = %d, want %d", componentCount, tt.wantComponents)
			}

			// Validate each component has required fields
			if bom.Components != nil {
				for i, component := range *bom.Components {
					if component.BOMRef == "" {
						t.Errorf("Component[%d] missing BOMRef", i)
					}
					if component.Name == "" {
						t.Errorf("Component[%d] missing Name", i)
					}
					if component.CryptoProperties == nil {
						t.Errorf("Component[%d] missing CryptoProperties", i)
					}
				}
			}
		})
	}
}

func TestConverter_ConvertNilReport(t *testing.T) {
	converter := NewConverter()
	_, err := converter.Convert(nil)
	if err == nil {
		t.Error("Convert(nil) should return error")
	}
}

func TestConverter_EmptyReport(t *testing.T) {
	converter := NewConverter()
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{
			Name:    "test",
			Version: "1.0",
		},
		Findings: []entities.Finding{},
	}

	bom, err := converter.Convert(report)
	if err != nil {
		t.Fatalf("Convert() unexpected error: %v", err)
	}

	if bom.Components != nil && len(*bom.Components) != 0 {
		t.Errorf("Empty report should produce 0 components, got %d", len(*bom.Components))
	}
}

func TestDetermineAssetType(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		want     string
	}{
		{
			name:     "Explicit digest type",
			metadata: map[string]string{"assetType": "digest", "algorithm": "SHA-256"},
			want:     "digest",
		},
		{
			name:     "Explicit protocol type",
			metadata: map[string]string{"assetType": "protocol", "name": "TLS"},
			want:     "protocol",
		},
		{
			name:     "Inferred algorithm from primitive",
			metadata: map[string]string{"primitive": "ae", "algorithmName": "AES"},
			want:     "algorithm",
		},
		{
			name:     "Default to algorithm",
			metadata: map[string]string{"algorithmName": "AES"},
			want:     "algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: tt.metadata,
			}
			got := determineAssetType(asset)
			if got != tt.want {
				t.Errorf("determineAssetType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateBOMRef(t *testing.T) {
	tests := []struct {
		name          string
		filePath      string
		lineNumber    int
		algorithmName string
	}{
		{
			name:          "Basic generation",
			filePath:      "src/crypto/test.go",
			lineNumber:    42,
			algorithmName: "AES",
		},
		{
			name:          "Different file and line",
			filePath:      "internal/security/hash.go",
			lineNumber:    100,
			algorithmName: "SHA-256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := generateBOMRef(tt.filePath, tt.lineNumber, tt.algorithmName)

			// Check format
			if ref == "" {
				t.Error("generateBOMRef() returned empty string")
			}

			// Should start with "crypto-asset/"
			expectedPrefix := "crypto-asset/"
			if len(ref) < len(expectedPrefix) || ref[:len(expectedPrefix)] != expectedPrefix {
				t.Errorf("BOM ref should start with %q, got %q", expectedPrefix, ref)
			}

			// Should contain algorithm name
			// Note: BOM ref format is crypto-asset/{algorithm}/{hash}/{line}
			// We just verify it's not empty and has correct structure
			if len(ref) < 20 { // Arbitrary minimum length
				t.Errorf("BOM ref seems too short: %q", ref)
			}
		})
	}

	// Test uniqueness
	ref1 := generateBOMRef("test.go", 10, "AES")
	ref2 := generateBOMRef("test.go", 20, "AES")
	ref3 := generateBOMRef("test.go", 10, "RSA")

	if ref1 == ref2 {
		t.Error("Different line numbers should produce different BOM refs")
	}
	if ref1 == ref3 {
		t.Error("Different algorithms should produce different BOM refs")
	}
}

func TestCountTotalAssets(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  int
	}{
		{
			name:  "Single file with one asset",
			files: []string{"algorithm_aes256_gcm.json"},
			want:  1,
		},
		{
			name:  "Multiple files with multiple assets",
			files: []string{"multi_assets.json"},
			want:  4,
		},
		{
			name:  "File with incomplete asset",
			files: []string{"incomplete_missing_primitive.json"},
			want:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var allFindings []entities.Finding
			for _, file := range tt.files {
				report := loadFixture(t, file)
				allFindings = append(allFindings, report.Findings...)
			}

			report := &entities.InterimReport{Findings: allFindings}
			got := countTotalAssets(report)

			if got != tt.want {
				t.Errorf("countTotalAssets() = %d, want %d", got, tt.want)
			}
		})
	}
}

// Helper function to load test fixtures.
func loadFixture(t *testing.T, filename string) *entities.InterimReport {
	t.Helper()

	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read fixture %q: %v", filename, err)
	}

	var report entities.InterimReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Failed to parse fixture %q: %v", filename, err)
	}

	return &report
}
