package converter

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// Helper function for string matching.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestRelatedCryptoMapper_MapToComponent(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	tests := []struct {
		name           string
		fixtureFile    string
		wantNameSuffix string
		wantErr        bool
		errContains    string
	}{
		{
			name:           "SHA-256 digest",
			fixtureFile:    "digest_sha256.json",
			wantNameSuffix: "@digest",
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := loadFixture(t, tt.fixtureFile)
			if len(report.Findings) == 0 {
				t.Fatal("Fixture has no findings")
			}

			finding := &report.Findings[0]
			if len(finding.CryptographicAssets) == 0 {
				t.Fatal("Finding has no assets")
			}

			asset := &finding.CryptographicAssets[0]

			// Run mapper
			component, err := mapper.MapToComponent(finding, asset)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("MapToComponent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Error should contain %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			// Check name has correct suffix (format is {bomRef}@{materialType})
			if !strings.HasSuffix(component.Name, tt.wantNameSuffix) {
				t.Errorf("Component name = %q, want suffix %q", component.Name, tt.wantNameSuffix)
			}

			// Check BOM ref
			if component.BOMRef == "" {
				t.Error("Component BOMRef is empty")
			}

			// Check description
			if component.Description == "" {
				t.Error("Component Description is empty for digest")
			}

			// Check crypto properties
			if component.CryptoProperties == nil {
				t.Fatal("Component missing CryptoProperties")
			}

			if string(component.CryptoProperties.AssetType) != "related-crypto-material" {
				t.Errorf("AssetType = %q, want %q", component.CryptoProperties.AssetType, "related-crypto-material")
			}

			// Check that basic properties exist (file, line)
			if component.Properties == nil || len(*component.Properties) == 0 {
				t.Fatal("Component missing Properties")
			}

			// Verify basic location properties exist
			props := *component.Properties
			hasFile := false
			hasLine := false

			for _, prop := range props {
				if prop.Name == "scanoss:location:file" {
					hasFile = true
				}
				if prop.Name == "scanoss:location:line" {
					hasLine = true
				}
			}

			if !hasFile {
				t.Error("Missing scanoss:location:file property")
			}
			if !hasLine {
				t.Error("Missing scanoss:location:line property")
			}
		})
	}
}

func TestRelatedCryptoMapper_ValidateRequiredFields(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	tests := []struct {
		name        string
		metadata    map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name: "Complete required fields",
			metadata: map[string]string{
				"assetType":    "related-crypto-material",
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr: false,
		},
		{
			name: "Missing assetType",
			metadata: map[string]string{
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr:     true,
			errContains: "assetType",
		},
		{
			name: "Wrong assetType",
			metadata: map[string]string{
				"assetType":    "algorithm",
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr:     true,
			errContains: "assetType",
		},
		{
			name: "Missing materialType",
			metadata: map[string]string{
				"assetType": "related-crypto-material",
				"algorithm": "SHA-256",
			},
			wantErr:     true,
			errContains: "materialType",
		},
		{
			name: "Empty materialType",
			metadata: map[string]string{
				"assetType":    "related-crypto-material",
				"materialType": "  ",
				"algorithm":    "SHA-256",
			},
			wantErr:     true,
			errContains: "materialType",
		},
		{
			name: "Case-insensitive assetType",
			metadata: map[string]string{
				"assetType":    "RELATED-CRYPTO-MATERIAL",
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: tt.metadata,
			}

			err := mapper.validateRequiredFields(asset)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequiredFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("Error should contain %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestRelatedCryptoMapper_BuildProperties(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	tests := []struct {
		name              string
		filePath          string
		lineNumber        int
		metadata          map[string]string
		ruleSeverity      string
		ruleID            string
		wantPropertiesMin int
	}{
		{
			name:       "Related crypto basic properties",
			filePath:   "src/test.go",
			lineNumber: 10,
			metadata: map[string]string{
				"materialType": "digest",
				"algorithm":    "SHA-256",
				"value":        "abc123def456",
			},
			wantPropertiesMin: 2, // file, line
		},
		{
			name:       "Related crypto with severity and rule ID",
			filePath:   "src/test.go",
			lineNumber: 20,
			metadata: map[string]string{
				"materialType": "digest",
				"algorithm":    "SHA-512",
			},
			ruleSeverity:      "info",
			ruleID:            "test-rule-123",
			wantPropertiesMin: 4, // file, line, severity, ruleid
		},
		{
			name:       "Related crypto with API",
			filePath:   "src/test.go",
			lineNumber: 30,
			metadata: map[string]string{
				"materialType": "key",
				"api":          "crypto.generateKey",
			},
			wantPropertiesMin: 3, // file, line, api
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &entities.Finding{
				FilePath: tt.filePath,
			}
			asset := &entities.CryptographicAsset{
				LineNumber: tt.lineNumber,
				Metadata:   tt.metadata,
				Rule: entities.RuleInfo{
					Severity: tt.ruleSeverity,
					ID:       tt.ruleID,
				},
			}

			props := mapper.buildProperties(finding, asset)

			if len(*props) < tt.wantPropertiesMin {
				t.Errorf("Properties count = %d, want at least %d", len(*props), tt.wantPropertiesMin)
			}

			// Check for required properties
			hasFile := false
			hasLine := false

			for _, prop := range *props {
				switch prop.Name {
				case "scanoss:location:file":
					hasFile = true
					if prop.Value != tt.filePath {
						t.Errorf("File property value = %q, want %q", prop.Value, tt.filePath)
					}
				case "scanoss:location:line":
					hasLine = true
				}
			}

			if !hasFile {
				t.Error("Missing scanoss:location:file property")
			}
			if !hasLine {
				t.Error("Missing scanoss:location:line property")
			}
		})
	}
}
