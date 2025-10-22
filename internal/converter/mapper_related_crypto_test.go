package converter

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestDigestMapper_MapToComponent(t *testing.T) {
	mapper := NewDigestMapper()

	tests := []struct {
		name        string
		fixtureFile string
		wantName    string
		wantErr     bool
		errContains string
	}{
		{
			name:        "SHA-256 digest",
			fixtureFile: "digest_sha256.json",
			wantName:    "SHA-256-digest",
			wantErr:     false,
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

			// Validate component
			if component == nil {
				t.Fatal("MapToComponent() returned nil component")
			}

			// Check name
			if component.Name != tt.wantName {
				t.Errorf("Component name = %q, want %q", component.Name, tt.wantName)
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

			// Check properties for digest-specific fields
			if component.Properties == nil || len(*component.Properties) == 0 {
				t.Fatal("Component missing Properties")
			}

			// Verify digest-specific properties exist
			props := *component.Properties
			hasDigestAlgorithm := false
			hasDigestValue := false

			for _, prop := range props {
				if prop.Name == "scanoss:digest:algorithm" {
					hasDigestAlgorithm = true
				}
				if prop.Name == "scanoss:digest:value" {
					hasDigestValue = true
				}
			}

			if !hasDigestAlgorithm {
				t.Error("Missing scanoss:digest:algorithm property")
			}
			if !hasDigestValue {
				t.Error("Missing scanoss:digest:value property")
			}
		})
	}
}

func TestDigestMapper_ValidateRequiredFields(t *testing.T) {
	mapper := NewDigestMapper()

	tests := []struct {
		name        string
		metadata    map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name: "Complete required fields",
			metadata: map[string]string{
				"assetType": "digest",
				"algorithm": "SHA-256",
			},
			wantErr: false,
		},
		{
			name: "Missing assetType",
			metadata: map[string]string{
				"algorithm": "SHA-256",
			},
			wantErr:     true,
			errContains: "assetType",
		},
		{
			name: "Wrong assetType",
			metadata: map[string]string{
				"assetType": "algorithm",
				"algorithm": "SHA-256",
			},
			wantErr:     true,
			errContains: "assetType",
		},
		{
			name: "Missing algorithm",
			metadata: map[string]string{
				"assetType": "digest",
			},
			wantErr:     true,
			errContains: "algorithm",
		},
		{
			name: "Empty algorithm",
			metadata: map[string]string{
				"assetType": "digest",
				"algorithm": "  ",
			},
			wantErr:     true,
			errContains: "algorithm",
		},
		{
			name: "Case-insensitive assetType",
			metadata: map[string]string{
				"assetType": "DIGEST",
				"algorithm": "SHA-256",
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

func TestDigestMapper_BuildProperties(t *testing.T) {
	mapper := NewDigestMapper()

	tests := []struct {
		name              string
		filePath          string
		lineNumber        int
		metadata          map[string]string
		wantPropertiesMin int
		wantDigestValue   bool
	}{
		{
			name:       "Digest with value",
			filePath:   "src/test.go",
			lineNumber: 10,
			metadata: map[string]string{
				"algorithm": "SHA-256",
				"value":     "abc123def456",
			},
			wantPropertiesMin: 5, // file, line, asset:type, algorithm, value
			wantDigestValue:   true,
		},
		{
			name:       "Digest without value",
			filePath:   "src/test.go",
			lineNumber: 20,
			metadata: map[string]string{
				"algorithm": "SHA-512",
			},
			wantPropertiesMin: 4, // file, line, asset:type, algorithm (no value)
			wantDigestValue:   false,
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
			}

			props := mapper.buildProperties(finding, asset)

			if props == nil {
				t.Fatal("buildProperties() returned nil")
			}

			if len(*props) < tt.wantPropertiesMin {
				t.Errorf("Properties count = %d, want at least %d", len(*props), tt.wantPropertiesMin)
			}

			// Check for required properties
			hasFile := false
			hasLine := false
			hasAssetType := false
			hasAlgorithm := false
			hasValue := false

			for _, prop := range *props {
				switch prop.Name {
				case "scanoss:location:file":
					hasFile = true
					if prop.Value != tt.filePath {
						t.Errorf("File property value = %q, want %q", prop.Value, tt.filePath)
					}
				case "scanoss:location:line":
					hasLine = true
				case "scanoss:asset:type":
					hasAssetType = true
					if prop.Value != "digest" {
						t.Errorf("Asset type property value = %q, want %q", prop.Value, "digest")
					}
				case "scanoss:digest:algorithm":
					hasAlgorithm = true
				case "scanoss:digest:value":
					hasValue = true
				}
			}

			if !hasFile {
				t.Error("Missing scanoss:location:file property")
			}
			if !hasLine {
				t.Error("Missing scanoss:location:line property")
			}
			if !hasAssetType {
				t.Error("Missing scanoss:asset:type property")
			}
			if !hasAlgorithm {
				t.Error("Missing scanoss:digest:algorithm property")
			}
			if tt.wantDigestValue && !hasValue {
				t.Error("Expected scanoss:digest:value property but not found")
			}
			if !tt.wantDigestValue && hasValue {
				t.Error("Unexpected scanoss:digest:value property found")
			}
		})
	}
}
