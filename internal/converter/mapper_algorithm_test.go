package converter

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestAlgorithmMapper_MapToComponent(t *testing.T) {
	mapper := NewAlgorithmMapper()

	tests := []struct {
		name          string
		fixtureFile   string
		wantName      string
		wantPrimitive string
		wantKeySize   string
		wantMode      string
		wantSecLevel  *int
		wantErr       bool
		errContains   string
	}{
		{
			name:          "AES-256-GCM complete",
			fixtureFile:   "algorithm_aes256_gcm.json",
			wantName:      "AES-256-GCM",
			wantPrimitive: "ae",
			wantKeySize:   "256",
			wantMode:      "gcm",
			wantSecLevel:  nil, // ClassicalSecurityLevel not currently calculated by mapper
			wantErr:       false,
		},
		{
			name:          "RSA-2048 public key",
			fixtureFile:   "algorithm_rsa_2048.json",
			wantName:      "RSA-2048",
			wantPrimitive: "pke",
			wantKeySize:   "2048",
			wantMode:      "",
			wantSecLevel:  nil, // ClassicalSecurityLevel not currently calculated by mapper
			wantErr:       false,
		},
		{
			name:          "ECDSA P-256 signature",
			fixtureFile:   "algorithm_ecdsa_p256.json",
			wantName:      "ECDSA-P-256",
			wantPrimitive: "signature",
			wantKeySize:   "P-256",
			wantMode:      "",
			wantSecLevel:  nil, // ClassicalSecurityLevel not currently calculated by mapper
			wantErr:       false,
		},
		{
			name:          "SHA-256 hash",
			fixtureFile:   "algorithm_sha256.json",
			wantName:      "SHA-256", // parameterSetIdentifier not appended (already in name)
			wantPrimitive: "hash",
			wantKeySize:   "256",
			wantMode:      "",
			wantSecLevel:  nil, // ClassicalSecurityLevel not currently calculated by mapper
			wantErr:       false,
		},
		{
			name:        "Missing assetType field",
			fixtureFile: "incomplete_missing_primitive.json",
			wantErr:     true,
			errContains: "missing required field 'assetType'",
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
			component, err := mapper.MapToComponentWithEvidence(asset)

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

			// Check name
			if component.Name != tt.wantName {
				t.Errorf("Component name = %q, want %q", component.Name, tt.wantName)
			}

			// Check BOM ref
			if component.BOMRef == "" {
				t.Error("Component BOMRef is empty")
			}

			// Check crypto properties
			if component.CryptoProperties == nil {
				t.Fatal("Component missing CryptoProperties")
			}

			if string(component.CryptoProperties.AssetType) != "algorithm" {
				t.Errorf("AssetType = %q, want %q", component.CryptoProperties.AssetType, "algorithm")
			}

			algProps := component.CryptoProperties.AlgorithmProperties

			// Check primitive
			if string(algProps.Primitive) != tt.wantPrimitive {
				t.Errorf("Primitive = %q, want %q", algProps.Primitive, tt.wantPrimitive)
			}

			// Check parameter set identifier (key size)
			if algProps.ParameterSetIdentifier != tt.wantKeySize {
				t.Errorf("ParameterSetIdentifier = %q, want %q", algProps.ParameterSetIdentifier, tt.wantKeySize)
			}

			// Check mode
			if tt.wantMode != "" {
				if string(algProps.Mode) != tt.wantMode {
					t.Errorf("Mode = %q, want %q", algProps.Mode, tt.wantMode)
				}
			}

			// Check security level
			if tt.wantSecLevel != nil {
				if algProps.ClassicalSecurityLevel == nil {
					t.Error("ClassicalSecurityLevel is nil, want value")
				} else if *algProps.ClassicalSecurityLevel != *tt.wantSecLevel {
					t.Errorf("ClassicalSecurityLevel = %d, want %d", *algProps.ClassicalSecurityLevel, *tt.wantSecLevel)
				}
			}

			// Note: Properties are no longer set by MapToComponentWithEvidence
			// They are built by the converter's buildEvidence method instead
		})
	}
}

func TestAlgorithmMapper_ValidateRequiredFields(t *testing.T) {
	mapper := NewAlgorithmMapper()

	tests := []struct {
		name        string
		metadata    map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name: "Complete required fields",
			metadata: map[string]string{
				"assetType":          "algorithm",
				"algorithmPrimitive": "ae",
				"algorithmFamily":    "AES",
			},
			wantErr: false,
		},
		{
			name: "Missing algorithmPrimitive",
			metadata: map[string]string{
				"assetType":       "algorithm",
				"algorithmFamily": "AES",
			},
			wantErr:     true,
			errContains: "algorithmPrimitive",
		},
		{
			name: "Missing algorithmFamily",
			metadata: map[string]string{
				"assetType":          "algorithm",
				"algorithmPrimitive": "ae",
			},
			wantErr:     true,
			errContains: "algorithmFamily",
		},
		{
			name: "Empty algorithmPrimitive",
			metadata: map[string]string{
				"assetType":          "algorithm",
				"algorithmPrimitive": "  ",
				"algorithmFamily":    "AES",
			},
			wantErr:     true,
			errContains: "algorithmPrimitive",
		},
		{
			name: "Empty algorithmFamily",
			metadata: map[string]string{
				"assetType":          "algorithm",
				"algorithmPrimitive": "ae",
				"algorithmFamily":    "  ",
			},
			wantErr:     true,
			errContains: "algorithmFamily",
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

func TestAlgorithmMapper_CryptoFunctions(t *testing.T) {
	mapper := NewAlgorithmMapper()

	tests := []struct {
		name              string
		primitive         string
		wantFunctions     []cdx.CryptoFunction
		wantFunctionCount int
	}{
		{
			name:              "Authenticated Encryption",
			primitive:         "ae",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionTag},
			wantFunctionCount: 3,
		},
		{
			name:              "Block Cipher",
			primitive:         "block-cipher",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
			wantFunctionCount: 2,
		},
		{
			name:              "Hash Function",
			primitive:         "hash",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
			wantFunctionCount: 1,
		},
		{
			name:              "Signature Algorithm",
			primitive:         "signature",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
			wantFunctionCount: 2,
		},
		{
			name:              "Key Derivation Function",
			primitive:         "kdf",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive},
			wantFunctionCount: 1,
		},
		{
			name:              "DRBG (Random Generator)",
			primitive:         "drbg",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionGenerate},
			wantFunctionCount: 1,
		},
		{
			name:              "Key Encapsulation Mechanism",
			primitive:         "kem",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate},
			wantFunctionCount: 2,
		},
		{
			name:              "Message Authentication Code",
			primitive:         "mac",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionTag, cdx.CryptoFunctionVerify},
			wantFunctionCount: 2,
		},
		{
			name:              "Public Key Encryption",
			primitive:         "pke",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
			wantFunctionCount: 2,
		},
		{
			name:              "Stream Cipher",
			primitive:         "stream-cipher",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
			wantFunctionCount: 2,
		},
		{
			name:              "Extendable Output Function",
			primitive:         "xof",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
			wantFunctionCount: 1,
		},
		{
			name:              "Key Agreement",
			primitive:         "key-agree",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionKeygen},
			wantFunctionCount: 1,
		},
		{
			name:              "Combiner (combines multiple primitives)",
			primitive:         "combiner",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionOther},
			wantFunctionCount: 1,
		},
		{
			name:              "Other Primitive",
			primitive:         "other",
			wantFunctions:     []cdx.CryptoFunction{cdx.CryptoFunctionOther},
			wantFunctionCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"assetType":          "algorithm",
					"algorithmPrimitive": tt.primitive,
					"algorithmFamily":    "TestAlgorithm",
				},
			}

			component, err := mapper.MapToComponentWithEvidence(asset)
			if err != nil {
				t.Fatalf("MapToComponentWithEvidence() unexpected error: %v", err)
			}

			if component.CryptoProperties == nil {
				t.Fatal("CryptoProperties is nil")
			}

			algProps := component.CryptoProperties.AlgorithmProperties
			if algProps == nil {
				t.Fatal("AlgorithmProperties is nil")
			}

			if algProps.CryptoFunctions == nil {
				t.Fatal("CryptoFunctions is nil")
			}

			functions := *algProps.CryptoFunctions
			if len(functions) != tt.wantFunctionCount {
				t.Errorf("CryptoFunctions count = %d, want %d", len(functions), tt.wantFunctionCount)
			}

			// Check that all expected functions are present
			for _, wantFn := range tt.wantFunctions {
				found := false
				for _, fn := range functions {
					if fn == wantFn {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected function %q not found in %v", wantFn, functions)
				}
			}
		})
	}
}
