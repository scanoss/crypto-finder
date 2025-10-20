package converter

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestValidator_Validate(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		fixtureFile string
		wantErr     bool
		errContains string
	}{
		{
			name:        "Valid AES-256-GCM BOM",
			fixtureFile: "algorithm_aes256_gcm.json",
			wantErr:     false,
		},
		{
			name:        "Valid RSA-2048 BOM",
			fixtureFile: "algorithm_rsa_2048.json",
			wantErr:     false,
		},
		{
			name:        "Valid ECDSA BOM",
			fixtureFile: "algorithm_ecdsa_p256.json",
			wantErr:     false,
		},
		{
			name:        "Valid SHA-256 hash BOM",
			fixtureFile: "algorithm_sha256.json",
			wantErr:     false,
		},
		{
			name:        "Valid digest BOM",
			fixtureFile: "digest_sha256.json",
			wantErr:     false,
		},
		{
			name:        "Valid multi-asset BOM",
			fixtureFile: "multi_assets.json",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load fixture and convert to BOM
			report := loadFixture(t, tt.fixtureFile)
			converter := NewConverter()
			bom, err := converter.Convert(report)
			if err != nil {
				t.Fatalf("Failed to convert fixture: %v", err)
			}

			// Validate BOM
			err = validator.Validate(bom)

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
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

func TestValidator_ValidateNilBOM(t *testing.T) {
	validator := NewValidator()
	err := validator.Validate(nil)
	if err == nil {
		t.Error("Validate(nil) should return error")
	}
}

func TestValidator_ValidateStructure(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		bom         *cdx.BOM
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid structure",
			bom: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				SerialNumber: "urn:uuid:test-123",
				Version:      1,
			},
			wantErr: false,
		},
		{
			name: "Invalid BOM format",
			bom: &cdx.BOM{
				BOMFormat:    "Invalid",
				SpecVersion:  cdx.SpecVersion1_6,
				SerialNumber: "urn:uuid:test-123",
				Version:      1,
			},
			wantErr:     true,
			errContains: "bomFormat",
		},
		{
			name: "Invalid spec version",
			bom: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_5,
				SerialNumber: "urn:uuid:test-123",
				Version:      1,
			},
			wantErr:     true,
			errContains: "specVersion",
		},
		{
			name: "Missing serial number",
			bom: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				SerialNumber: "",
				Version:      1,
			},
			wantErr:     true,
			errContains: "serialNumber",
		},
		{
			name: "Invalid version",
			bom: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				SerialNumber: "urn:uuid:test-123",
				Version:      0,
			},
			wantErr:     true,
			errContains: "version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateStructure(tt.bom)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateStructure() error = %v, wantErr %v", err, tt.wantErr)
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

func TestValidator_ValidateComponent(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		component   *cdx.Component
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid algorithm component",
			component: &cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				BOMRef: "crypto-asset/AES/test/42",
				Name:   "AES-256-GCM",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeAlgorithm,
					AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
						Primitive: cdx.CryptoPrimitiveAE,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid digest component",
			component: &cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				BOMRef: "crypto-asset/SHA-256/test/20",
				Name:   "SHA-256-digest",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid component type",
			component: &cdx.Component{
				Type:   cdx.ComponentTypeLibrary,
				BOMRef: "test-ref",
				Name:   "Test",
			},
			wantErr:     true,
			errContains: "cryptographic-asset",
		},
		{
			name: "Missing BOM ref",
			component: &cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				BOMRef: "",
				Name:   "Test",
			},
			wantErr:     true,
			errContains: "bom-ref",
		},
		{
			name: "Missing name",
			component: &cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				BOMRef: "test-ref",
				Name:   "",
			},
			wantErr:     true,
			errContains: "name",
		},
		{
			name: "Missing crypto properties",
			component: &cdx.Component{
				Type:             cdx.ComponentTypeCryptographicAsset,
				BOMRef:           "test-ref",
				Name:             "Test",
				CryptoProperties: nil,
			},
			wantErr:     true,
			errContains: "cryptoProperties",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateComponent(tt.component)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateComponent() error = %v, wantErr %v", err, tt.wantErr)
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

func TestValidator_ValidateCryptoProperties(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		props       *cdx.CryptoProperties
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid algorithm properties",
			props: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Primitive: cdx.CryptoPrimitiveAE,
				},
			},
			wantErr: false,
		},
		{
			name: "Valid digest properties",
			props: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			},
			wantErr: false,
		},
		{
			name: "Missing asset type",
			props: &cdx.CryptoProperties{
				AssetType: "",
			},
			wantErr:     true,
			errContains: "assetType",
		},
		{
			name: "Missing algorithm properties for algorithm asset",
			props: &cdx.CryptoProperties{
				AssetType:           cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: nil,
			},
			wantErr:     true,
			errContains: "algorithmProperties",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateCryptoProperties(tt.props)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateCryptoProperties() error = %v, wantErr %v", err, tt.wantErr)
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

func TestValidator_ValidateAlgorithmProperties(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		props       *cdx.CryptoProperties
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid algorithm properties",
			props: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Primitive:              cdx.CryptoPrimitiveAE,
					ParameterSetIdentifier: "256",
				},
			},
			wantErr: false,
		},
		{
			name: "Missing primitive",
			props: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Primitive: "",
				},
			},
			wantErr:     true,
			errContains: "primitive",
		},
		{
			name: "Invalid primitive value",
			props: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Primitive: "invalid-primitive",
				},
			},
			wantErr:     true,
			errContains: "primitive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateAlgorithmProperties(tt.props)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateAlgorithmProperties() error = %v, wantErr %v", err, tt.wantErr)
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

func TestValidator_ValidatePrimitive(t *testing.T) {
	validator := NewValidator()

	validPrimitives := []cdx.CryptoPrimitive{
		cdx.CryptoPrimitiveAE,
		cdx.CryptoPrimitiveBlockCipher,
		cdx.CryptoPrimitiveStreamCipher,
		cdx.CryptoPrimitiveHash,
		cdx.CryptoPrimitiveSignature,
		cdx.CryptoPrimitiveMAC,
		cdx.CryptoPrimitiveKDF,
		cdx.CryptoPrimitivePKE,
		cdx.CryptoPrimitiveKEM,
		cdx.CryptoPrimitiveDRBG,
		cdx.CryptoPrimitiveOther,
	}

	// Test all valid primitives
	for _, prim := range validPrimitives {
		t.Run("Valid_"+string(prim), func(t *testing.T) {
			err := validator.validatePrimitive(prim)
			if err != nil {
				t.Errorf("validatePrimitive(%q) should not error: %v", prim, err)
			}
		})
	}

	// Test invalid primitive
	t.Run("Invalid primitive", func(t *testing.T) {
		err := validator.validatePrimitive("invalid-primitive")
		if err == nil {
			t.Error("validatePrimitive('invalid-primitive') should return error")
		}
	})

	// Test empty primitive
	t.Run("Empty primitive", func(t *testing.T) {
		err := validator.validatePrimitive("")
		if err == nil {
			t.Error("validatePrimitive('') should return error")
		}
	})
}
