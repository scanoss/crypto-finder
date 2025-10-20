package converter

import (
	"testing"

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
			wantSecLevel:  intPtr(256),
			wantErr:       false,
		},
		{
			name:          "RSA-2048 public key",
			fixtureFile:   "algorithm_rsa_2048.json",
			wantName:      "RSA-2048",
			wantPrimitive: "pke",
			wantKeySize:   "2048",
			wantMode:      "",
			wantSecLevel:  intPtr(112),
			wantErr:       false,
		},
		{
			name:          "ECDSA P-256 signature",
			fixtureFile:   "algorithm_ecdsa_p256.json",
			wantName:      "ECDSA-P-256",
			wantPrimitive: "signature",
			wantKeySize:   "P-256",
			wantMode:      "",
			wantSecLevel:  nil, // P-256 is not numeric, no security level
			wantErr:       false,
		},
		{
			name:          "SHA-256 hash",
			fixtureFile:   "algorithm_sha256.json",
			wantName:      "SHA-256-256", // Note: parameterSetIdentifier appended
			wantPrimitive: "hash",
			wantKeySize:   "256",
			wantMode:      "",
			wantSecLevel:  intPtr(256),
			wantErr:       false,
		},
		{
			name:        "Missing primitive field",
			fixtureFile: "incomplete_missing_primitive.json",
			wantErr:     true,
			errContains: "missing required field 'primitive'",
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

			// Check crypto properties
			if component.CryptoProperties == nil {
				t.Fatal("Component missing CryptoProperties")
			}

			if string(component.CryptoProperties.AssetType) != "algorithm" {
				t.Errorf("AssetType = %q, want %q", component.CryptoProperties.AssetType, "algorithm")
			}

			algProps := component.CryptoProperties.AlgorithmProperties
			if algProps == nil {
				t.Fatal("Component missing AlgorithmProperties")
			}

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

			// Check properties
			if component.Properties == nil || len(*component.Properties) == 0 {
				t.Error("Component missing Properties for traceability")
			}
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
				"primitive":     "ae",
				"algorithmName": "AES",
			},
			wantErr: false,
		},
		{
			name: "Missing primitive",
			metadata: map[string]string{
				"algorithmName": "AES",
			},
			wantErr:     true,
			errContains: "primitive",
		},
		{
			name: "Missing algorithmName",
			metadata: map[string]string{
				"primitive": "ae",
			},
			wantErr:     true,
			errContains: "algorithmName",
		},
		{
			name: "Empty primitive",
			metadata: map[string]string{
				"primitive":     "  ",
				"algorithmName": "AES",
			},
			wantErr:     true,
			errContains: "primitive",
		},
		{
			name: "Empty algorithmName",
			metadata: map[string]string{
				"primitive":     "ae",
				"algorithmName": "  ",
			},
			wantErr:     true,
			errContains: "algorithmName",
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

func TestGenerateComponentName(t *testing.T) {
	mapper := NewAlgorithmMapper()

	tests := []struct {
		name          string
		algorithmName string
		metadata      map[string]string
		want          string
	}{
		{
			name:          "Algorithm with parameterSetIdentifier and mode",
			algorithmName: "AES",
			metadata: map[string]string{
				"parameterSetIdentifier": "256",
				"mode":                   "GCM",
			},
			want: "AES-256-GCM",
		},
		{
			name:          "Algorithm with keySize instead of parameterSetIdentifier",
			algorithmName: "AES",
			metadata: map[string]string{
				"keySize": "128",
				"mode":    "CBC",
			},
			want: "AES-128-CBC",
		},
		{
			name:          "Algorithm with curve",
			algorithmName: "ECDSA",
			metadata: map[string]string{
				"curve": "P-256",
			},
			want: "ECDSA-P-256",
		},
		{
			name:          "Algorithm with only name",
			algorithmName: "SHA-256",
			metadata:      map[string]string{},
			want:          "SHA-256",
		},
		{
			name:          "Algorithm with keySize but no mode",
			algorithmName: "RSA",
			metadata: map[string]string{
				"keySize": "2048",
			},
			want: "RSA-2048",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: tt.metadata,
			}

			got := mapper.generateComponentName(tt.algorithmName, asset)

			if got != tt.want {
				t.Errorf("generateComponentName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCalculateClassicalSecurityLevel(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		keySize   int
		want      int
	}{
		// Symmetric algorithms
		{name: "AES-128", algorithm: "AES", keySize: 128, want: 128},
		{name: "AES-256", algorithm: "AES", keySize: 256, want: 256},
		{name: "ChaCha20", algorithm: "ChaCha20", keySize: 256, want: 256},

		// Hash functions
		{name: "SHA-256", algorithm: "SHA-256", keySize: 256, want: 256},
		{name: "SHA-512", algorithm: "SHA-512", keySize: 512, want: 512},

		// RSA (asymmetric)
		{name: "RSA-1024", algorithm: "RSA", keySize: 1024, want: 80},
		{name: "RSA-2048", algorithm: "RSA", keySize: 2048, want: 112},
		{name: "RSA-3072", algorithm: "RSA", keySize: 3072, want: 128},
		{name: "RSA-7680", algorithm: "RSA", keySize: 7680, want: 192},
		{name: "RSA-15360", algorithm: "RSA", keySize: 15360, want: 256},

		// ECC
		{name: "ECDSA-256", algorithm: "ECDSA", keySize: 256, want: 128},
		{name: "ECDSA-384", algorithm: "ECDSA", keySize: 384, want: 192},
		{name: "ECDSA-512", algorithm: "ECDSA", keySize: 512, want: 256},

		// EdDSA
		{name: "Ed25519", algorithm: "Ed25519", keySize: 256, want: 128},
		{name: "Ed448", algorithm: "Ed448", keySize: 448, want: 224},

		// Unknown/zero cases
		{name: "Unknown algorithm", algorithm: "UNKNOWN", keySize: 128, want: 128},
		{name: "Very large key", algorithm: "UNKNOWN", keySize: 1024, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateClassicalSecurityLevel(tt.algorithm, tt.keySize)
			if got != tt.want {
				t.Errorf("calculateClassicalSecurityLevel(%q, %d) = %d, want %d",
					tt.algorithm, tt.keySize, got, tt.want)
			}
		})
	}
}

func TestMapLibraryToImplementationPlatform(t *testing.T) {
	tests := []struct {
		name    string
		library string
		want    string
	}{
		{name: "Go stdlib crypto/aes", library: "crypto/aes", want: "Go stdlib"},
		{name: "Go stdlib crypto/rsa", library: "crypto/rsa", want: "Go stdlib"},
		{name: "go-crypto alias", library: "go-crypto", want: "Go stdlib"},
		{name: "golang.org/x/crypto", library: "golang.org/x/crypto/chacha20", want: "golang.org/x/crypto"},
		{name: "Other library", library: "bouncycastle", want: "bouncycastle"},
		{name: "pyca/cryptography", library: "pyca/cryptography", want: "pyca/cryptography"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapLibraryToImplementationPlatform(tt.library)
			if got != tt.want {
				t.Errorf("mapLibraryToImplementationPlatform(%q) = %q, want %q",
					tt.library, got, tt.want)
			}
		})
	}
}

// Helper functions.
func intPtr(i int) *int {
	return &i
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
