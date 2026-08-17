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

package converter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

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
		{
			name:           "Multiple rules on same line (deduplicated)",
			fixtureFile:    "multi_rule_same_line.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "All CycloneDX crypto asset types",
			fixtureFile:    "all_asset_types.json",
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
			allFindings := make([]entities.Finding, 0, len(tt.files))
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

func TestConverter_ConvertAggregatedAsset_ErrorPaths(t *testing.T) {
	converter := NewConverter()

	tests := []struct {
		name        string
		aggregated  *AggregatedAsset
		wantErr     bool
		errContains string
	}{
		{
			name: "Protocol asset",
			aggregated: &AggregatedAsset{
				Name:      "tls-1.3",
				AssetType: AssetTypeProtocol,
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType":       "protocol",
						"protocolType":    "TLS",
						"protocolVersion": "1.3",
					},
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr: false,
		},
		{
			name: "Certificate asset",
			aggregated: &AggregatedAsset{
				Name:      "certificate:10:12",
				AssetType: AssetTypeCertificate,
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType":               "certificate",
						"certificateFormat":       "PEM",
						"certificateSerialNumber": "01:02",
						"certificateType":         "X.509",
					},
					StartLine: 10,
					EndLine:   12,
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr: false,
		},
		{
			name: "Unknown asset type",
			aggregated: &AggregatedAsset{
				Name:      "Unknown",
				AssetType: "unknown-type",
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType": "unknown-type",
					},
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr:     true,
			errContains: "unsupported asset type",
		},
		{
			name: "Algorithm with missing required fields",
			aggregated: &AggregatedAsset{
				Name:      "InvalidAlgorithm",
				AssetType: AssetTypeAlgorithm,
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType": "algorithm",
						// Missing algorithmPrimitive and algorithmFamily
					},
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr:     true,
			errContains: "missing required field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component, err := converter.convertAggregatedAsset(tt.aggregated)

			if (err != nil) != tt.wantErr {
				t.Errorf("convertAggregatedAsset() error = %v, wantErr %v", err, tt.wantErr)
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

			if component == nil {
				t.Error("Expected component but got nil")
			}
		})
	}
}

func TestConverter_ConvertProtocolAndCertificateProperties(t *testing.T) {
	converter := NewConverter()
	bom, err := converter.Convert(loadFixture(t, "all_asset_types.json"))
	if err != nil {
		t.Fatalf("Convert() unexpected error: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) != 4 {
		t.Fatalf("expected 4 components, got %d", lenOrZero(bom.Components))
	}

	components := make(map[string]cdx.Component, len(*bom.Components))
	for _, component := range *bom.Components {
		components[component.Name] = component
	}
	if got := components["AES-256-GCM"].CryptoProperties.AssetType; got != cdx.CryptoAssetTypeAlgorithm {
		t.Errorf("algorithm asset type = %q, want %q", got, cdx.CryptoAssetTypeAlgorithm)
	}
	if got := components["secret-key"].CryptoProperties.AssetType; got != cdx.CryptoAssetTypeRelatedCryptoMaterial {
		t.Errorf("related material asset type = %q, want %q", got, cdx.CryptoAssetTypeRelatedCryptoMaterial)
	}

	protocol, ok := components["tls-1.3"]
	if !ok {
		t.Fatal("missing tls-1.3 component")
	}
	if protocol.CryptoProperties == nil || protocol.CryptoProperties.AssetType != cdx.CryptoAssetTypeProtocol {
		t.Fatal("protocol component has incorrect crypto properties")
	}
	if protocol.CryptoProperties.ProtocolProperties == nil {
		t.Fatal("protocol component missing ProtocolProperties")
	}
	if got := protocol.CryptoProperties.ProtocolProperties.Type; got != cdx.CryptoProtocolTypeTLS {
		t.Errorf("protocol type = %q, want %q", got, cdx.CryptoProtocolTypeTLS)
	}
	if got := protocol.CryptoProperties.ProtocolProperties.Version; got != "1.3" {
		t.Errorf("protocol version = %q, want %q", got, "1.3")
	}

	certificate, ok := components["01:02"]
	if !ok {
		t.Fatal("missing certificate component")
	}
	if certificate.CryptoProperties == nil || certificate.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
		t.Fatal("certificate component has incorrect crypto properties")
	}
	if certificate.CryptoProperties.CertificateProperties == nil {
		t.Fatal("certificate component missing CertificateProperties")
	}
	if got := certificate.CryptoProperties.CertificateProperties.CertificateFormat; got != "PEM" {
		t.Errorf("certificate format = %q, want %q", got, "PEM")
	}
	properties := propertyValues(certificate)
	if properties["scanoss:certificateSerialNumber"] != "01:02" {
		t.Errorf("certificate serial property = %q, want %q", properties["scanoss:certificateSerialNumber"], "01:02")
	}
	if properties["scanoss:certificateType"] != "X.509" {
		t.Errorf("certificate type property = %q, want %q", properties["scanoss:certificateType"], "X.509")
	}
}

func TestConverter_ConvertUnknownProtocolType(t *testing.T) {
	tests := []struct {
		name          string
		protocolType  string
		wantType      cdx.CryptoProtocolType
		wantProperty  string
		wantComponent string
	}{
		{
			name:          "custom protocol uses source property",
			protocolType:  "  custom-protocol  ",
			wantProperty:  "  custom-protocol  ",
			wantComponent: "custom-protocol-v1",
		},
		{
			name:          "other is an official protocol type",
			protocolType:  "OTHER",
			wantType:      cdx.CryptoProtocolTypeOther,
			wantComponent: "other-v1",
		},
		{
			name:          "unknown is an official protocol type",
			protocolType:  " UNKNOWN ",
			wantType:      cdx.CryptoProtocolTypeUnknown,
			wantComponent: "unknown-v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component, err := NewConverter().convertAggregatedAsset(&AggregatedAsset{
				AssetType: AssetTypeProtocol,
				ReferenceAsset: &entities.CryptographicAsset{Metadata: map[string]string{
					"assetType":       AssetTypeProtocol,
					"protocolType":    tt.protocolType,
					"protocolVersion": "v1",
				}},
			})
			if err != nil {
				t.Fatalf("convertAggregatedAsset() unexpected error: %v", err)
			}
			if component.Name != tt.wantComponent {
				t.Errorf("component name = %q, want %q", component.Name, tt.wantComponent)
			}
			if component.CryptoProperties == nil || component.CryptoProperties.ProtocolProperties == nil {
				t.Fatal("protocol component missing ProtocolProperties")
			}
			if got := component.CryptoProperties.ProtocolProperties.Type; got != tt.wantType {
				t.Errorf("protocol type = %q, want %q", got, tt.wantType)
			}
			properties := propertyValues(*component)
			if tt.wantProperty == "" {
				if _, ok := properties["scanoss:protocolType"]; ok {
					t.Errorf("unexpected scanoss:protocolType property: %q", properties["scanoss:protocolType"])
				}
			} else if properties["scanoss:protocolType"] != tt.wantProperty {
				t.Errorf("protocol type property = %q, want %q", properties["scanoss:protocolType"], tt.wantProperty)
			}
		})
	}
}

func TestConverter_ConvertProtocolWithoutVersion(t *testing.T) {
	component, err := NewConverter().convertAggregatedAsset(&AggregatedAsset{
		AssetType: AssetTypeProtocol,
		ReferenceAsset: &entities.CryptographicAsset{Metadata: map[string]string{
			"assetType":    AssetTypeProtocol,
			"protocolType": " SSH ",
		}},
	})
	if err != nil {
		t.Fatalf("convertAggregatedAsset() unexpected error: %v", err)
	}
	if component.Name != "ssh" {
		t.Errorf("component name = %q, want %q", component.Name, "ssh")
	}
	if got := component.CryptoProperties.ProtocolProperties.Type; got != cdx.CryptoProtocolTypeSSH {
		t.Errorf("protocol type = %q, want %q", got, cdx.CryptoProtocolTypeSSH)
	}
	if got := component.CryptoProperties.ProtocolProperties.Version; got != "" {
		t.Errorf("protocol version = %q, want empty", got)
	}
}

func TestConverter_ConvertCertificateFallbackName(t *testing.T) {
	component, err := NewConverter().convertAggregatedAsset(&AggregatedAsset{
		AssetType: AssetTypeCertificate,
		ReferenceAsset: &entities.CryptographicAsset{
			StartLine: 10,
			EndLine:   12,
			Metadata: map[string]string{
				"assetType":         AssetTypeCertificate,
				"certificateType":   "X.509",
				"certificateFormat": "PEM",
			},
		},
	})
	if err != nil {
		t.Fatalf("convertAggregatedAsset() unexpected error: %v", err)
	}
	if component.Name != "certificate:10:12:X.509:PEM" {
		t.Errorf("component name = %q, want location-based fallback", component.Name)
	}
}

func lenOrZero(components *[]cdx.Component) int {
	if components == nil {
		return 0
	}
	return len(*components)
}

func propertyValues(component cdx.Component) map[string]string {
	values := make(map[string]string)
	if component.Properties == nil {
		return values
	}
	for _, property := range *component.Properties {
		values[property.Name] = property.Value
	}
	return values
}

func TestConverter_MultipleRulesOnSameLine(t *testing.T) {
	converter := NewConverter()

	// Load test fixture with multiple rules detecting the same line
	report := loadFixture(t, "multi_rule_same_line.json")

	// Run conversion
	bom, err := converter.Convert(report)
	if err != nil {
		t.Fatalf("Convert() unexpected error: %v", err)
	}

	// Verify we get exactly 1 component (deduplicated)
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("Expected 1 component, got %d", len(*bom.Components))
	}

	component := (*bom.Components)[0]

	// Verify the component has crypto properties
	if component.CryptoProperties == nil {
		t.Fatal("Component missing CryptoProperties")
	}

	// Verify evidence structure
	if component.Evidence == nil {
		t.Fatal("Component missing Evidence")
	}

	// Verify occurrences contain code snippets (not rule IDs)
	if component.Evidence.Occurrences == nil || len(*component.Evidence.Occurrences) == 0 {
		t.Fatal("Component missing Evidence.Occurrences")
	}

	// Verify identity contains rule IDs (not code)
	if component.Evidence.Identity == nil || len(*component.Evidence.Identity) == 0 {
		t.Fatal("Component missing Evidence.Identity")
	}

	identities := *component.Evidence.Identity
	if len(identities) != 2 {
		t.Errorf("Expected 2 identity entries (one per rule), got %d", len(identities))
	}

	// Verify each identity contains methods with rule IDs
	for i, identity := range identities {
		if identity.Field != cdx.EvidenceIdentityFieldTypeName {
			t.Errorf(
				"Identity[%d] field = %q, want %q",
				i,
				identity.Field,
				cdx.EvidenceIdentityFieldTypeName,
			)
		}

		if identity.Methods == nil || len(*identity.Methods) == 0 {
			t.Errorf("Identity[%d] has no methods", i)
			continue
		}
		method := (*identity.Methods)[0]
		if method.Value == "" {
			t.Errorf("Identity[%d] method has empty value", i)
		}
		// Methods should contain rule IDs in format "scanoss:ruleid,<rule-id>"
		if !contains(method.Value, "scanoss:ruleid") {
			t.Errorf("Identity[%d] method value should contain 'scanoss:ruleid', got %q", i, method.Value)
		}
	}
}

// TestConverter_MergesCryptoFunctionsForSharedAPIDifferentOperation guards the
// DCA multi-crypto-function synthesis case: two synthesized assets at the same
// declaration site (org.bouncycastle.crypto.engines.AESEngine.init) share one
// algorithm identity but differ in cryptoFunction (encrypt vs decrypt). They
// must collapse into ONE CDX component (as aggregation-by-name already does),
// and that component's CryptoFunctions array must carry BOTH values instead of
// only the first asset's.
func TestConverter_MergesCryptoFunctionsForSharedAPIDifferentOperation(t *testing.T) {
	converter := NewConverter()

	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "org/bouncycastle/crypto/engines/AESEngine.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 70,
						EndLine:   70,
						Rules:     []entities.RuleInfo{{ID: "java.bouncycastle.algorithm.block-cipher.aes-init-encrypt", Severity: "INFO"}},
						Metadata: map[string]string{
							"assetType":          "algorithm",
							"algorithmFamily":    "AES",
							"algorithmPrimitive": "block-cipher",
							"operation":          "encrypt",
							"cryptoFunction":     "encrypt",
							"api":                "org.bouncycastle.crypto.engines.AESEngine.init",
						},
					},
					{
						StartLine: 70,
						EndLine:   70,
						Rules:     []entities.RuleInfo{{ID: "java.bouncycastle.algorithm.block-cipher.aes-init-decrypt", Severity: "INFO"}},
						Metadata: map[string]string{
							"assetType":          "algorithm",
							"algorithmFamily":    "AES",
							"algorithmPrimitive": "block-cipher",
							"operation":          "decrypt",
							"cryptoFunction":     "decrypt",
							"api":                "org.bouncycastle.crypto.engines.AESEngine.init",
						},
					},
				},
			},
		},
	}

	bom, err := converter.Convert(report)
	if err != nil {
		t.Fatalf("Convert() unexpected error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("expected 1 merged component, got nil Components")
	}
	if len(*bom.Components) != 1 {
		t.Fatalf("expected 1 merged component, got %d", len(*bom.Components))
	}

	component := (*bom.Components)[0]
	if component.CryptoProperties == nil || component.CryptoProperties.AlgorithmProperties == nil {
		t.Fatal("component missing AlgorithmProperties")
	}
	algProps := component.CryptoProperties.AlgorithmProperties
	if algProps.CryptoFunctions == nil {
		t.Fatal("CryptoFunctions is nil, want [encrypt decrypt]")
	}
	functions := *algProps.CryptoFunctions
	if len(functions) != 2 {
		t.Fatalf("CryptoFunctions count = %d, want 2 (%v)", len(functions), functions)
	}
	var hasEncrypt, hasDecrypt bool
	for _, fn := range functions {
		if fn == cdx.CryptoFunctionEncrypt {
			hasEncrypt = true
		}
		if fn == cdx.CryptoFunctionDecrypt {
			hasDecrypt = true
		}
	}
	if !hasEncrypt || !hasDecrypt {
		t.Fatalf("expected both encrypt and decrypt in CryptoFunctions, got %v", functions)
	}

	// The scanoss:cryptoFunction custom property must also carry both values.
	if component.Properties == nil {
		t.Fatal("component missing Properties")
	}
	var propValue string
	for _, p := range *component.Properties {
		if p.Name == scanossCryptoFunctionPropertyName {
			propValue = p.Value
		}
	}
	if !contains(propValue, "encrypt") || !contains(propValue, "decrypt") {
		t.Fatalf("scanoss:cryptoFunction property = %q, want it to mention both encrypt and decrypt", propValue)
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
