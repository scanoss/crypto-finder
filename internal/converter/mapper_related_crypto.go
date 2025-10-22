package converter

import (
	"fmt"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
)

const (
	unknownValue = "unknown"
)

// RelatedCryptoMapper converts related cryptographic material assets to CycloneDX components.
// This includes keys, tokens, secrets, passwords, digests, IVs, etc.
type RelatedCryptoMapper struct{}

// NewRelatedCryptoMapper creates a new related crypto material mapper.
func NewRelatedCryptoMapper() *RelatedCryptoMapper {
	return &RelatedCryptoMapper{}
}

// MapToComponent converts a related-crypto-material asset to a CycloneDX component.
// Applies strict mapping - returns error if required fields are missing.
func (m *RelatedCryptoMapper) MapToComponent(finding *entities.Finding, asset *entities.CryptographicAsset) (*cdx.Component, error) {
	// Validate required fields
	if err := m.validateRequiredFields(asset); err != nil {
		return nil, err
	}

	// Extract algorithm field (recommended for context)
	algorithm := asset.Metadata["algorithm"]
	if algorithm == "" {
		algorithm = unknownValue
	}

	// Get material type if specified (e.g., "digest", "key", "token", "secret", "iv")
	materialType, hasMaterialType := asset.Metadata["materialType"]
	if !hasMaterialType || materialType == "" {
		materialType = "crypto-material"
	}

	// Build crypto properties
	assetType := cdx.CryptoAssetTypeRelatedCryptoMaterial
	cryptoProps := &cdx.CryptoProperties{
		AssetType: assetType,
		// Note: CycloneDX doesn't have specific properties for related-crypto-material
		// We'll use custom properties to store material-specific data
	}

	// Generate component name
	componentName := generateComponentName(algorithm, materialType)

	// Generate BOM reference
	bomRef := generateBOMRef(finding.FilePath, asset.LineNumber, algorithm)

	// Build component
	componentType := cdx.ComponentTypeCryptographicAsset
	component := &cdx.Component{
		Type:             componentType,
		BOMRef:           bomRef,
		Name:             componentName,
		Description:      generateDescription(algorithm, materialType),
		CryptoProperties: cryptoProps,
		Properties:       m.buildProperties(finding, asset, materialType),
	}

	return component, nil
}

// generateComponentName creates a component name from algorithm and material type.
func generateComponentName(algorithm, materialType string) string {
	if algorithm != unknownValue && algorithm != "" {
		return fmt.Sprintf("%s-%s", algorithm, materialType)
	}
	return materialType
}

// generateDescription creates a description for the component.
func generateDescription(algorithm, materialType string) string {
	if algorithm != unknownValue && algorithm != "" {
		return fmt.Sprintf("%s produced by or related to %s", materialType, algorithm)
	}
	return fmt.Sprintf("Cryptographic %s", materialType)
}

// validateRequiredFields checks that all required fields are present for related-crypto-material assets.
func (m *RelatedCryptoMapper) validateRequiredFields(asset *entities.CryptographicAsset) error {
	// Check for assetType
	assetType, hasAssetType := asset.Metadata["assetType"]
	if !hasAssetType || strings.TrimSpace(assetType) == "" {
		return fmt.Errorf("missing required field 'assetType'")
	}

	// Verify assetType is "related-crypto-material"
	normalized := strings.ToLower(strings.TrimSpace(assetType))
	if normalized != AssetTypeRelatedCryptoMaterial {
		return fmt.Errorf("invalid assetType '%s' for related-crypto mapper (must be '%s')", assetType, AssetTypeRelatedCryptoMaterial)
	}

	// Algorithm is recommended but not strictly required for all related-crypto-material
	// (e.g., a token might not have a specific algorithm)

	return nil
}

// buildProperties creates custom properties for related-crypto-material traceability.
func (m *RelatedCryptoMapper) buildProperties(finding *entities.Finding, asset *entities.CryptographicAsset, materialType string) *[]cdx.Property {
	properties := []cdx.Property{
		{
			Name:  "scanoss:location:file",
			Value: finding.FilePath,
		},
		{
			Name:  "scanoss:location:line",
			Value: strconv.Itoa(asset.LineNumber),
		},
		{
			Name:  "scanoss:asset:type",
			Value: AssetTypeRelatedCryptoMaterial,
		},
		{
			Name:  "scanoss:material:type",
			Value: materialType,
		},
	}

	// Add algorithm if available
	if algorithm, ok := asset.Metadata["algorithm"]; ok && algorithm != "" {
		properties = append(properties, cdx.Property{
			Name:  "scanoss:material:algorithm",
			Value: algorithm,
		})
	}

	// Add value if available (e.g., digest value, key ID, token value)
	if value, ok := asset.Metadata["value"]; ok && value != "" {
		properties = append(properties, cdx.Property{
			Name:  "scanoss:material:value",
			Value: value,
		})
	}

	// Add key size if available
	if keySize, ok := asset.Metadata["keySize"]; ok && keySize != "" {
		properties = append(properties, cdx.Property{
			Name:  "scanoss:material:keySize",
			Value: keySize,
		})
	}

	return &properties
}
