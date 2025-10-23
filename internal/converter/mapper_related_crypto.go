package converter

import (
	"fmt"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
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
	if err := m.validateRequiredFields(asset); err != nil {
		return nil, err
	}

	// Get material type (e.g., "private-key", "public-key", "secret-key", "key", "token", etc...)
	materialType := asset.Metadata["materialType"]

	relatedCryptoMaterialProps := &cdx.RelatedCryptoMaterialProperties{}

	m.addType(relatedCryptoMaterialProps, asset)

	assetType := cdx.CryptoAssetTypeRelatedCryptoMaterial
	cryptoProps := &cdx.CryptoProperties{
		AssetType:                       assetType,
		RelatedCryptoMaterialProperties: relatedCryptoMaterialProps,
	}

	bomRef := generateBOMRef()

	componentName := generateComponentName(bomRef, materialType)

	componentType := cdx.ComponentTypeCryptographicAsset
	component := &cdx.Component{
		Type:             componentType,
		BOMRef:           bomRef,
		Name:             componentName,
		Description:      generateDescription(materialType),
		CryptoProperties: cryptoProps,
		Properties:       m.buildProperties(finding, asset),
	}

	return component, nil
}

// generateComponentName creates a component name from material type and bom-ref.
func generateComponentName(bomRef, materialType string) string {
	return fmt.Sprintf("%s@%s", bomRef, materialType)
}

// generateDescription creates a description for the component.
func generateDescription(materialType string) string {
	return fmt.Sprintf("Cryptographic %s", materialType)
}

// validateRequiredFields checks that all required fields are present for related-crypto-material assets.
func (m *RelatedCryptoMapper) validateRequiredFields(asset *entities.CryptographicAsset) error {
	// Check for assetType
	assetType, hasAssetType := asset.Metadata["assetType"]
	if !hasAssetType || strings.TrimSpace(assetType) == "" {
		return fmt.Errorf("missing required field 'assetType'")
	}

	// Check for materialType
	materialType, hasMaterialType := asset.Metadata["materialType"]
	if !hasMaterialType || strings.TrimSpace(materialType) == "" {
		return fmt.Errorf("missing required field 'materialType'")
	}

	// Verify assetType is "related-crypto-material"
	normalized := strings.ToLower(strings.TrimSpace(assetType))
	if normalized != AssetTypeRelatedCryptoMaterial {
		return fmt.Errorf("invalid assetType '%s' for related-crypto mapper (must be '%s')", assetType, AssetTypeRelatedCryptoMaterial)
	}

	return nil
}

// buildProperties creates custom properties for related-crypto-material traceability.
func (m *RelatedCryptoMapper) buildProperties(finding *entities.Finding, asset *entities.CryptographicAsset) *[]cdx.Property {
	properties := []cdx.Property{
		{
			Name:  "scanoss:location:file",
			Value: finding.FilePath,
		},
		{
			Name:  "scanoss:location:line",
			Value: strconv.Itoa(asset.LineNumber),
		},
	}

	// Add API if available
	if api, ok := asset.Metadata["api"]; ok && api != "" {
		properties = append(properties, cdx.Property{
			Name:  "scanoss:api",
			Value: api,
		})
	}

	// Add severity
	if asset.Rule.Severity != "" {
		properties = append(properties, cdx.Property{
			Name:  "scanoss:severity",
			Value: asset.Rule.Severity,
		})
	}

	// Add rule id if available
	if asset.Rule.ID != "" {
		properties = append(properties, cdx.Property{
			Name:  "scanoss:ruleid",
			Value: asset.Rule.ID,
		})
	}

	return &properties
}

// addType adds the type of the cryptographic related material if available.
func (m *RelatedCryptoMapper) addType(props *cdx.RelatedCryptoMaterialProperties, asset *entities.CryptographicAsset) {
	// Try explicit parameterSetIdentifier first
	if relatedMaterialType, ok := asset.Metadata["type"]; ok && relatedMaterialType != "" {
		props.Type = cdx.RelatedCryptoMaterialType(relatedMaterialType)
		return
	}
}
