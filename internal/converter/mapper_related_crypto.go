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

// MapToComponentWithEvidence converts a related-crypto-material asset to a CycloneDX component.
// This method does NOT build properties or evidence - those are handled by the converter.
func (m *RelatedCryptoMapper) MapToComponentWithEvidence(asset *entities.CryptographicAsset) (*cdx.Component, error) {
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

	componentName := m.getMaterialName(asset)

	componentType := cdx.ComponentTypeCryptographicAsset
	component := &cdx.Component{
		Type:             componentType,
		BOMRef:           bomRef,
		Name:             componentName,
		Description:      generateDescription(materialType),
		CryptoProperties: cryptoProps,
		// Properties and Evidence will be set by the converter
	}

	return component, nil
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

// getMaterialName gets the material name for grouping purposes.
// For related-crypto-material, we group by the material type.
func (m *RelatedCryptoMapper) getMaterialName(asset *entities.CryptographicAsset) string {
	materialType := asset.Metadata["materialType"]
	if materialType == "" {
		materialType = "unknown"
	}
	// For now, we group by material type
	// In the future, we might want more sophisticated grouping
	return materialType
}

// buildProperties creates custom properties for related-crypto-material traceability.
func (m *RelatedCryptoMapper) buildProperties(finding *entities.Finding, asset *entities.CryptographicAsset) *[]cdx.Property {
	properties := []cdx.Property{
		{
			Name:  "scanoss:location:file",
			Value: finding.FilePath,
		},
		{
			Name:  "scanoss:location:start_line",
			Value: strconv.Itoa(asset.StartLine),
		},
		{
			Name:  "scanoss:location:end_line",
			Value: strconv.Itoa(asset.EndLine),
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
	if relatedMaterialType, ok := asset.Metadata["materialType"]; ok && relatedMaterialType != "" {
		props.Type = cdx.RelatedCryptoMaterialType(relatedMaterialType)
		return
	}
}
