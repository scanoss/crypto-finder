package converter

import (
	"fmt"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// DigestMapper converts hash digest assets to CycloneDX components.
type DigestMapper struct{}

// NewDigestMapper creates a new digest mapper.
func NewDigestMapper() *DigestMapper {
	return &DigestMapper{}
}

// MapToComponent converts a digest asset to a CycloneDX component.
// Applies strict mapping - returns error if required fields are missing.
func (m *DigestMapper) MapToComponent(finding *entities.Finding, asset *entities.CryptographicAsset) (*cdx.Component, error) {
	// Validate required fields
	if err := m.validateRequiredFields(asset); err != nil {
		return nil, err
	}

	// Extract required algorithm field
	algorithm := asset.Metadata["algorithm"]

	// Build crypto properties for digest
	assetType := cdx.CryptoAssetTypeRelatedCryptoMaterial // Digest uses related-crypto-material
	cryptoProps := &cdx.CryptoProperties{
		AssetType: assetType,
		// Note: CycloneDX doesn't have specific digestProperties
		// We'll use properties to store digest-specific data
	}

	// Generate component name
	componentName := fmt.Sprintf("%s-digest", algorithm)

	// Generate BOM reference
	bomRef := generateBOMRef(finding.FilePath, asset.LineNumber, algorithm)

	// Build component
	componentType := cdx.ComponentTypeCryptographicAsset
	component := &cdx.Component{
		Type:             componentType,
		BOMRef:           bomRef,
		Name:             componentName,
		Description:      fmt.Sprintf("Digest produced by %s", algorithm),
		CryptoProperties: cryptoProps,
		Properties:       m.buildProperties(finding, asset),
	}

	return component, nil
}

// validateRequiredFields checks that all required fields are present for digest assets.
func (m *DigestMapper) validateRequiredFields(asset *entities.CryptographicAsset) error {
	// Check for assetType = "digest"
	assetType, hasAssetType := asset.Metadata["assetType"]
	if !hasAssetType || strings.ToLower(strings.TrimSpace(assetType)) != "digest" {
		return fmt.Errorf("missing or invalid assetType (must be 'digest')")
	}

	// Check for algorithm
	algorithm, hasAlgorithm := asset.Metadata["algorithm"]
	if !hasAlgorithm || strings.TrimSpace(algorithm) == "" {
		return fmt.Errorf("missing required field 'algorithm'")
	}

	return nil
}

// buildProperties creates custom properties for digest traceability.
func (m *DigestMapper) buildProperties(finding *entities.Finding, asset *entities.CryptographicAsset) *[]cdx.Property {
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
			Value: "digest",
		},
		{
			Name:  "scanoss:digest:algorithm",
			Value: asset.Metadata["algorithm"],
		},
	}

	// Add digest value if available
	if value, ok := asset.Metadata["value"]; ok && value != "" {
		properties = append(properties, cdx.Property{
			Name:  "scanoss:digest:value",
			Value: value,
		})
	}

	return &properties
}
