package converter

import (
	"fmt"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// AlgorithmMapper converts cryptographic algorithm assets to CycloneDX components.
type AlgorithmMapper struct{}

// NewAlgorithmMapper creates a new algorithm mapper.
func NewAlgorithmMapper() *AlgorithmMapper {
	return &AlgorithmMapper{}
}

// MapToComponent converts a cryptographic asset to a CycloneDX component.
// Applies strict mapping - returns error if required fields are missing.
func (m *AlgorithmMapper) MapToComponent(finding *entities.Finding, asset *entities.CryptographicAsset) (*cdx.Component, error) {
	if err := m.validateRequiredFields(asset); err != nil {
		return nil, err
	}

	algorithmPrimitive := asset.Metadata["algorithmPrimitive"]

	cdxPrimitive, err := mapPrimitiveToCycloneDX(algorithmPrimitive)
	if err != nil {
		return nil, fmt.Errorf("invalid primitive type: %w", err)
	}

	algorithmProps := &cdx.CryptoAlgorithmProperties{
		Primitive: cdxPrimitive,
	}

	// TODO: Add algorithmFamily, it's not supported yet in cdx library and cdx 1.6 spec
	// Add optional fields
	m.addParameterSetIdentifier(algorithmProps, asset)
	m.addMode(algorithmProps, asset)
	m.addPadding(algorithmProps, asset)

	algorithmName := m.getAlgorithmName(asset)

	assetType := cdx.CryptoAssetTypeAlgorithm
	cryptoProps := &cdx.CryptoProperties{
		AssetType:           assetType,
		AlgorithmProperties: algorithmProps,
	}

	bomRef := generateBOMRef()

	componentType := cdx.ComponentTypeCryptographicAsset
	component := &cdx.Component{
		Type:             componentType,
		BOMRef:           bomRef,
		Name:             algorithmName,
		CryptoProperties: cryptoProps,
		Properties:       m.buildProperties(finding, asset),
	}

	return component, nil
}

// validateRequiredFields checks that all required CBOM fields are present.
func (m *AlgorithmMapper) validateRequiredFields(asset *entities.CryptographicAsset) error {
	// Check for assetType
	assetType, hasAssetType := asset.Metadata["assetType"]
	if !hasAssetType || strings.TrimSpace(assetType) == "" {
		return fmt.Errorf("missing required field 'assetType'")
	}

	// Verify assetType is "algorithm"
	if strings.ToLower(strings.TrimSpace(assetType)) != "algorithm" {
		return fmt.Errorf("invalid assetType '%s' for algorithm mapper (must be 'algorithm')", assetType)
	}

	// Check for primitive
	primitive, hasPrimitive := asset.Metadata["algorithmPrimitive"]
	if !hasPrimitive || strings.TrimSpace(primitive) == "" {
		return fmt.Errorf("missing required field 'algorithmPrimitive' (required for assetType='algorithm')")
	}

	// Check for family
	family, hasFamily := asset.Metadata["algorithmFamily"]
	if !hasFamily || strings.TrimSpace(family) == "" {
		return fmt.Errorf("missing required field 'algorithmFamily' (required for assetType='algorithm')")
	}

	return nil
}

// addParameterSetIdentifier adds parameter set identifier (key size, curve, etc.) if available.
func (m *AlgorithmMapper) addParameterSetIdentifier(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	// Try explicit parameterSetIdentifier first
	if paramSet, ok := asset.Metadata["algorithmParameterSetIdentifier"]; ok && paramSet != "" {
		props.ParameterSetIdentifier = paramSet
		return
	}

	log.Debug().
		Str("match", asset.Match).
		Str("ruleID", asset.Rule.ID).
		Msg("Asset missing recommended field for assetType='algorithm' 'algorithmParameterSetIdentifier'")
}

// addMode adds encryption mode if available.
func (m *AlgorithmMapper) addMode(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	if algorithmMode, ok := asset.Metadata["algorithmMode"]; ok && algorithmMode != "" {
		// Normalize to lowercase for CycloneDX
		modeLower := strings.ToLower(algorithmMode)
		props.Mode = cdx.CryptoAlgorithmMode(modeLower)
	}
}

// addPadding adds padding scheme if available.
func (m *AlgorithmMapper) addPadding(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	if algorithmPadding, ok := asset.Metadata["algorithmPadding"]; ok && algorithmPadding != "" {
		props.Padding = cdx.CryptoPadding(algorithmPadding)
	}
}

// getAlgorithmName gets the algorithmName based on the asset metadata.
// If algorithmName is specified, we use it as is.
// Otherwise, we construct the name based on the metadata.
// {algorithmFamily}[-{algorithmParameterSetIdentifier}][-{algorithmMode}].
func (m *AlgorithmMapper) getAlgorithmName(asset *entities.CryptographicAsset) string {
	if algorithmName, ok := asset.Metadata["algorithmName"]; ok && algorithmName != "" {
		return algorithmName
	}

	algorithmFamily := asset.Metadata["algorithmFamily"]
	parts := []string{algorithmFamily}

	// Add parameter set identifier if available
	if paramSet, ok := asset.Metadata["algorithmParameterSetIdentifier"]; ok && paramSet != "" {
		parts = append(parts, paramSet)
	}

	// Add mode if available
	if mode, ok := asset.Metadata["algorithmMode"]; ok && mode != "" {
		modeUpper := strings.ToUpper(mode)
		parts = append(parts, modeUpper)
	}

	return strings.Join(parts, "-")
}

// buildProperties creates custom properties for traceability.
func (m *AlgorithmMapper) buildProperties(finding *entities.Finding, asset *entities.CryptographicAsset) *[]cdx.Property {
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
