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

	primitive := asset.Metadata["primitive"]
	algorithmName := asset.Metadata["algorithmName"]

	cdxPrimitive, err := mapPrimitiveToCycloneDX(primitive)
	if err != nil {
		return nil, fmt.Errorf("invalid primitive type: %w", err)
	}

	algorithmProps := &cdx.CryptoAlgorithmProperties{
		Primitive: cdxPrimitive,
	}

	// Add optional fields
	m.addParameterSetIdentifier(algorithmProps, asset)
	m.addMode(algorithmProps, asset)
	m.addPadding(algorithmProps, asset)
	m.addCurve(algorithmProps, asset)

	assetType := cdx.CryptoAssetTypeAlgorithm
	cryptoProps := &cdx.CryptoProperties{
		AssetType:           assetType,
		AlgorithmProperties: algorithmProps,
	}

	componentName := m.generateComponentName(algorithmName, asset)

	bomRef := generateBOMRef()

	componentType := cdx.ComponentTypeCryptographicAsset
	component := &cdx.Component{
		Type:             componentType,
		BOMRef:           bomRef,
		Name:             componentName,
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
	primitive, hasPrimitive := asset.Metadata["primitive"]
	if !hasPrimitive || strings.TrimSpace(primitive) == "" {
		return fmt.Errorf("missing required field 'primitive' (required for assetType='algorithm')")
	}

	// Check for algorithm name
	algorithmName, hasAlgorithmName := asset.Metadata["algorithmName"]
	if !hasAlgorithmName || strings.TrimSpace(algorithmName) == "" {
		return fmt.Errorf("missing required field 'algorithmName' (required for assetType='algorithm')")
	}

	return nil
}

// addParameterSetIdentifier adds parameter set identifier (key size, curve, etc.) if available.
func (m *AlgorithmMapper) addParameterSetIdentifier(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	// Try explicit parameterSetIdentifier first
	if paramSet, ok := asset.Metadata["parameterSetIdentifier"]; ok && paramSet != "" {
		props.ParameterSetIdentifier = paramSet
		return
	}

	// Fallback to keySize if available
	if keySize, ok := asset.Metadata["keySize"]; ok && keySize != "" {
		props.ParameterSetIdentifier = keySize
		return
	}

	// Fallback to curve if available
	if curve, ok := asset.Metadata["curve"]; ok && curve != "" {
		props.ParameterSetIdentifier = curve
		return
	}

	algorithmName := asset.Metadata["algorithmName"]
	log.Debug().
		Str("algorithm", algorithmName).
		Str("ruleID", asset.Rule.ID).
		Msg("Asset missing recommended field 'parameterSetIdentifier'")
}

// addMode adds encryption mode if available.
func (m *AlgorithmMapper) addMode(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	if mode, ok := asset.Metadata["mode"]; ok && mode != "" {
		// Normalize to lowercase for CycloneDX
		modeLower := strings.ToLower(mode)
		props.Mode = cdx.CryptoAlgorithmMode(modeLower)
	}
}

// addPadding adds padding scheme if available.
func (m *AlgorithmMapper) addPadding(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	if padding, ok := asset.Metadata["padding"]; ok && padding != "" {
		props.Padding = cdx.CryptoPadding(padding)
	}
}

// addCurve adds elliptic curve if available.
func (m *AlgorithmMapper) addCurve(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	if curve, ok := asset.Metadata["curve"]; ok && curve != "" {
		props.Curve = curve
	}
}

// generateComponentName creates a component name from algorithm details.
// Format: {algorithmName}[-{parameterSetIdentifier}][-{mode}].
func (m *AlgorithmMapper) generateComponentName(algorithmName string, asset *entities.CryptographicAsset) string {
	parts := []string{algorithmName}

	// Add parameter set identifier if available
	if paramSet, ok := asset.Metadata["parameterSetIdentifier"]; ok && paramSet != "" {
		if !strings.HasSuffix(algorithmName, "-"+paramSet) {
			parts = append(parts, paramSet)
		}
	} else if keySize, ok := asset.Metadata["keySize"]; ok && keySize != "" {
		if !strings.HasSuffix(algorithmName, "-"+keySize) {
			parts = append(parts, keySize)
		}
	}

	// Add mode if available
	if mode, ok := asset.Metadata["mode"]; ok && mode != "" {
		modeUpper := strings.ToUpper(mode)
		if !strings.HasSuffix(algorithmName, "-"+modeUpper) {
			parts = append(parts, modeUpper)
		}
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
