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
	// Validate required fields for CBOM
	if err := m.validateRequiredFields(asset); err != nil {
		return nil, err
	}

	// Extract required fields
	primitive := asset.Metadata["primitive"]
	algorithmName := asset.Metadata["algorithmName"]

	// Map primitive to CycloneDX enum
	cdxPrimitive, err := mapPrimitiveToCycloneDX(primitive)
	if err != nil {
		return nil, fmt.Errorf("invalid primitive type: %w", err)
	}

	// Build algorithm properties
	algorithmProps := &cdx.CryptoAlgorithmProperties{
		Primitive: cdxPrimitive,
	}

	// Add optional fields
	m.addParameterSetIdentifier(algorithmProps, asset)
	m.addMode(algorithmProps, asset)
	m.addPadding(algorithmProps, asset)
	m.addCurve(algorithmProps, asset)
	m.addExecutionEnvironment(algorithmProps, asset)
	m.addImplementationPlatform(algorithmProps, asset)
	m.addSecurityLevel(algorithmProps, asset)

	// Build crypto properties
	assetType := cdx.CryptoAssetTypeAlgorithm
	cryptoProps := &cdx.CryptoProperties{
		AssetType:           assetType,
		AlgorithmProperties: algorithmProps,
	}

	// Generate component name
	componentName := m.generateComponentName(algorithmName, asset)

	// Generate BOM reference
	bomRef := generateBOMRef(finding.FilePath, asset.LineNumber, algorithmName)

	// Build component
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

	// Log warning if missing (recommended but not required)
	algorithmName := asset.Metadata["algorithmName"]
	log.Warn().
		Str("algorithm", algorithmName).
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

// addExecutionEnvironment sets execution environment (defaults to software-plain-ram).
func (m *AlgorithmMapper) addExecutionEnvironment(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	// Check if explicitly provided
	if execEnv, ok := asset.Metadata["executionEnvironment"]; ok && execEnv != "" {
		props.ExecutionEnvironment = cdx.CryptoExecutionEnvironment(execEnv)
		return
	}

	// Default to software-plain-ram
	props.ExecutionEnvironment = cdx.CryptoExecutionEnvironmentSoftwarePlainRAM
}

// addImplementationPlatform adds implementation platform (library) if available.
func (m *AlgorithmMapper) addImplementationPlatform(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	if library, ok := asset.Metadata["library"]; ok && library != "" {
		// Map Go stdlib libraries to friendly names
		platform := mapLibraryToImplementationPlatform(library)
		props.ImplementationPlatform = cdx.ImplementationPlatform(platform)
	}
}

// addSecurityLevel calculates classical security level from key size if available.
func (m *AlgorithmMapper) addSecurityLevel(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	// Try to extract security level from parameter set identifier or key size
	var keySize int
	var err error

	if props.ParameterSetIdentifier != "" {
		keySize, err = strconv.Atoi(props.ParameterSetIdentifier)
		if err != nil {
			// Not a numeric parameter (e.g., curve name)
			return
		}
	} else if keySizeStr, ok := asset.Metadata["keySize"]; ok {
		keySize, err = strconv.Atoi(keySizeStr)
		if err != nil {
			return
		}
	} else {
		return
	}

	// Calculate classical security level based on algorithm and key size
	algorithmName := asset.Metadata["algorithmName"]
	securityLevel := calculateClassicalSecurityLevel(algorithmName, keySize)
	if securityLevel > 0 {
		props.ClassicalSecurityLevel = &securityLevel
	}
}

// generateComponentName creates a component name from algorithm details.
// Format: {algorithmName}[-{parameterSetIdentifier}][-{mode}]
func (m *AlgorithmMapper) generateComponentName(algorithmName string, asset *entities.CryptographicAsset) string {
	parts := []string{algorithmName}

	// Add parameter set identifier if available
	if paramSet, ok := asset.Metadata["parameterSetIdentifier"]; ok && paramSet != "" {
		parts = append(parts, paramSet)
	} else if keySize, ok := asset.Metadata["keySize"]; ok && keySize != "" {
		parts = append(parts, keySize)
	} else if curve, ok := asset.Metadata["curve"]; ok && curve != "" {
		parts = append(parts, curve)
	}

	// Add mode if available
	if mode, ok := asset.Metadata["mode"]; ok && mode != "" {
		parts = append(parts, mode)
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

	return &properties
}

// mapLibraryToImplementationPlatform maps library names to friendly platform names.
func mapLibraryToImplementationPlatform(library string) string {
	switch {
	case strings.HasPrefix(library, "crypto/"):
		return "Go stdlib"
	case library == "go-crypto":
		return "Go stdlib"
	case strings.HasPrefix(library, "golang.org/x/crypto"):
		return "golang.org/x/crypto"
	default:
		return library
	}
}

// calculateClassicalSecurityLevel estimates security level from algorithm and key size.
// Based on NIST SP 800-57 Part 1 Rev. 5
func calculateClassicalSecurityLevel(algorithmName string, keySize int) int {
	algorithmUpper := strings.ToUpper(algorithmName)

	switch {
	// Symmetric algorithms (AES, ChaCha20, etc.)
	case strings.Contains(algorithmUpper, "AES"),
		strings.Contains(algorithmUpper, "CHACHA"),
		strings.Contains(algorithmUpper, "CAMELLIA"):
		return keySize

	// Hash functions (SHA-256, SHA-512, etc.)
	case strings.Contains(algorithmUpper, "SHA"),
		strings.Contains(algorithmUpper, "BLAKE"),
		strings.Contains(algorithmUpper, "KECCAK"):
		return keySize

	// RSA (security level is lower than key size)
	case algorithmUpper == "RSA":
		switch {
		case keySize >= 15360:
			return 256
		case keySize >= 7680:
			return 192
		case keySize >= 3072:
			return 128
		case keySize >= 2048:
			return 112
		case keySize >= 1024:
			return 80
		default:
			return 0
		}

	// ECC (based on curve size or name)
	case algorithmUpper == "ECDSA", algorithmUpper == "ECDH",
		strings.Contains(algorithmUpper, "EC"):
		switch {
		case keySize >= 512:
			return 256
		case keySize >= 384:
			return 192
		case keySize >= 256:
			return 128
		default:
			return 0
		}

	// EdDSA
	case strings.Contains(algorithmUpper, "ED25519"):
		return 128
	case strings.Contains(algorithmUpper, "ED448"):
		return 224

	// Default: return key size if symmetric-like
	default:
		if keySize <= 512 {
			return keySize
		}
		return 0
	}
}
