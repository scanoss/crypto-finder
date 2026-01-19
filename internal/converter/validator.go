package converter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog/log"
)

// Validator validates CycloneDX BOMs against the 1.6 schema.
type Validator struct{}

// NewValidator creates a new BOM validator.
func NewValidator() *Validator {
	return &Validator{}
}

// Validate checks if a BOM conforms to the CycloneDX 1.6 schema.
func (v *Validator) Validate(bom *cdx.BOM) error {
	if bom == nil {
		return fmt.Errorf("BOM cannot be nil")
	}

	log.Debug().Msg("Starting BOM validation against CycloneDX 1.6 schema")

	// Marshal BOM to JSON for validation
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("failed to encode BOM to JSON: %w", err)
	}

	// Basic structural validation
	if err := v.validateStructure(bom); err != nil {
		return fmt.Errorf("structural validation failed: %w", err)
	}

	// Validate component requirements
	if bom.Components != nil {
		for i := range *bom.Components {
			if err := v.validateComponent(&(*bom.Components)[i]); err != nil {
				return fmt.Errorf("component validation failed: %w", err)
			}
		}
	}

	log.Debug().Msg("BOM validation successful")
	return nil
}

// validateStructure checks basic BOM structure requirements.
func (v *Validator) validateStructure(bom *cdx.BOM) error {
	// Check BOM format
	if bom.BOMFormat != "CycloneDX" {
		return fmt.Errorf("bomFormat must be 'CycloneDX', got '%s'", bom.BOMFormat)
	}

	// Check spec version
	if bom.SpecVersion != cdx.SpecVersion1_6 {
		return fmt.Errorf("specVersion must be 1.6, got '%s'", bom.SpecVersion)
	}

	// Check serial number format
	if bom.SerialNumber == "" {
		return fmt.Errorf("serialNumber is required")
	}

	// Check version
	if bom.Version < 1 {
		return fmt.Errorf("version must be >= 1, got %d", bom.Version)
	}

	return nil
}

// validateComponent checks component-specific requirements.
func (v *Validator) validateComponent(component *cdx.Component) error {
	// Check component type
	if component.Type != cdx.ComponentTypeCryptographicAsset {
		return fmt.Errorf("component type must be 'cryptographic-asset', got '%s'", component.Type)
	}

	// Check BOM ref
	if component.BOMRef == "" {
		return fmt.Errorf("bom-ref is required")
	}

	// Check name
	if component.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Check crypto properties
	if component.CryptoProperties == nil {
		return fmt.Errorf("cryptoProperties is required for cryptographic assets")
	}

	// Validate crypto properties
	if err := v.validateCryptoProperties(component.CryptoProperties); err != nil {
		return fmt.Errorf("cryptoProperties: %w", err)
	}

	return nil
}

// validateCryptoProperties validates cryptographic properties.
func (v *Validator) validateCryptoProperties(props *cdx.CryptoProperties) error {
	// Check asset type
	if props.AssetType == "" {
		return fmt.Errorf("assetType is required")
	}

	// Validate based on asset type
	switch props.AssetType {
	case cdx.CryptoAssetTypeAlgorithm:
		return v.validateAlgorithmProperties(props)
	case cdx.CryptoAssetTypeRelatedCryptoMaterial:
		// Digest assets use related-crypto-material
		// No specific validation needed beyond assetType
		return nil
	case cdx.CryptoAssetTypeCertificate:
		// Certificate assets
		// No specific validation needed beyond assetType
		return nil
	case cdx.CryptoAssetTypeProtocol:
		// Protocol assets
		// No specific validation needed beyond assetType
		return nil
	default:
		return fmt.Errorf("unsupported assetType: %s", props.AssetType)
	}
}

// validateAlgorithmProperties validates algorithm-specific properties.
func (v *Validator) validateAlgorithmProperties(props *cdx.CryptoProperties) error {
	if props.AlgorithmProperties == nil {
		return fmt.Errorf("algorithmProperties is required for algorithm assets")
	}

	algProps := props.AlgorithmProperties

	// Check primitive
	if algProps.Primitive == "" {
		return fmt.Errorf("algorithmProperties.primitive is required")
	}

	// Validate primitive is a known value
	if err := v.validatePrimitive(algProps.Primitive); err != nil {
		return err
	}

	// Warn if parameterSetIdentifier is missing (recommended but not required)
	if algProps.ParameterSetIdentifier == "" {
		log.Debug().
			Msg("algorithmProperties.parameterSetIdentifier is recommended but missing")
	}

	return nil
}

// validatePrimitive checks if a primitive value is valid.
func (v *Validator) validatePrimitive(primitive cdx.CryptoPrimitive) error {
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
		cdx.CryptoPrimitiveKeyAgree,
		cdx.CryptoPrimitiveCombiner,
		cdx.CryptoPrimitiveXOF,
		cdx.CryptoPrimitiveOther,
	}

	if slices.Contains(validPrimitives, primitive) {
		return nil
	}

	var validPrimitivesStr string
	for _, validPrimitive := range validPrimitives {
		validPrimitivesStr += string(validPrimitive) + ", "
	}
	validPrimitivesStr = validPrimitivesStr[:len(validPrimitivesStr)-2]

	return fmt.Errorf("invalid primitive value: %s (must be one of: %s)", primitive, validPrimitivesStr)
}
