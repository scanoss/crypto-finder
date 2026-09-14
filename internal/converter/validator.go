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
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog/log"
	"github.com/xeipuuv/gojsonschema"
)

// Validator validates CycloneDX BOMs against the 1.7 schema.
//
//go:embed schema/bom-1.7.schema.json
var cycloneDX17Schema string

//go:embed schema/jsf-0.82.schema.json
var cycloneDX17JSFSchema string

//go:embed schema/spdx.schema.json
var cycloneDX17SPDXSchema string

//go:embed schema/cryptography-defs.schema.json
var cycloneDX17CryptographySchema string

// Validator validates emitted JSON against the official CycloneDX 1.7 schema.
type Validator struct{}

// NewValidator creates a new BOM validator.
func NewValidator() *Validator {
	return &Validator{}
}

// Validate checks if a BOM conforms to the CycloneDX 1.7 schema.
func (v *Validator) Validate(bom *cdx.BOM) error {
	if bom == nil {
		return fmt.Errorf("BOM cannot be nil")
	}

	log.Debug().Msg("Starting BOM validation against CycloneDX 1.7 schema")

	// Marshal BOM to JSON for validation
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("failed to encode BOM to JSON: %w", err)
	}

	// Validate against the unmodified official CycloneDX 1.7 JSON schema before
	// applying repository-specific diagnostics. Custom checks alone cannot prove
	// standards conformance.
	if err := v.ValidateJSON(buf.Bytes()); err != nil {
		return err
	}

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

// ValidateJSON validates raw output with the official, embedded CycloneDX 1.7
// schema. It is exported so integration tests can prove malformed documents do
// not pass a repository-only structural check.
func (v *Validator) ValidateJSON(document []byte) error {
	schema, err := cycloneDX17OfflineSchema()
	if err != nil {
		return fmt.Errorf("official CycloneDX 1.7 schema bundle: %w", err)
	}
	result, err := schema.Validate(gojsonschema.NewBytesLoader(document))
	if err != nil {
		return fmt.Errorf("official CycloneDX 1.7 schema validation failed: %w", err)
	}
	if result.Valid() {
		return nil
	}
	issues := make([]string, 0, len(result.Errors()))
	for _, issue := range result.Errors() {
		issues = append(issues, issue.String())
	}
	return fmt.Errorf("official CycloneDX 1.7 schema rejected BOM: %s", strings.Join(issues, "; "))
}

// cycloneDX17OfflineSchema binds every external reference used by the official
// schema before compilation. The root schema's absolute $id would otherwise
// make gojsonschema resolve relative references through HTTP at runtime.
func cycloneDX17OfflineSchema() (*gojsonschema.Schema, error) {
	loader := gojsonschema.NewSchemaLoader()
	for url, content := range map[string]string{
		"http://cyclonedx.org/schema/jsf-0.82.schema.json":          cycloneDX17JSFSchema,
		"http://cyclonedx.org/schema/spdx.schema.json":              cycloneDX17SPDXSchema,
		"http://cyclonedx.org/schema/cryptography-defs.schema.json": cycloneDX17CryptographySchema,
		"http://cyclonedx.org/schema/bom-1.7.schema.json":           cycloneDX17Schema,
	} {
		if err := loader.AddSchema(url, gojsonschema.NewStringLoader(content)); err != nil {
			return nil, err
		}
	}
	return loader.Compile(gojsonschema.NewReferenceLoader("http://cyclonedx.org/schema/bom-1.7.schema.json"))
}

// validateStructure checks basic BOM structure requirements.
func (v *Validator) validateStructure(bom *cdx.BOM) error {
	// Check BOM format
	if bom.BOMFormat != "CycloneDX" {
		return fmt.Errorf("bomFormat must be 'CycloneDX', got '%s'", bom.BOMFormat)
	}

	// Check spec version
	if bom.SpecVersion != cdx.SpecVersion1_7 {
		return fmt.Errorf("specVersion must be 1.7, got '%s'", bom.SpecVersion)
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

	if err := v.validateEvidence(component.Evidence); err != nil {
		return err
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
		cdx.CryptoPrimitiveKeyWrap,
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

// validateEvidence validates evidence structures used by generated cryptographic assets.
func (v *Validator) validateEvidence(evidence *cdx.Evidence) error {
	if evidence == nil || evidence.Identity == nil {
		return nil
	}

	for i, identity := range *evidence.Identity.Identities {
		if identity.Field == "" {
			return fmt.Errorf("evidence.identity[%d].field is required", i)
		}
	}

	return nil
}
