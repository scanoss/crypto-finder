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
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// primitiveToFunctions maps cryptographic primitive types to their cryptographic functions.
// This mapping is based on standardized cryptographic definitions (NIST, IETF) and is stable.
// Only includes valid CycloneDX primitives as defined in the CycloneDX specification.
var primitiveToFunctions = map[string][]cdx.CryptoFunction{
	"ae":            {cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionTag},
	"block-cipher":  {cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
	"stream-cipher": {cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
	"hash":          {cdx.CryptoFunctionDigest},
	"signature":     {cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
	"mac":           {cdx.CryptoFunctionTag, cdx.CryptoFunctionVerify},
	"kdf":           {cdx.CryptoFunctionKeyderive},
	"pke":           {cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
	"kem":           {cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate},
	"xof":           {cdx.CryptoFunctionDigest},
	"key-agree":     {cdx.CryptoFunctionKeygen},
	"combiner":      {cdx.CryptoFunctionOther}, // Combines multiple primitives
	"drbg":          {cdx.CryptoFunctionGenerate},
	"other":         {cdx.CryptoFunctionOther},
}

// AlgorithmMapper converts cryptographic algorithm assets to CycloneDX components.
type AlgorithmMapper struct{}

// NewAlgorithmMapper creates a new algorithm mapper.
func NewAlgorithmMapper() *AlgorithmMapper {
	return &AlgorithmMapper{}
}

// MapToComponentWithEvidence converts a cryptographic asset to a CycloneDX component
// with support for new fields (executionEnvironment, implementationPlatform).
// This method does NOT build properties or evidence - those are handled by the converter.
func (m *AlgorithmMapper) MapToComponentWithEvidence(asset *entities.CryptographicAsset) (*cdx.Component, error) {
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

	// Add optional fields
	m.addParameterSetIdentifier(algorithmProps, asset)
	m.addMode(algorithmProps, asset)
	m.addPadding(algorithmProps, asset)
	m.addExecutionEnvironment(algorithmProps, asset)
	m.addImplementationPlatform(algorithmProps, asset)
	m.addCryptoFunctions(algorithmProps, asset)

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
		// Properties and Evidence will be set by the converter
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

	ruleID := ""
	if len(asset.Rules) > 0 {
		ruleID = asset.Rules[0].ID
	}
	log.Debug().
		Str("match", asset.Match).
		Str("ruleID", ruleID).
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

// addExecutionEnvironment adds execution environment field.
// Default: "software-plain-ram", can be overridden by rule metadata.
func (m *AlgorithmMapper) addExecutionEnvironment(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	executionEnv := "software-plain-ram" // Default value

	// Allow override from rule metadata
	if envFromMetadata, ok := asset.Metadata["executionEnvironment"]; ok && envFromMetadata != "" {
		executionEnv = envFromMetadata
	}

	props.ExecutionEnvironment = cdx.CryptoExecutionEnvironment(executionEnv)
}

// addImplementationPlatform adds implementation platform field.
// Default: "x86_64", can be overridden by rule metadata.
func (m *AlgorithmMapper) addImplementationPlatform(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	platform := "x86_64" // Default value

	// Allow override from rule metadata
	if platformFromMetadata, ok := asset.Metadata["implementationPlatform"]; ok && platformFromMetadata != "" {
		platform = platformFromMetadata
	}

	props.ImplementationPlatform = cdx.ImplementationPlatform(platform)
}

// addCryptoFunctions adds cryptographic functions based on the algorithm primitive type.
// Maps from algorithmPrimitive to the cryptographic functions the algorithm implements.
// For example: "hash" → ["digest"], "signature" → ["sign", "verify"].
func (m *AlgorithmMapper) addCryptoFunctions(props *cdx.CryptoAlgorithmProperties, _ *entities.CryptographicAsset) {
	primitiveStr := string(props.Primitive)

	// Look up functions for this primitive
	functions, ok := primitiveToFunctions[primitiveStr]
	if !ok {
		// If primitive not found, default to unknown
		log.Debug().
			Str("primitive", primitiveStr).
			Msg("Unknown primitive type, defaulting cryptoFunctions to 'unknown'")
		functions = []cdx.CryptoFunction{cdx.CryptoFunctionUnknown}
	}

	// Set the crypto functions
	props.CryptoFunctions = &functions
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
