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
	"cmp"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// AlgorithmMapper converts cryptographic algorithm assets to CycloneDX components.
type AlgorithmMapper struct{}

// NewAlgorithmMapper creates a new algorithm mapper.
func NewAlgorithmMapper() *AlgorithmMapper { return &AlgorithmMapper{} }

// scanossUnresolvedPropertyName marks a component built from crypto calls
// whose algorithm the scan could not resolve, such as Cipher.getInstance(x).
const scanossUnresolvedPropertyName = "scanoss:unresolved"

// MapToComponentWithEvidence converts a cryptographic asset to a CycloneDX component
// with support for new fields (executionEnvironment, implementationPlatform).
// This method does NOT build properties or evidence - those are handled by the converter.
func (m *AlgorithmMapper) MapToComponentWithEvidence(asset *entities.CryptographicAsset) (*cdx.Component, error) {
	if err := m.validateRequiredFields(asset); err != nil {
		return nil, err
	}

	algorithmProps := &cdx.CryptoAlgorithmProperties{}
	component := &cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: generateBOMRef(),
		Name:   m.getAlgorithmName(asset),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: algorithmProps,
			// Projection consumes the prepared OID; it never re-resolves a claim after
			// the terminal disposition has deliberately omitted it.
			OID: asset.OID,
		},
		// Properties and Evidence will be set by the converter
	}

	metadata := asset.Metadata
	algorithmProps.Primitive = cdx.CryptoPrimitive(primitiveField.value(component, metadata["algorithmPrimitive"]))
	m.addParameterSetIdentifier(algorithmProps, asset)
	algorithmProps.Mode = cdx.CryptoAlgorithmMode(modeField.value(component, metadata["algorithmMode"]))
	algorithmProps.Padding = cdx.CryptoPadding(paddingField.value(component, cbomPadding(metadata["algorithmPadding"])))
	algorithmProps.ExecutionEnvironment = cdx.CryptoExecutionEnvironment(
		executionEnvironmentField.value(component, cmp.Or(metadata["executionEnvironment"], "software-plain-ram")))
	algorithmProps.ImplementationPlatform = cdx.ImplementationPlatform(
		implementationPlatformField.value(component, cmp.Or(metadata["implementationPlatform"], "x86_64")))
	m.addCryptoFunctions(algorithmProps, asset)

	addAlgorithmFamily(component, algorithmProps, metadata["algorithmFamily"])
	addCryptoFunctionProperty(component, asset)
	if isUnresolvedAlgorithm(asset) {
		addCustomProperty(component, scanossUnresolvedPropertyName, "true")
	}

	return component, nil
}

// validateRequiredFields checks that all required CBOM fields are present.
func (m *AlgorithmMapper) validateRequiredFields(asset *entities.CryptographicAsset) error {
	assetType, hasAssetType := asset.Metadata["assetType"]
	if !hasAssetType || strings.TrimSpace(assetType) == "" {
		return fmt.Errorf("missing required field 'assetType'")
	}

	if strings.ToLower(strings.TrimSpace(assetType)) != "algorithm" {
		return fmt.Errorf("invalid assetType '%s' for algorithm mapper (must be 'algorithm')", assetType)
	}

	primitive, hasPrimitive := asset.Metadata["algorithmPrimitive"]
	if !hasPrimitive || strings.TrimSpace(primitive) == "" {
		return fmt.Errorf("missing required field 'algorithmPrimitive' (required for assetType='algorithm')")
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

// cbomPadding maps unambiguous Java cipher transformation padding names onto
// the CycloneDX enum. Any other value is returned unchanged.
func cbomPadding(value string) string {
	switch padding := strings.ToLower(strings.TrimSpace(value)); padding {
	case "pkcs5padding":
		return "pkcs5"
	case "pkcs7padding":
		return "pkcs7"
	case "nopadding":
		return "raw"
	case "pkcs1padding":
		return string(cdx.CryptoPaddingPKCS1v15)
	case "oaeppadding":
		return string(cdx.CryptoPaddingOAEP)
	default:
		// OAEPWith<digest>AndMGF1Padding, such as OAEPWithSHA-256AndMGF1Padding.
		if strings.HasPrefix(padding, "oaepwith") && strings.HasSuffix(padding, "andmgf1padding") {
			return string(cdx.CryptoPaddingOAEP)
		}
		return value
	}
}

// addCryptoFunctions adds a single CycloneDX crypto function driven by the rule-level
// cryptoFunction/operation metadata instead of inferring a list from the primitive.
func (m *AlgorithmMapper) addCryptoFunctions(props *cdx.CryptoAlgorithmProperties, asset *entities.CryptographicAsset) {
	raw := resolveRawCryptoFunction(asset)
	if raw == "" {
		log.Debug().
			Str("name", asset.Metadata["algorithmName"]).
			Str("api", asset.Metadata["api"]).
			Msg("Asset missing cryptoFunction/operation metadata; omitting CycloneDX cryptoFunctions")
		return
	}

	function, ok := mapRawCryptoFunctionToCycloneDX(raw)
	if !ok {
		log.Debug().
			Str("cryptoFunction", raw).
			Msg("Unable to map cryptoFunction to CycloneDX enum; omitting cryptoFunctions")
		return
	}

	functions := []cdx.CryptoFunction{function}
	props.CryptoFunctions = &functions
}

// getAlgorithmName gets the algorithmName based on the asset metadata.
// If algorithmName is specified, we use it as is.
// Otherwise, we construct the name based on the metadata.
// {algorithmFamily}[-{algorithmParameterSetIdentifier}][-{algorithmMode}].
// An asset that names neither an algorithm nor a family is named
// unknown-{algorithmPrimitive}, so unresolved calls group by primitive.
func (m *AlgorithmMapper) getAlgorithmName(asset *entities.CryptographicAsset) string {
	if algorithmName, ok := asset.Metadata["algorithmName"]; ok && algorithmName != "" {
		return algorithmName
	}
	if isUnresolvedAlgorithm(asset) {
		return "unknown-" + strings.ToLower(strings.TrimSpace(asset.Metadata["algorithmPrimitive"]))
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

// isUnresolvedAlgorithm reports whether a rule matched a crypto call without
// resolving which algorithm it uses.
func isUnresolvedAlgorithm(asset *entities.CryptographicAsset) bool {
	return strings.TrimSpace(asset.Metadata["algorithmName"]) == "" &&
		strings.TrimSpace(asset.Metadata["algorithmFamily"]) == ""
}
