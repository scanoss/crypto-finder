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

// addType adds the type of the cryptographic related material if available.
func (m *RelatedCryptoMapper) addType(props *cdx.RelatedCryptoMaterialProperties, asset *entities.CryptographicAsset) {
	// Try explicit parameterSetIdentifier first
	if relatedMaterialType, ok := asset.Metadata["materialType"]; ok && relatedMaterialType != "" {
		props.Type = cdx.RelatedCryptoMaterialType(relatedMaterialType)
		return
	}
}
