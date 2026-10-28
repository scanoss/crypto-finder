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

const (
	scanossMaterialAlgorithmPropertyName = "scanoss:materialAlgorithm"
	scanossCurvePropertyName             = "scanoss:curve"
)

// MapToComponentWithEvidence converts a related-crypto-material asset to a CycloneDX component.
// This method does NOT build properties or evidence - those are handled by the converter.
func (m *RelatedCryptoMapper) MapToComponentWithEvidence(asset *entities.CryptographicAsset) (*cdx.Component, error) {
	if err := m.validateRequiredFields(asset); err != nil {
		return nil, err
	}

	// Get material type (e.g., "private-key", "public-key", "secret-key", "key", "token", etc...)
	materialType := asset.Metadata["materialType"]

	relatedCryptoMaterialProps := &cdx.RelatedCryptoMaterialProperties{}
	component := &cdx.Component{
		Type:        cdx.ComponentTypeCryptographicAsset,
		BOMRef:      generateBOMRef(),
		Name:        m.getMaterialName(asset),
		Description: generateDescription(materialType),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: relatedCryptoMaterialProps,
		},
		// Properties and Evidence will be set by the converter
	}

	relatedCryptoMaterialProps.Type = cdx.RelatedCryptoMaterialType(materialTypeField.value(component, materialType))
	m.addSize(relatedCryptoMaterialProps, asset)

	addCryptoFunctionProperty(component, asset)
	addKeySizeProperties(component, asset)
	identity := materialIdentityOf(asset)
	addCustomProperty(component, scanossMaterialAlgorithmPropertyName, identity.algorithm)
	addCustomProperty(component, scanossCurvePropertyName, identity.curve)

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

// materialIdentity is what tells one piece of related crypto material from
// another: two RSA keys of different sizes are different material.
type materialIdentity struct {
	materialType string
	algorithm    string
	size         string
	curve        string
}

func materialIdentityOf(asset *entities.CryptographicAsset) materialIdentity {
	return materialIdentity{
		materialType: cmp.Or(strings.TrimSpace(asset.Metadata["materialType"]), "unknown"),
		algorithm:    strings.TrimSpace(asset.Metadata["materialAlgorithm"]),
		size:         resolveRelatedCryptoMaterialSize(asset),
		curve:        strings.TrimSpace(asset.Metadata["materialCurve"]),
	}
}

// name joins algorithm, curve or else size, and type, such as RSA-3072-key,
// EC-secp384r1-key or AES-256-secret-key. A curve already fixes the size.
func (id materialIdentity) name() string {
	parts := make([]string, 0, 3)
	if id.algorithm != "" {
		parts = append(parts, id.algorithm)
	}
	if detail := cmp.Or(id.curve, id.size); detail != "" {
		parts = append(parts, detail)
	}
	return strings.Join(append(parts, id.materialType), "-")
}

// key separates material that shares a name but not a size.
func (id materialIdentity) key() string {
	return id.name() + "\x00" + id.size
}

// getMaterialName names the component after the material's identity.
func (m *RelatedCryptoMapper) getMaterialName(asset *entities.CryptographicAsset) string {
	return materialIdentityOf(asset).name()
}

func (m *RelatedCryptoMapper) addSize(props *cdx.RelatedCryptoMaterialProperties, asset *entities.CryptographicAsset) {
	rawSize := resolveRelatedCryptoMaterialSize(asset)
	if rawSize == "" {
		return
	}

	size, err := strconv.Atoi(rawSize)
	if err != nil || size <= 0 {
		return
	}

	props.Size = &size
}

const (
	scanossPublicKeySizePropertyName  = "scanoss:publicKeySize"
	scanossPrivateKeySizePropertyName = "scanoss:privateKeySize"
)

func resolveRelatedCryptoMaterialSize(asset *entities.CryptographicAsset) string {
	if asset == nil {
		return ""
	}

	if materialSize := strings.TrimSpace(asset.Metadata["materialSize"]); materialSize != "" {
		return materialSize
	}

	switch strings.ToLower(strings.TrimSpace(asset.Metadata["materialType"])) {
	case "public-key":
		return strings.TrimSpace(asset.Metadata["publicKeySize"])
	case "private-key":
		return strings.TrimSpace(asset.Metadata["privateKeySize"])
	default:
		return ""
	}
}

func addKeySizeProperties(component *cdx.Component, asset *entities.CryptographicAsset) {
	if asset == nil {
		return
	}

	addCustomProperty(component, scanossPublicKeySizePropertyName, asset.Metadata["publicKeySize"])
	addCustomProperty(component, scanossPrivateKeySizePropertyName, asset.Metadata["privateKeySize"])
}
