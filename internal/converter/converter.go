// Package converter transforms crypto-finder interim format to CycloneDX CBOM format.
package converter

import (
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// Asset type constants matching CycloneDX 1.6 cryptographic asset type enum.
const (
	// AssetTypeAlgorithm represents cryptographic algorithms (AES, RSA, SHA-256, etc.)
	AssetTypeAlgorithm = "algorithm"

	// AssetTypeProtocol represents cryptographic protocols (TLS, SSH, IPsec, etc.)
	AssetTypeProtocol = "protocol"

	// AssetTypeCertificate represents X.509 certificates and TLS certificates.
	AssetTypeCertificate = "certificate"

	// AssetTypeRelatedCryptoMaterial represents keys, tokens, secrets, passwords, digests, IVs.
	AssetTypeRelatedCryptoMaterial = "related-crypto-material"
)

// Converter transforms interim reports to CycloneDX BOM format.
type Converter struct {
	algorithmMapper     *AlgorithmMapper
	relatedCryptoMapper *RelatedCryptoMapper
	validator           *Validator
}

// NewConverter creates a new CBOM converter with all required mappers.
func NewConverter() *Converter {
	return &Converter{
		algorithmMapper:     NewAlgorithmMapper(),
		relatedCryptoMapper: NewRelatedCryptoMapper(),
		validator:           NewValidator(),
	}
}

// Convert transforms an interim report to a CycloneDX BOM.
// It applies strict mapping - assets without required fields are skipped.
// Returns the BOM and any validation errors.
func (c *Converter) Convert(report *entities.InterimReport) (*cdx.BOM, error) {
	if report == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	log.Info().Msg("Starting conversion to CycloneDX CBOM format")

	// Create BOM with metadata
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: generateSerialNumber(),
		Version:      1,
		Metadata:     c.buildMetadata(report),
	}

	// Convert all findings to components
	components := []cdx.Component{}
	skippedCount := 0

	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			component, err := c.convertAsset(&finding, &asset)
			if err != nil {
				// Log skip but continue processing
				log.Warn().
					Str("file", finding.FilePath).
					Int("line", asset.LineNumber).
					Str("rule", asset.Rule.ID).
					Err(err).
					Msg("Skipping asset - missing required fields")
				skippedCount++
				continue
			}

			components = append(components, *component)
		}
	}

	bom.Components = &components

	log.Info().
		Int("total_assets", countTotalAssets(report)).
		Int("converted", len(components)).
		Int("skipped", skippedCount).
		Msg("Conversion complete")

	// Validate the generated BOM
	if err := c.validator.Validate(bom); err != nil {
		return nil, fmt.Errorf("BOM validation failed: %w", err)
	}

	log.Info().Msg("BOM validation successful")

	return bom, nil
}

// convertAsset converts a single cryptographic asset to a CycloneDX component.
func (c *Converter) convertAsset(finding *entities.Finding, asset *entities.CryptographicAsset) (*cdx.Component, error) {
	// Require explicit assetType in metadata
	assetType, ok := asset.Metadata["assetType"]
	if !ok || assetType == "" {
		return nil, fmt.Errorf("missing required field 'assetType' in crypto metadata (must be one of: %s, %s, %s, %s)",
			AssetTypeAlgorithm, AssetTypeProtocol, AssetTypeCertificate, AssetTypeRelatedCryptoMaterial)
	}

	// Route to appropriate mapper based on asset type
	switch assetType {
	case AssetTypeAlgorithm:
		return c.algorithmMapper.MapToComponent(finding, asset)

	case AssetTypeRelatedCryptoMaterial:
		return c.relatedCryptoMapper.MapToComponent(finding, asset)

	case AssetTypeProtocol:
		return nil, fmt.Errorf("asset type 'protocol' is not yet implemented - protocol mapper coming soon")

	case AssetTypeCertificate:
		return nil, fmt.Errorf("asset type 'certificate' is not yet implemented - certificate mapper coming soon")

	default:
		return nil, fmt.Errorf("unsupported asset type '%s' (must be one of: %s, %s, %s, %s)",
			assetType, AssetTypeAlgorithm, AssetTypeProtocol, AssetTypeCertificate, AssetTypeRelatedCryptoMaterial)
	}
}

// buildMetadata creates BOM metadata with tool information.
func (c *Converter) buildMetadata(report *entities.InterimReport) *cdx.Metadata {
	timestamp := time.Now().UTC().Format(time.RFC3339)

	return &cdx.Metadata{
		Timestamp: timestamp,
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    report.Tool.Name,
					Version: report.Tool.Version,
					Group:   "SCANOSS",
				},
			},
		},
	}
}

// generateSerialNumber creates a unique BOM serial number.
func generateSerialNumber() string {
	return fmt.Sprintf("urn:uuid:%s", uuid.New().String())
}

// generateBOMRef creates a unique BOM reference for a component.
// For now we are using UUIDs. Leaving this function if we decide to use a different approach.
func generateBOMRef() string {
	return uuid.NewString()
}

// countTotalAssets counts all cryptographic assets in the report.
func countTotalAssets(report *entities.InterimReport) int {
	count := 0
	for _, finding := range report.Findings {
		count += len(finding.CryptographicAssets)
	}
	return count
}
