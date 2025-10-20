// Package converter transforms crypto-finder interim format to CycloneDX CBOM format.
package converter

import (
	"crypto/sha256"
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// AssetTypeAlgorithm is the type of asset used to store algorithm information in the CBOM.
const AssetTypeAlgorithm = "algorithm"

// AssetTypeDigest is the type of asset used to store digest information in the CBOM.
const AssetTypeDigest = "digest"

// Converter transforms interim reports to CycloneDX BOM format.
type Converter struct {
	algorithmMapper *AlgorithmMapper
	digestMapper    *DigestMapper
	validator       *Validator
}

// NewConverter creates a new CBOM converter with all required mappers.
func NewConverter() *Converter {
	return &Converter{
		algorithmMapper: NewAlgorithmMapper(),
		digestMapper:    NewDigestMapper(),
		validator:       NewValidator(),
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
	// Determine asset type based on metadata
	assetType := determineAssetType(asset)

	switch assetType {
	case AssetTypeAlgorithm:
		return c.algorithmMapper.MapToComponent(finding, asset)
	case AssetTypeDigest:
		return c.digestMapper.MapToComponent(finding, asset)
	default:
		return nil, fmt.Errorf("unsupported asset type: %s", assetType)
	}
}

// determineAssetType infers the asset type from metadata.
func determineAssetType(asset *entities.CryptographicAsset) string {
	// Check for explicit assetType in metadata
	if assetType, ok := asset.Metadata["assetType"]; ok {
		return assetType
	}

	// Infer from presence of primitive field
	if _, hasPrimitive := asset.Metadata["primitive"]; hasPrimitive {
		return AssetTypeAlgorithm
	}

	// Default to algorithm for backwards compatibility
	return AssetTypeAlgorithm
}

// buildMetadata creates BOM metadata with tool information.
func (c *Converter) buildMetadata(report *entities.InterimReport) *cdx.Metadata {
	timestamp := time.Now().UTC().Format(time.RFC3339)

	return &cdx.Metadata{
		Timestamp: timestamp,
		Tools: &cdx.ToolsChoice{
			Tools: &[]cdx.Tool{
				{
					Vendor:  "SCANOSS",
					Name:    report.Tool.Name,
					Version: report.Tool.Version,
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
// Format: crypto-asset/{algorithm}/{file_hash}/{line_number}
func generateBOMRef(filePath string, lineNumber int, algorithmName string) string {
	// Create hash of file path for uniqueness
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%s:%d:%s", filePath, lineNumber, algorithmName)))
	fileHash := fmt.Sprintf("%x", hasher.Sum(nil))[:8] // First 8 chars

	return fmt.Sprintf("crypto-asset/%s/%s/%d", algorithmName, fileHash, lineNumber)
}

// countTotalAssets counts all cryptographic assets in the report.
func countTotalAssets(report *entities.InterimReport) int {
	count := 0
	for _, finding := range report.Findings {
		count += len(finding.CryptographicAssets)
	}
	return count
}
