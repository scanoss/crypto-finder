// Package converter transforms crypto-finder interim format to CycloneDX CBOM format.
package converter

import (
	"fmt"
	"strings"
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
	aggregator          *Aggregator
}

// NewConverter creates a new CBOM converter with all required mappers.
func NewConverter() *Converter {
	return &Converter{
		algorithmMapper:     NewAlgorithmMapper(),
		relatedCryptoMapper: NewRelatedCryptoMapper(),
		validator:           NewValidator(),
		aggregator:          NewAggregator(),
	}
}

// Convert transforms an interim report to a CycloneDX BOM.
// It aggregates assets by identity and builds evidence for each occurrence.
// Returns the BOM and any validation errors.
func (c *Converter) Convert(report *entities.InterimReport) (*cdx.BOM, error) {
	if report == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	log.Info().Msg("Starting conversion to CycloneDX CBOM format")

	// Aggregate assets by identity
	aggregatedAssets, err := c.aggregator.AggregateAssets(report)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate assets: %w", err)
	}

	log.Info().
		Int("total_occurrences", countTotalAssets(report)).
		Int("unique_assets", len(aggregatedAssets)).
		Msg("Asset aggregation complete")

	// Create BOM with metadata
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: generateSerialNumber(),
		Version:      1,
		Metadata:     c.buildMetadata(report),
	}

	// Convert aggregated assets to components
	components := []cdx.Component{}
	skippedCount := 0

	for _, aggregated := range aggregatedAssets {
		component, err := c.convertAggregatedAsset(&aggregated)
		if err != nil {
			log.Debug().
				Str("name", aggregated.Name).
				Str("assetType", aggregated.AssetType).
				Err(err).
				Msg("Skipping aggregated asset - conversion failed")
			skippedCount++
			continue
		}

		components = append(components, *component)
	}

	bom.Components = &components

	log.Info().
		Int("unique_assets", len(aggregatedAssets)).
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

// convertAggregatedAsset converts an aggregated cryptographic asset to a CycloneDX component.
// This builds a single component with evidence tracking all occurrences and detection methods.
func (c *Converter) convertAggregatedAsset(aggregated *AggregatedAsset) (*cdx.Component, error) {
	var baseComponent *cdx.Component
	var err error

	switch aggregated.AssetType {
	case AssetTypeAlgorithm:
		baseComponent, err = c.algorithmMapper.MapToComponentWithEvidence(
			aggregated.ReferenceAsset,
		)

	case AssetTypeRelatedCryptoMaterial:
		baseComponent, err = c.relatedCryptoMapper.MapToComponentWithEvidence(
			aggregated.ReferenceAsset,
		)

	case AssetTypeProtocol:
		return nil, fmt.Errorf("asset type 'protocol' is not yet implemented")

	case AssetTypeCertificate:
		return nil, fmt.Errorf("asset type 'certificate' is not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported asset type '%s'", aggregated.AssetType)
	}

	if err != nil {
		return nil, err
	}

	baseComponent.Name = aggregated.Name
	baseComponent.Evidence = c.buildEvidence(aggregated)

	return baseComponent, nil
}

// buildEvidence constructs the evidence structure with occurrences and identities.
func (c *Converter) buildEvidence(aggregated *AggregatedAsset) *cdx.Evidence {
	occurrences := make([]cdx.EvidenceOccurrence, 0, len(aggregated.Occurrences))
	for _, occ := range aggregated.Occurrences {
		occurrence := cdx.EvidenceOccurrence{
			Location: occ.FilePath,
		}

		if occ.StartLine > 0 {
			occurrence.Line = &occ.StartLine
		}

		if occ.RuleID != "" {
			occurrence.AdditionalContext = fmt.Sprintf("scanoss:ruleid,%s", occ.RuleID)
		}

		occurrences = append(occurrences, occurrence)
	}

	// Build identity array
	identities := make([]cdx.EvidenceIdentity, 0, len(aggregated.Identities))
	for _, identity := range aggregated.Identities {
		methods := []cdx.EvidenceIdentityMethod{}

		confidence := float32(identity.Confidence)

		if identity.API != "" {
			cleanedMatch := strings.Join(strings.Fields(identity.Match), " ")
			methods = append(methods, cdx.EvidenceIdentityMethod{
				Technique:  "source-code-analysis",
				Value:      fmt.Sprintf("scanoss:match,%s", cleanedMatch),
				Confidence: &confidence,
			})
		}

		identities = append(identities, cdx.EvidenceIdentity{
			Methods:    &methods,
			Confidence: &confidence,
		})
	}

	evidence := &cdx.Evidence{}

	if len(occurrences) > 0 {
		evidence.Occurrences = &occurrences
	}

	if len(identities) > 0 {
		evidence.Identity = &identities
	}

	return evidence
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
