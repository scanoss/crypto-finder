// Package converter transforms crypto-finder interim format to CycloneDX CBOM format.
package converter

import (
	"github.com/scanoss/crypto-finder/internal/entities"
)

// AggregatedAsset represents a cryptographic asset with all its occurrences and detection methods.
type AggregatedAsset struct {
	// Name is the CycloneDX component name (e.g., "CSPRNG", "SHA-256", "AES-256-GCM")
	Name string

	// AssetType is the type of cryptographic asset ("algorithm", "related-crypto-material", etc.)
	AssetType string

	// Occurrences tracks all locations where this asset was detected
	Occurrences []AssetOccurrence

	// Identities tracks all unique detection methods (rules) that found this asset
	Identities []AssetIdentity

	// ReferenceAsset holds one representative asset for extracting common metadata
	ReferenceAsset *entities.CryptographicAsset

	// ReferenceFinding holds one representative finding for context
	ReferenceFinding *entities.Finding
}

// AssetOccurrence represents a single detection instance of a cryptographic asset.
type AssetOccurrence struct {
	// FilePath is the location of the file containing the asset
	FilePath string

	// StartLine is the line number where the asset was detected
	StartLine int

	// EndLine is the line number where the asset ends
	EndLine int

	// RuleID is the ID of the rule that detected this occurrence
	RuleID string

	// API is the cryptographic API that was detected (if available)
	API string

	// Match is the code snippet that was matched
	Match string
}

// AssetIdentity represents a unique detection method for a cryptographic asset.
type AssetIdentity struct {
	// RuleID is the unique identifier of the detection rule
	RuleID string

	// API is the cryptographic API detected by this rule (if available)
	API string

	// Message is the human-readable description from the rule
	Message string

	// Match is the code snippet that was matched
	Match string

	// Severity is the severity level of the finding
	Severity string

	// Confidence is the confidence level of this detection (0.0 to 1.0)
	Confidence float64
}

// Aggregator groups cryptographic assets by their identity.
type Aggregator struct {
	algorithmMapper     *AlgorithmMapper
	relatedCryptoMapper *RelatedCryptoMapper
}

// NewAggregator creates a new asset aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		algorithmMapper:     NewAlgorithmMapper(),
		relatedCryptoMapper: NewRelatedCryptoMapper(),
	}
}

// AggregateAssets groups cryptographic assets by their identity (CDX component name).
// Assets are grouped such that multiple occurrences of the same crypto asset
// (e.g., SHA-256 used in multiple files) are combined into a single aggregated entry.
func (a *Aggregator) AggregateAssets(report *entities.InterimReport) ([]AggregatedAsset, error) {
	// Map to group assets by their unique key
	assetMap := make(map[string]*AggregatedAsset)

	// Iterate through all findings and assets
	for i := range report.Findings {
		finding := &report.Findings[i]

		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]

			// Get the asset type
			assetType, ok := asset.Metadata["assetType"]
			if !ok || assetType == "" {
				continue // Skip assets without type
			}

			// Generate the asset key (CDX component name) based on asset type
			assetKey := a.getAssetKey(asset)

			// Create or retrieve aggregated asset
			aggregated, exists := assetMap[assetKey]
			if !exists {
				aggregated = &AggregatedAsset{
					Name:             assetKey,
					AssetType:        assetType,
					Occurrences:      []AssetOccurrence{},
					Identities:       []AssetIdentity{},
					ReferenceAsset:   asset,
					ReferenceFinding: finding,
				}
				assetMap[assetKey] = aggregated
			}

			// Add occurrence
			occurrence := AssetOccurrence{
				FilePath:  finding.FilePath,
				StartLine: asset.StartLine,
				EndLine:   asset.EndLine,
				RuleID:    asset.Rule.ID,
				API:       asset.Metadata["api"],
				Match:     asset.Match,
			}
			aggregated.Occurrences = append(aggregated.Occurrences, occurrence)

			// Add identity if it's a new rule
			a.addIdentityIfNew(aggregated, asset)
		}
	}

	// Convert map to slice
	result := make([]AggregatedAsset, 0, len(assetMap))
	for _, aggregated := range assetMap {
		result = append(result, *aggregated)
	}

	return result, nil
}

// getAssetKey generates the unique key for grouping assets.
// For algorithms, this is the CDX component name (e.g., "SHA-256", "AES-256-GCM").
// For related-crypto-material, this is also based on the name pattern.
func (a *Aggregator) getAssetKey(asset *entities.CryptographicAsset) string {
	assetType := asset.Metadata["assetType"]

	switch assetType {
	case AssetTypeAlgorithm:
		return a.algorithmMapper.getAlgorithmName(asset)
	case AssetTypeRelatedCryptoMaterial:
		return a.relatedCryptoMapper.getMaterialName(asset)
	default:
		// For other types, we'll handle them later
		return ""
	}
}

// addIdentityIfNew adds a new identity entry if this rule hasn't been seen for this asset.
func (a *Aggregator) addIdentityIfNew(aggregated *AggregatedAsset, asset *entities.CryptographicAsset) {
	ruleID := asset.Rule.ID
	api := asset.Metadata["api"]

	// Check if we already have an identity for this rule + API combination
	for _, existing := range aggregated.Identities {
		if existing.RuleID == ruleID && existing.API == api {
			return // Already exists
		}
	}

	// Add new identity
	identity := AssetIdentity{
		RuleID:     ruleID,
		API:        api,
		Message:    asset.Rule.Message,
		Severity:   asset.Rule.Severity,
		Match:      asset.Match,
		Confidence: 1.0, // Default confidence for source-code-analysis
	}
	aggregated.Identities = append(aggregated.Identities, identity)
}
