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

// Package enricher provides functionality to enrich cryptographic findings
// with additional metadata such as OIDs (Object Identifiers).
package enricher

import (
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/converter"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// OIDEnricher enriches cryptographic assets with OIDs based on their metadata.
// It uses the OIDMapper to resolve algorithm names to their standard OIDs.
type OIDEnricher struct {
	mapper *converter.OIDMapper
}

// NewOIDEnricher creates a new OID enricher with the OID mapper initialized.
func NewOIDEnricher() *OIDEnricher {
	return &OIDEnricher{
		mapper: converter.NewOIDMapper(),
	}
}

// EnrichAsset enriches a single cryptographic asset with its OID.
// It only adds an OID if:
//   - The asset doesn't already have an OID (never overwrites)
//   - The asset has algorithm metadata available (family or name)
//
// This method respects existing OIDs specified in semgrep rules and will not overwrite them,
// even if the mapper would resolve a different OID.
func (e *OIDEnricher) EnrichAsset(asset *entities.CryptographicAsset) {
	if asset.OID != "" {
		return
	}

	// Check if we have algorithm metadata to resolve OID from
	family := asset.Metadata["algorithmFamily"]
	name := asset.Metadata["algorithmName"]

	if family == "" && name == "" {
		return
	}

	oid := e.mapper.ResolveOID(asset)
	if oid != "" {
		asset.OID = oid
		log.Debug().
			Str("algorithmFamily", family).
			Str("algorithmName", name).
			Str("oid", oid).
			Msg("Enriched asset with OID")
	}
}

// EnrichReport enriches all cryptographic assets in an interim report with OIDs.
func (e *OIDEnricher) EnrichReport(report *entities.InterimReport) {
	if report == nil {
		return
	}

	enrichedCount := 0
	totalCount := 0

	for i := range report.Findings {
		for j := range report.Findings[i].CryptographicAssets {
			totalCount++
			asset := &report.Findings[i].CryptographicAssets[j]

			if asset.OID == "" {
				e.EnrichAsset(asset)
				if asset.OID != "" {
					enrichedCount++
				}
			}
		}
	}

	if enrichedCount > 0 {
		log.Info().
			Int("enriched", enrichedCount).
			Int("total", totalCount).
			Msg("OID enrichment complete")
	}
}
