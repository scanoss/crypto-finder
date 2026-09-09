// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package enricher provides OID enrichment after finding materialization.
package enricher

import (
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// OIDEnricher applies the exact-only OID resolver. Supplied OIDs are claims, not facts.
type OIDEnricher struct {
	resolver *oid.Resolver
	mapper   any
}

// NewOIDEnricher creates an exact-only OID enricher.
func NewOIDEnricher() *OIDEnricher {
	return &OIDEnricher{resolver: oid.NewDefaultResolver(), mapper: struct{}{}}
}

// EnrichAsset resolves a single asset through the same exact-only policy used for reports.
func (e *OIDEnricher) EnrichAsset(asset *entities.CryptographicAsset) {
	if asset == nil {
		return
	}
	result := e.resolver.ResolveAsset(asset)
	asset.OID = result.OID
}

// PrepareReport is the sole report-level compatibility seam. It never writes a
// resolved clone back into an InterimReport: callers must pass the opaque
// prepared result to a projection, so raw reports cannot be mistaken for final
// OID evidence.
func (e *OIDEnricher) PrepareReport(report *entities.InterimReport) (*oid.PreparedReport, error) {
	if report == nil {
		return nil, nil
	}
	return e.resolver.PrepareReport(report)
}
