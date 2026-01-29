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

package enricher

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/converter"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestNewOIDEnricher(t *testing.T) {
	enricher := NewOIDEnricher()
	if enricher == nil {
		t.Fatal("NewOIDEnricher() returned nil")
	}
	if enricher.mapper == nil {
		t.Error("OIDMapper is nil")
	}
}

func TestOIDEnricher_EnrichAsset(t *testing.T) {
	enricher := NewOIDEnricher()

	tests := []struct {
		name         string
		initialOID   string
		family       string
		algoName     string
		paramSet     string
		mode         string
		expectedOID  string
		shouldEnrich bool
	}{
		{
			name:         "Enrich AES-128-CBC",
			initialOID:   "",
			family:       "AES",
			algoName:     "AES-128-CBC",
			paramSet:     "128",
			mode:         "CBC",
			expectedOID:  converter.OIDAES128CBC,
			shouldEnrich: true,
		},
		{
			name:         "Enrich SHA-256",
			initialOID:   "",
			family:       "SHA",
			algoName:     "SHA-256",
			paramSet:     "256",
			mode:         "",
			expectedOID:  converter.OIDSHA256,
			shouldEnrich: true,
		},
		{
			name:         "Enrich RSA family only",
			initialOID:   "",
			family:       "RSA",
			algoName:     "",
			paramSet:     "2048",
			mode:         "",
			expectedOID:  converter.OIDRSA,
			shouldEnrich: true,
		},
		{
			name:         "Skip - already has OID",
			initialOID:   "1.2.3.4.5",
			family:       "AES",
			algoName:     "AES-128-CBC",
			paramSet:     "128",
			mode:         "CBC",
			expectedOID:  "1.2.3.4.5", // Should keep existing OID
			shouldEnrich: false,
		},
		{
			name:         "Skip - no algorithm metadata",
			initialOID:   "",
			family:       "",
			algoName:     "",
			paramSet:     "",
			mode:         "",
			expectedOID:  "",
			shouldEnrich: false,
		},
		{
			name:         "Skip - unknown algorithm",
			initialOID:   "",
			family:       "UNKNOWN",
			algoName:     "UNKNOWN-999",
			paramSet:     "999",
			mode:         "XYZ",
			expectedOID:  "",
			shouldEnrich: false,
		},
		{
			name:         "Enrich ECDSA-SHA256",
			initialOID:   "",
			family:       "ECDSA",
			algoName:     "ECDSA-SHA256",
			paramSet:     "",
			mode:         "",
			expectedOID:  converter.OIDECDSASHA256,
			shouldEnrich: true,
		},
		{
			name:         "Enrich HMAC-SHA256",
			initialOID:   "",
			family:       "",
			algoName:     "HMAC-SHA256",
			paramSet:     "",
			mode:         "",
			expectedOID:  converter.OIDHMACSHA256,
			shouldEnrich: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				OID: tt.initialOID,
				Metadata: map[string]string{
					"algorithmFamily":                 tt.family,
					"algorithmName":                   tt.algoName,
					"algorithmParameterSetIdentifier": tt.paramSet,
					"algorithmMode":                   tt.mode,
				},
			}

			enricher.EnrichAsset(asset)

			if asset.OID != tt.expectedOID {
				t.Errorf("OID = %q, want %q", asset.OID, tt.expectedOID)
			}
		})
	}
}

func TestOIDEnricher_EnrichAsset_PreservesExistingOID(t *testing.T) {
	enricher := NewOIDEnricher()

	// Create asset with existing OID (even if it's wrong/legacy)
	asset := &entities.CryptographicAsset{
		OID: "1.2.3.4.5.6.7.8.9", // Some custom/wrong OID
		Metadata: map[string]string{
			"algorithmFamily": "AES",
			"algorithmName":   "AES-128-CBC",
		},
	}

	enricher.EnrichAsset(asset)

	// Should preserve the existing OID
	if asset.OID != "1.2.3.4.5.6.7.8.9" {
		t.Errorf("Existing OID was overwritten: got %q, want %q", asset.OID, "1.2.3.4.5.6.7.8.9")
	}
}

func TestOIDEnricher_EnrichReport(t *testing.T) {
	enricher := NewOIDEnricher()

	report := &entities.InterimReport{
		Version: "1.1",
		Tool: entities.ToolInfo{
			Name:    "test",
			Version: "1.0",
		},
		Findings: []entities.Finding{
			{
				FilePath: "test1.go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						OID: "", // Will be enriched
						Metadata: map[string]string{
							"algorithmFamily": "AES",
							"algorithmName":   "AES-256-GCM",
						},
					},
					{
						OID: converter.OIDSHA256, // Already has OID
						Metadata: map[string]string{
							"algorithmFamily": "SHA",
							"algorithmName":   "SHA-256",
						},
					},
				},
			},
			{
				FilePath: "test2.go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						OID: "", // Will be enriched
						Metadata: map[string]string{
							"algorithmFamily": "RSA",
						},
					},
					{
						OID: "", // Unknown algorithm, won't be enriched
						Metadata: map[string]string{
							"algorithmFamily": "UNKNOWN",
						},
					},
				},
			},
		},
	}

	enricher.EnrichReport(report)

	// Check that AES-256-GCM was enriched
	if report.Findings[0].CryptographicAssets[0].OID != converter.OIDAES256GCM {
		t.Errorf("AES-256-GCM not enriched: got %q, want %q",
			report.Findings[0].CryptographicAssets[0].OID,
			converter.OIDAES256GCM)
	}

	// Check that SHA-256 OID was preserved (not changed)
	if report.Findings[0].CryptographicAssets[1].OID != converter.OIDSHA256 {
		t.Errorf("SHA-256 OID was changed: got %q, want %q",
			report.Findings[0].CryptographicAssets[1].OID,
			converter.OIDSHA256)
	}

	// Check that RSA was enriched
	if report.Findings[1].CryptographicAssets[0].OID != converter.OIDRSA {
		t.Errorf("RSA not enriched: got %q, want %q",
			report.Findings[1].CryptographicAssets[0].OID,
			converter.OIDRSA)
	}

	// Check that UNKNOWN algorithm was not enriched
	if report.Findings[1].CryptographicAssets[1].OID != "" {
		t.Errorf("Unknown algorithm should not have OID: got %q",
			report.Findings[1].CryptographicAssets[1].OID)
	}
}

func TestOIDEnricher_EnrichReport_NilReport(_ *testing.T) {
	enricher := NewOIDEnricher()

	// Should not panic
	enricher.EnrichReport(nil)
}

func TestOIDEnricher_EnrichReport_EmptyReport(_ *testing.T) {
	enricher := NewOIDEnricher()

	report := &entities.InterimReport{
		Version:  "1.1",
		Findings: []entities.Finding{},
	}

	// Should not panic
	enricher.EnrichReport(report)
}
