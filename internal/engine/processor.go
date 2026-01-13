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

package engine

import (
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/version"
)

// Processor handles result aggregation and enrichment.
// For MVP, it performs basic validation and metadata enrichment.
type Processor struct{}

// NewProcessor creates a new result processor.
func NewProcessor() *Processor {
	return &Processor{}
}

// Process enriches and validates the scan results.
//
// Current processing:
//   - Validates report structure
//   - Ensures all required fields are present
func (p *Processor) Process(report *entities.InterimReport, _ []string) (*entities.InterimReport, error) {
	if report == nil {
		// Return empty report if scanner found nothing
		return &entities.InterimReport{
			Version:  "1.0",
			Tool:     entities.ToolInfo{Name: version.ToolName, Version: version.Version},
			Findings: []entities.Finding{},
		}, nil
	}

	// Validate report structure
	if report.Version == "" {
		report.Version = "1.0"
	}

	if report.Findings == nil {
		report.Findings = []entities.Finding{}
	}

	return report, nil
}
