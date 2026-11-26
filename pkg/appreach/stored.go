// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/scanoss/crypto-finder/pkg/pqc"
)

// A component's stored findings report is the crypto-finder report scanning
// the component itself produced (the miner stores it, the offline client
// caches it). Served as is, it keeps what an annotation does not carry:
// columns, status, every rule with its message and severity, occurrence_key,
// conditioned_value and the scan's own finding_id.

// crypto-finder names a dependency's asset "dependency"; the API's published
// source vocabulary (direct / indirect) calls it "indirect".
const (
	storedSourceDependency = "dependency"
	// SourceIndirect is the served source of a finding in a dependency.
	SourceIndirect = "indirect"

	sourceDirect = "direct"
)

// ErrNoStoredReport is returned when the component has no usable findings payload.
var ErrNoStoredReport = errors.New("no stored findings report")

// storedReport is the part of crypto-finder's report (InterimReport) the
// response serves. Findings stays raw so a missing key is told apart from an
// empty list.
type storedReport struct {
	Version  string          `json:"version"`
	Findings json.RawMessage `json:"findings"`
}

type storedFile struct {
	FilePath            string                   `json:"file_path"`
	Language            string                   `json:"language"`
	CryptographicAssets []*CryptographicAssetDTO `json:"cryptographic_assets"`
}

// StoredFindings is a stored report projected into a response block.
type StoredFindings struct {
	Findings []*FindingDTO
	// Count is the number of cryptographic assets, as finding_count is on
	// every other path.
	Count int
	// Schema is the report's own version, or the stored schema column when
	// the report does not state one.
	Schema string
}

// DecodeStoredReport projects a stored report. A payload that is absent, not
// a report, or newer than this binary reads is an error, so the caller falls
// back to the annotation-rendered findings. schemaColumn is the schema the
// store recorded beside the payload, used when the report states none.
func DecodeStoredReport(payload []byte, schemaColumn string) (StoredFindings, error) {
	if len(payload) == 0 || string(payload) == "null" {
		return StoredFindings{}, ErrNoStoredReport
	}
	var report storedReport
	if err := json.Unmarshal(payload, &report); err != nil {
		return StoredFindings{}, fmt.Errorf("decode stored findings: %w", err)
	}
	if len(report.Findings) == 0 {
		return StoredFindings{}, fmt.Errorf("%w: payload has no findings", ErrNoStoredReport)
	}
	schema := report.Version
	if schema == "" {
		schema = schemaColumn
	}
	if err := ValidateSchemaVersion("findings", schema, FindingsSchemaVersion); err != nil {
		return StoredFindings{}, err
	}
	var files []storedFile
	if err := json.Unmarshal(report.Findings, &files); err != nil {
		return StoredFindings{}, fmt.Errorf("decode stored findings: %w", err)
	}

	out := StoredFindings{Findings: make([]*FindingDTO, 0, len(files)), Schema: schema}
	for _, file := range files {
		if len(file.CryptographicAssets) == 0 {
			continue
		}
		finding := &FindingDTO{
			FilePath:            file.FilePath,
			Language:            file.Language,
			CryptographicAssets: file.CryptographicAssets,
		}
		for _, asset := range file.CryptographicAssets {
			asset.PQC = pqc.Current(asset.PQC, asset.Metadata)
			if asset.Source == storedSourceDependency {
				asset.Source = SourceIndirect
			}
			// The file-level dependency_info every block has always carried.
			if finding.DependencyInfo == nil && asset.DependencyInfo != nil {
				dep := *asset.DependencyInfo
				finding.DependencyInfo = &dep
			}
		}
		out.Findings = append(out.Findings, finding)
		out.Count += len(file.CryptographicAssets)
	}
	return out, nil
}
