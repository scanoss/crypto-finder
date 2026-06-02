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

package graphfrag

import "encoding/json"

// FindingsSchemaVersion is the findings.json envelope version emitted by
// ToFindingsEnvelope. It matches the schema crypto-finder's scanner writes so
// downstream consumers see a uniform `version` regardless of whether the
// findings came from a live scan or were reconstructed from graph fragments.
const FindingsSchemaVersion = "1.3"

// FindingsEnvelope is the findings.json v1.3 envelope reconstructed from a
// dependency closure of graph fragments. It is the asset-metadata companion to
// ToCallgraphExport: the serving layer joins assets (here) to call chains
// (callgraph export) by finding_id, so the two MUST agree on finding_id — which
// they do by construction, since both derive it from the same CryptoOperation
// fields via computeFindingID/depPrefixedPath.
type FindingsEnvelope struct {
	Version  string        `json:"version"`
	Findings []FindingFile `json:"findings"`
}

// FindingFile is one file-level grouping in the envelope, mirroring a
// findings.json `findings[]` entry.
type FindingFile struct {
	Language            string         `json:"language"`
	FilePath            string         `json:"file_path"`
	CryptographicAssets []FindingAsset `json:"cryptographic_assets"`
}

// FindingAsset is one cryptographic asset, mirroring a findings.json
// `cryptographic_assets[]` entry. Metadata is the verbatim camelCase block.
type FindingAsset struct {
	FindingID string          `json:"finding_id"`
	OID       string          `json:"oid,omitempty"`
	Match     string          `json:"match"`
	Source    string          `json:"source"`
	StartLine int             `json:"start_line"`
	EndLine   int             `json:"end_line"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// ToFindingsEnvelope reconstructs the findings.json v1.3 envelope for the root
// component and its transitive dependency closure, from the stored crypto
// annotations in each fragment. Unlike ToCallgraphExport (which emits only
// reachable findings), this emits EVERY crypto operation in the closure —
// reachability decoration is the serving layer's job.
//
// finding_id, file_path, and source are computed to match a live
// `--scan-dependencies` run:
//   - root-component ops: unprefixed file_path, source="direct".
//   - dependency ops: file_path prefixed with "module@version/", source="indirect".
//
// finding_id is computed with the SAME inputs as ToCallgraphExport
// (computeFindingID over the resolved path + start_line + rule_id), so the
// serving layer's asset->call_chains join by finding_id holds.
func ToFindingsEnvelope(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, meta ScanMeta) FindingsEnvelope {
	closure := dependencyClosure(root, deps)

	// Group assets by (resolved) file path, preserving first-seen order so the
	// output is deterministic.
	var order []string
	byPath := make(map[string][]FindingAsset)

	for _, key := range closure {
		frag := fragments[key]
		isRoot := key == root
		for i := range frag.CryptoOperations {
			op := &frag.CryptoOperations[i]

			path := op.FilePath
			source := "direct"
			if !isRoot {
				path = depPrefixedPath(op.FilePath, frag.Module, key.Version)
				source = "indirect"
			}

			asset := FindingAsset{
				FindingID: computeFindingID(path, op.StartLine, op.RuleID),
				OID:       op.OID,
				Match:     op.Match,
				Source:    source,
				StartLine: op.StartLine,
				EndLine:   op.EndLine,
				Metadata:  op.Metadata,
			}
			if _, ok := byPath[path]; !ok {
				order = append(order, path)
			}
			byPath[path] = append(byPath[path], asset)
		}
	}

	env := FindingsEnvelope{Version: FindingsSchemaVersion}
	for _, p := range order {
		env.Findings = append(env.Findings, FindingFile{
			Language:            meta.Ecosystem,
			FilePath:            p,
			CryptographicAssets: byPath[p],
		})
	}
	return env
}
