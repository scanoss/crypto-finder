// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"bytes"
	"encoding/json"
	"fmt"

	gf "github.com/scanoss/reach/graphfrag"
)

// producerGraphPrefix starts a structural graph as crypto-finder writes it
// (graphfrag.StructuralExport of a graph-fragment document): schema_version
// first.
var producerGraphPrefix = []byte(`{"schema_version":`)

// IsProducerGraph reports whether raw is a structural graph-fragment document
// rather than another stored graph form.
func IsProducerGraph(raw []byte) bool {
	return bytes.HasPrefix(raw, producerGraphPrefix)
}

// producerGraph is the part of a graph-fragment document the stitch model reads
// (see gf.GraphFragmentExport.ToFragment). The document also carries what a
// detector needs to re-match rules without the source (source_lines,
// constant_refs, declarations, casts, call_anchors, external_signatures);
// leaving those fields out of the struct skips them while decoding, so serving
// a graph costs no more memory than the stitch model it builds.
type producerGraph struct {
	ScanMetadata         gf.GraphFragmentScanMetadata  `json:"scan_metadata"`
	Functions            []gf.GraphFragmentFunction    `json:"functions"`
	InternalEdges        []gf.GraphFragmentEdge        `json:"internal_edges,omitempty"`
	InternalEdgeStrings  []string                      `json:"internal_edge_strings,omitempty"`
	CompactInternalEdges []gf.GraphFragmentCompactEdge `json:"internal_edges_compact,omitempty"`
	ExternalCalls        []gf.GraphFragmentExternal    `json:"external_calls,omitempty"`
	Supertypes           map[string][]string           `json:"supertypes,omitempty"`
	Exports              map[string]string             `json:"exports,omitempty"`
	ServiceProviders     map[string][]string           `json:"service_providers,omitempty"`
}

// DecodeProducerGraph turns a structural graph-fragment document into the
// structural half of a Fragment, as gf.DecodeFragment decodes it, so it
// carries the entry kinds and supertypes.
func DecodeProducerGraph(k ComponentKey, raw []byte) (*Fragment, error) {
	var doc producerGraph
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode code graph %s: %w", k, err)
	}
	export := gf.GraphFragmentExport{
		ScanMetadata:         doc.ScanMetadata,
		Functions:            doc.Functions,
		InternalEdges:        doc.InternalEdges,
		InternalEdgeStrings:  doc.InternalEdgeStrings,
		CompactInternalEdges: doc.CompactInternalEdges,
		ExternalCalls:        doc.ExternalCalls,
		Supertypes:           doc.Supertypes,
		Exports:              doc.Exports,
		ServiceProviders:     doc.ServiceProviders,
	}
	frag := export.ToFragment(k)
	return &frag, nil
}
