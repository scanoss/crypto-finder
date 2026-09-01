// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"strconv"
	"strings"
)

// ExportInternedFunction is one identity record in the functions[] catalog.
// Schema 6.15 keeps this as the join surface for call-chain frames; hop-specific
// fields (entry_call, crypto_call, entry_resolution) stay on the frames.
type ExportInternedFunction struct {
	FunctionKey        string                `json:"function_key,omitempty"`
	FunctionName       string                `json:"function_name"`
	CanonicalSignature string                `json:"canonical_signature,omitempty"`
	ReturnType         string                `json:"return_type,omitempty"`
	ParameterTypes     []string              `json:"parameter_types,omitempty"`
	Visibility         string                `json:"visibility,omitempty"`
	OwnerVisibility    string                `json:"owner_visibility,omitempty"`
	DisplaySymbol      string                `json:"display_symbol,omitempty"`
	Aliases            []string              `json:"aliases,omitempty"`
	FilePath           string                `json:"file_path"`
	StartLine          int                   `json:"start_line,omitempty"`
	DependencyInfo     *ExportDependencyInfo `json:"dependency_info,omitempty"`
}

// FrameIdentity is the intern key and catalog payload for one call-chain frame.
type FrameIdentity struct {
	FunctionKey        string
	FunctionName       string
	CanonicalSignature string
	ReturnType         string
	ParameterTypes     []string
	Visibility         string
	OwnerVisibility    string
	DisplaySymbol      string
	Aliases            []string
	FilePath           string
	StartLine          int
	DependencyInfo     *ExportDependencyInfo
}

// FunctionInterner assigns stable 0-based indexes to frame identities in first-
// seen order. Live export and stitch share this so the same N-sample of routes
// intern the same way.
type FunctionInterner struct {
	index map[string]int
	items []ExportInternedFunction
}

// IdentityFromChainNode copies interned identity fields from an inlined frame.
func IdentityFromChainNode(n ExportChainNode) FrameIdentity {
	return FrameIdentity{
		FunctionKey:        n.FunctionKey,
		FunctionName:       n.FunctionName,
		CanonicalSignature: n.CanonicalSignature,
		ReturnType:         n.ReturnType,
		ParameterTypes:     n.ParameterTypes,
		Visibility:         n.Visibility,
		OwnerVisibility:    n.OwnerVisibility,
		DisplaySymbol:      n.DisplaySymbol,
		Aliases:            n.Aliases,
		FilePath:           n.FilePath,
		StartLine:          n.StartLine,
		DependencyInfo:     n.DependencyInfo,
	}
}

func internKey(id FrameIdentity) string {
	var b strings.Builder
	b.WriteString(id.FunctionKey)
	b.WriteByte(0)
	b.WriteString(id.FunctionName)
	b.WriteByte(0)
	b.WriteString(id.FilePath)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(id.StartLine))
	if id.DependencyInfo != nil {
		b.WriteByte(0)
		b.WriteString(id.DependencyInfo.Module)
		b.WriteByte(0)
		b.WriteString(id.DependencyInfo.Version)
		b.WriteByte(0)
		b.WriteString(id.DependencyInfo.PURL)
	}
	return b.String()
}

// Intern records id on first sight and returns its catalog index.
func (c *FunctionInterner) Intern(id FrameIdentity) int {
	if c.index == nil {
		c.index = make(map[string]int)
	}
	key := internKey(id)
	if i, ok := c.index[key]; ok {
		return i
	}
	item := ExportInternedFunction{
		FunctionKey:        id.FunctionKey,
		FunctionName:       id.FunctionName,
		CanonicalSignature: id.CanonicalSignature,
		ReturnType:         id.ReturnType,
		ParameterTypes:     append([]string(nil), id.ParameterTypes...),
		Visibility:         id.Visibility,
		OwnerVisibility:    id.OwnerVisibility,
		DisplaySymbol:      id.DisplaySymbol,
		Aliases:            append([]string(nil), id.Aliases...),
		FilePath:           id.FilePath,
		StartLine:          id.StartLine,
		DependencyInfo:     cloneExportDependencyInfo(id.DependencyInfo),
	}
	i := len(c.items)
	c.index[key] = i
	c.items = append(c.items, item)
	return i
}

func cloneExportDependencyInfo(in *ExportDependencyInfo) *ExportDependencyInfo {
	if in == nil {
		return nil
	}
	cp := *in
	return &cp
}

// InternChains maps each inlined chain onto catalog indexes.
func (c *FunctionInterner) InternChains(chains [][]ExportChainNode) [][]int {
	if len(chains) == 0 {
		return nil
	}
	out := make([][]int, len(chains))
	for i, chain := range chains {
		idx := make([]int, len(chain))
		for j := range chain {
			idx[j] = c.Intern(IdentityFromChainNode(chain[j]))
		}
		out[i] = idx
	}
	return out
}

// Functions returns the catalog in intern order.
func (c *FunctionInterner) Functions() []ExportInternedFunction {
	if len(c.items) == 0 {
		return []ExportInternedFunction{}
	}
	out := make([]ExportInternedFunction, len(c.items))
	copy(out, c.items)
	return out
}

// ContractChainIdentities clears interned identity fields from frames so the
// catalog plus call_chain_indexes are the only copy of function identity.
func ContractChainIdentities(chains [][]ExportChainNode) {
	for i := range chains {
		for j := range chains[i] {
			n := &chains[i][j]
			n.FunctionKey = ""
			n.FunctionName = ""
			n.CanonicalSignature = ""
			n.ReturnType = ""
			n.ParameterTypes = nil
			n.Visibility = ""
			n.OwnerVisibility = ""
			n.DisplaySymbol = ""
			n.Aliases = nil
			n.FilePath = ""
			n.StartLine = 0
			n.DependencyInfo = nil
		}
	}
}

// applyCatalogIdentity copies interned identity onto a chain frame. Hop fields
// (entry_call, crypto_call, entry_resolution) are left untouched.
func applyCatalogIdentity(n *ExportChainNode, id ExportInternedFunction) {
	n.FunctionKey = id.FunctionKey
	n.FunctionName = id.FunctionName
	n.CanonicalSignature = id.CanonicalSignature
	n.ReturnType = id.ReturnType
	n.ParameterTypes = append([]string(nil), id.ParameterTypes...)
	n.Visibility = id.Visibility
	n.OwnerVisibility = id.OwnerVisibility
	n.DisplaySymbol = id.DisplaySymbol
	n.Aliases = append([]string(nil), id.Aliases...)
	n.FilePath = id.FilePath
	n.StartLine = id.StartLine
	n.DependencyInfo = cloneExportDependencyInfo(id.DependencyInfo)
}

// HydrateChainIdentities copies catalog identity onto frames whose function_name
// and canonical_signature are empty. Inlined 6.14 frames are left unchanged.
// An empty index list is treated as inlined (no-op, true). Returns false when
// indexes exist but do not reconstruct the same routes.
func HydrateChainIdentities(catalog []ExportInternedFunction, chains [][]ExportChainNode, indexes [][]int) bool {
	if len(indexes) == 0 {
		return true
	}
	rebuilt, ok := ReconstructChainIdentities(catalog, indexes)
	if !ok || len(rebuilt) != len(chains) {
		return false
	}
	for i := range chains {
		if len(rebuilt[i]) != len(chains[i]) {
			return false
		}
		for j := range chains[i] {
			n := &chains[i][j]
			if n.FunctionName != "" || n.CanonicalSignature != "" {
				continue
			}
			applyCatalogIdentity(n, rebuilt[i][j])
		}
	}
	return true
}

// HydrateChainIdentities fills empty frame identity from Functions and each
// finding's call_chain_indexes. Returns false if any finding's indexes are
// present but invalid.
func (c *CallgraphExport) HydrateChainIdentities() bool {
	if c == nil {
		return true
	}
	ok := true
	for i := range c.FindingGraphs {
		if !HydrateChainIdentities(c.Functions, c.FindingGraphs[i].CallChains, c.FindingGraphs[i].CallChainIndexes) {
			ok = false
		}
	}
	return ok
}

// ReconstructChainIdentities rebuilds each route from catalog indexes.
func ReconstructChainIdentities(catalog []ExportInternedFunction, indexes [][]int) ([][]ExportInternedFunction, bool) {
	out := make([][]ExportInternedFunction, len(indexes))
	for i, route := range indexes {
		frames := make([]ExportInternedFunction, len(route))
		for j, idx := range route {
			if idx < 0 || idx >= len(catalog) {
				return nil, false
			}
			frames[j] = catalog[idx]
		}
		out[i] = frames
	}
	return out, true
}
