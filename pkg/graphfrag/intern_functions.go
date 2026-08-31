// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "strconv"

// ExportInternedFunction is one identity record in the schema-6.14 functions[]
// catalog. It carries the stable callable identity that inlined call_chains
// frames repeat. Hop-specific fields (entry_call, crypto_call, entry_resolution)
// stay on the inlined frames and on the index lists only as integer positions.
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
	if id.FunctionKey != "" {
		return "k\x00" + id.FunctionKey
	}
	return "n\x00" + id.FunctionName + "\x00" + id.FilePath + "\x00" + strconv.Itoa(id.StartLine)
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
