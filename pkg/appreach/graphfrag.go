// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import gf "github.com/scanoss/reach/graphfrag"

// The stitch model and its wire schemas, under the names this package's code
// reads (the same types, not copies).
type (
	// ComponentKey is the identity of a component in a stitch.
	ComponentKey = gf.ComponentKey
	// DependencyGraph is the dependency graph a stitch walks.
	DependencyGraph = gf.DependencyGraph
	// Fragment is the graph fragment of one component.
	Fragment = gf.Fragment
	// Function is a function of a fragment.
	Function = gf.Function
	// InternalEdge is a call between two functions of a fragment.
	InternalEdge = gf.InternalEdge
	// ExternalCall is a call of a fragment that leaves it.
	ExternalCall = gf.ExternalCall
	// CryptoOperation is a cryptographic operation of a fragment.
	CryptoOperation = gf.CryptoOperation
	// SupportingCall is a call that supports a cryptographic operation.
	SupportingCall = gf.SupportingCall
	// CryptoEntryPoint is an entry point that reaches a cryptographic operation.
	CryptoEntryPoint = gf.CryptoEntryPoint
	// ExportChainNode is a node of an exported call chain.
	ExportChainNode = gf.ExportChainNode
	// ScanMeta is the scan metadata of a call graph export.
	ScanMeta = gf.ScanMeta
	// CallgraphExport is the interned call graph a stitch exports.
	CallgraphExport = gf.CallgraphExport
	// ExportInternedFunction is a function of the interned call graph export.
	ExportInternedFunction = gf.ExportInternedFunction
	// ExportFindingGraph is the call chains of one finding in the call graph export.
	ExportFindingGraph = gf.ExportFindingGraph
	// StitchOptions is the options of a stitch.
	StitchOptions = gf.StitchOptions
	// Result is the result of a stitch.
	Result = gf.Result
)

// Schema versions owned by the graph-fragment contract.
const (
	SchemaVersion                  = gf.SchemaVersion
	CallgraphSchemaVersion         = gf.CallgraphSchemaVersion
	CallgraphInternedSchemaVersion = gf.CallgraphInternedSchemaVersion
)

// HydrateChainIdentities copies catalog identity onto frames whose
// function_name and canonical_signature are empty.
func HydrateChainIdentities(catalog []ExportInternedFunction, chains [][]ExportChainNode, indexes [][]int) bool {
	return gf.HydrateChainIdentities(catalog, chains, indexes)
}
