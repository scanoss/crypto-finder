// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package boundary names the engine/domain boundary of crypto-finder.
//
// The ENGINE is the language-agnostic reachability machinery: call graph
// construction and its contracts loader, the graph-fragment model, stitcher
// and renderers, and the packages they need. It lives in its own module,
// github.com/scanoss/reach (EngineModule), which imports nothing from
// crypto-finder and guards that itself. crypto-finder is the DOMAIN (crypto
// detection and reporting: cards, rules, the crypto KB, OIDs, PQC, key length
// and material) and the CLIENT (CLI, configuration, API, cache, offline,
// dependency resolution, output), built on the engine. boundary_test.go fails
// when an engine package reappears inside crypto-finder.
package boundary

// Module is the module path every package below is relative to.
const Module = "github.com/scanoss/crypto-finder"

// EngineModule is the module the engine lives in.
const EngineModule = "github.com/scanoss/reach"

// MovedEnginePackages are the module-relative paths the engine packages had
// in crypto-finder before they moved to EngineModule, each with its path
// there. No package may live at these paths again: engine changes go to
// reach.
var MovedEnginePackages = map[string]string{
	"internal/callgraph":             EngineModule + "/callgraph",
	"internal/callgraph/contracts":   EngineModule + "/callgraph/contracts",
	"internal/callgraph/entrypoints": EngineModule + "/callgraph/entrypoints",
	"internal/javaruntime":           EngineModule + "/javaruntime",
	"internal/language":              EngineModule + "/language",
	"internal/perf":                  EngineModule + "/perf",
	"internal/skip":                  EngineModule + "/skip",
	"pkg/graphfrag":                  EngineModule + "/graphfrag",
	"pkg/graphfrag/equiv":            EngineModule + "/graphfrag/equiv",
	"pkg/graphwalk":                  EngineModule + "/graphwalk",
	"pkg/paramcondition":             EngineModule + "/paramcondition",
	"pkg/purl":                       EngineModule + "/purl",
}
