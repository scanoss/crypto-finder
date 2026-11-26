// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package graphalgoguard holds the graph algorithm version guard, a test with
// no package code: it scans a small corpus per ecosystem with crypto-finder's
// scanner and fails when the structural graph that consumers cache under
// github.com/scanoss/reach/graphfrag's GraphAlgoVersion (or
// GraphAlgoVersionPython, GraphAlgoVersionGo) changes while that id stays the same. The ids live
// in reach; the guard lives here because it drives crypto-finder's scan.
package graphalgoguard
