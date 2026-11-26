// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package appreach decides, for every finding of an application's pinned
// dependency closure, whether the application's call sites reach it, and renders
// the answer as the SCANOSS API's /v3/cryptography/reachability/application
// response. It is the one implementation behind both modes of a dependency
// scan: the API runs it over the graphs and findings its miners stored, and
// the offline client runs it in process over the dependencies it mined
// itself. The callers own where the components come from; this package owns
// the request validation, the stitch policy, the verdicts, the conditioned
// expansion and the response.
//
// It also holds the response block renderer the API's /component and
// /dep-tree endpoints share (ComponentBlock), since the project response
// renders its findings the same way.
package appreach
