// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package scanner defines legacy and optional scanner interfaces.
package scanner

import (
	"context"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// OutcomeScanner is optional. Legacy/custom adapters need not implement it.
type OutcomeScanner interface {
	ScanWithOutcome(context.Context, string, []string, entities.ToolInfo) (Outcome, error)
}

// Outcome pairs one report with its native invocation. ScopedComplete does not
// establish immutable inputs, complete crypto coverage, owned graphs or safe reuse.
// Raw diagnostics can contain private source paths. They are not public exports.
type Outcome struct {
	Report         *entities.InterimReport
	ScopedComplete bool
	Reason         string
	Scanner        string
	Version        string
	Argv           []string
	Stdout         []byte
	Stderr         string
	ExitCode       int
	ExitAvailable  bool
}
