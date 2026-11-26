// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/failure"
)

const ecosystemPython = "python"

// pySharedLocks are the lock files scanoss.go's resolver reads, in the order
// they win.
var pySharedLocks = []string{"uv.lock", "poetry.lock", "Pipfile.lock"}

// PythonResolver resolves a Python project's pinned dependency closure from
// files only: no pip, no Python, no build backend. The first input that
// exists wins:
//
//  1. uv.lock, poetry.lock, Pipfile.lock (scanoss.go's resolver);
//  2. pdm.lock, pylock.toml (PEP 751), requirements files where every
//     requirement is pinned with ==. Pinned requirements give the versions
//     of what they list, and an installed environment (3), when there is
//     one, completes the closure with what they require: many projects pin
//     only their direct dependencies. Without one, the pins are the closure;
//  3. an installed environment (.venv, venv, VIRTUAL_ENV);
//  4. declared requirements only (pyproject.toml, Pipfile, requirements
//     files): == pins are dependencies, the rest are Unpinned.
//
// Environment markers and extras: the closure is the union of every marker
// branch and every extra a lock resolves (owner decision 2026-11-15); each
// dependency keeps its markers and extras for display. Development
// dependencies are left out, as test scope is for Java. Names are PEP 503
// normalised and versions kept as written (PEP 440, not normalised).
// Dependencies have no compiled artifact and no source directory, except in
// an installed environment, where Dir is site-packages and Files the RECORD.
type PythonResolver struct{}

// NewPythonResolver creates a Python resolver.
func NewPythonResolver() *PythonResolver {
	return &PythonResolver{}
}

// Ecosystem returns "python".
func (r *PythonResolver) Ecosystem() string {
	return ecosystemPython
}

// CanResolve reports whether targetDir holds a Python lock file, manifest or
// requirements file, or an environment to read.
func (r *PythonResolver) CanResolve(targetDir string) bool {
	for _, name := range append(append([]string{}, pySharedLocks...), "pdm.lock", "pyproject.toml", "Pipfile") {
		if fileExists(filepath.Join(targetDir, name)) {
			return true
		}
	}
	return len(pylockNames(targetDir)) > 0 || len(pyRequirementsFiles(targetDir)) > 0 || len(pyEnvironmentDirs(targetDir)) > 0
}

// Resolve returns the pinned closure of the project at targetDir. A lock
// file that exists but cannot be read is an error: it decides the closure,
// and reading the next input instead would report another one.
func (r *PythonResolver) Resolve(ctx context.Context, targetDir string) (*ResolveResult, error) {
	g, err := readPyClosure(ctx, targetDir)
	if err != nil {
		return nil, failure.New(failure.CodeDependencyResolutionFailed, failure.StageDependency,
			fmt.Sprintf("read the Python dependency closure of %s: %v", targetDir, err),
			failure.WithDetail("target_dir", targetDir))
	}
	if g == nil {
		return &ResolveResult{Graph: map[string][]string{}, VersionedGraph: map[string][]Ref{}}, nil
	}
	result := g.toResult()
	log.Debug().Str("source", result.Source).Int("dependencies", len(result.Dependencies)).
		Int("unpinned", len(result.Unpinned)).Msg("Resolved the Python dependency closure")
	return result, nil
}

func readPyClosure(ctx context.Context, dir string) (*pyGraph, error) {
	for _, name := range pySharedLocks {
		if fileExists(filepath.Join(dir, name)) {
			return readSharedPyLock(ctx, dir, name)
		}
	}
	if fileExists(filepath.Join(dir, "pdm.lock")) {
		return readPdmLock(dir)
	}
	if names := pylockNames(dir); len(names) > 0 {
		return readPylock(dir, names)
	}
	if g, ok := readPinnedRequirements(dir); ok {
		site := pyEnvironmentSite(dir)
		if added := completeFromEnvironment(g, site); added > 0 {
			log.Info().Str("source", g.source).Str("environment", site).Int("added", added).
				Msg("Completed the pinned requirements' closure from the installed environment")
		}
		return g, nil
	}
	if g, ok := readPyEnvironment(dir); ok {
		return g, nil
	}
	if g, ok := readDeclaredPy(dir); ok {
		return g, nil
	}
	return nil, nil
}
