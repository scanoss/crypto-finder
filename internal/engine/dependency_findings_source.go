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
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package engine

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/rs/zerolog/log"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// apiRulesSource names the SCANOSS API as the origin of a dependency report.
const apiRulesSource = "scanoss-api"

// DependencyFindingsSource publishes findings per package version. A
// dependency scan uses them in place of detection when the findings cache
// holds none; the call graph and reachability are still built locally.
type DependencyFindingsSource interface {
	// Findings returns the findings published for the versionless purl at
	// version, or false when the source has none.
	Findings(ctx context.Context, purl, version string) (*entities.InterimReport, bool, error)
}

// DependencyScannerOption configures a DependencyScanner.
type DependencyScannerOption func(*DependencyScanner)

// WithDependencyFindingsSource consults source for a dependency the findings
// cache does not hold, before scanning it.
func WithDependencyFindingsSource(source DependencyFindingsSource) DependencyScannerOption {
	return func(ds *DependencyScanner) { ds.findingsSource = source }
}

type componentFindingsAPI interface {
	ComponentFindings(ctx context.Context, purl, requirement string) (*apiclient.ComponentFindings, bool, error)
}

// APIFindingsSource reads the findings the SCANOSS mining service published
// for a component. Its answer for a purl and version is taken as it is,
// including the closest mined patch the API serves for that version.
type APIFindingsSource struct {
	api    componentFindingsAPI
	denied atomic.Bool
}

// NewAPIFindingsSource returns a source backed by api.
func NewAPIFindingsSource(api componentFindingsAPI) *APIFindingsSource {
	return &APIFindingsSource{api: api}
}

// Findings implements DependencyFindingsSource. Once the API refuses the
// credentials, or does not offer the endpoint at all, the source answers
// "none" without asking again, so either costs one request per scan, not one
// per dependency. A component the API has not mined is a 200, not a 404.
func (s *APIFindingsSource) Findings(ctx context.Context, purl, version string) (*entities.InterimReport, bool, error) {
	if s.denied.Load() {
		return nil, false, nil
	}
	answer, found, err := s.api.ComponentFindings(ctx, purl, version)
	switch {
	case errors.Is(err, apiclient.ErrUnauthorized) || errors.Is(err, apiclient.ErrForbidden):
		s.stopAsking(err, "The SCANOSS API refused dependency findings for this API key; dependencies are scanned locally")
		return nil, false, nil
	case errors.Is(err, apiclient.ErrNotFound):
		s.stopAsking(err, "The SCANOSS API does not offer dependency findings; dependencies are scanned locally")
		return nil, false, nil
	}
	if err != nil || !found {
		return nil, false, err
	}
	return &entities.InterimReport{
		Version:  "1.0",
		Tool:     entities.ToolInfo{Name: apiRulesSource},
		Rules:    entities.RulesInfo{Source: apiRulesSource, Version: answer.RulesVersion},
		Findings: answer.Findings,
	}, true, nil
}

// stopAsking turns the source off for the rest of the scan and warns once.
func (s *APIFindingsSource) stopAsking(err error, message string) {
	if !s.denied.Swap(true) {
		log.Warn().Err(err).Msg(message)
	}
}
