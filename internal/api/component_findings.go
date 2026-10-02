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

package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/pkg/schema"
)

const (
	componentFindingsEndpoint = "/v3/cryptography/reachability/component"
	componentReady            = "READY"
)

// ComponentFindings is what the API publishes for one component version.
type ComponentFindings struct {
	// Version is the version the findings were mined from. The API may serve
	// the closest mined patch of the requested minor.
	Version      string
	RulesVersion string
	Findings     []schema.Finding
}

type componentRequest struct {
	Purl        string `json:"purl"`
	Requirement string `json:"requirement"`
}

type componentResponse struct {
	InfoCode     string `json:"info_code"`
	RulesVersion string `json:"rules_version"`
	Data         []struct {
		Version            string           `json:"version"`
		ActualMinedVersion string           `json:"actual_mined_version"`
		Findings           []schema.Finding `json:"findings"`
	} `json:"data"`
}

// ComponentFindings asks the API for the findings mined from purl at
// requirement. Asking for nothing but the purl and the requirement selects
// the findings-only answer, without reachability. It reports false when the
// API has no findings for that component.
func (c *Client) ComponentFindings(ctx context.Context, purl, requirement string) (*ComponentFindings, bool, error) {
	payload, err := json.Marshal(componentRequest{Purl: purl, Requirement: requirement})
	if err != nil {
		return nil, false, fmt.Errorf("apiclient: encode component request: %w", err)
	}
	url := c.baseURL + componentFindingsEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, false, fmt.Errorf("apiclient: create component request: %w", err)
	}
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set(headerUserAgent, userAgentValue)
	req.Header.Set("Content-Type", "application/json")

	// #nosec G704 -- URL is the configured API base URL plus a fixed endpoint.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("apiclient: component request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Msg("Failed to close component findings response")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, false, c.handleHTTPError(resp, url)
	}

	var body componentResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxComponentResponseBytes)).Decode(&body); err != nil {
		return nil, false, fmt.Errorf("apiclient: decode component response for %s: %w", purl, err)
	}
	if body.InfoCode != componentReady || len(body.Data) == 0 {
		return nil, false, nil
	}
	block := body.Data[0]
	version := block.Version
	if block.ActualMinedVersion != "" {
		version = block.ActualMinedVersion
	}
	return &ComponentFindings{Version: version, RulesVersion: body.RulesVersion, Findings: block.Findings}, true, nil
}

// maxComponentResponseBytes bounds one answer. The largest mined components
// answer with a few megabytes of findings.
const maxComponentResponseBytes = 256 << 20
