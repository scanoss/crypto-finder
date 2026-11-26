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
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/pkg/conditioned"
	"github.com/scanoss/crypto-finder/pkg/schema"
)

const (
	applicationReachabilityEndpoint = "/v3/cryptography/reachability/application"
	// ApplicationReachabilitySchemaVersion is the request schema of
	// /reachability/application this client speaks.
	ApplicationReachabilitySchemaVersion = "1"
	// maxApplicationResponseBytes bounds one answer: every finding of every
	// pinned dependency, with call chains when asked for.
	maxApplicationResponseBytes = 1 << 30
)

// ApplicationDependency is one member of the project's pinned dependency closure.
type ApplicationDependency struct {
	// Purl is the dependency's package URL without a version.
	Purl    string `json:"purl"`
	Version string `json:"version"`
	// Direct marks a dependency the project declares itself.
	Direct bool `json:"direct"`
	// Requires lists the versionless purls this dependency depends on in the
	// project's resolved tree, each pinned elsewhere in the request.
	Requires []string `json:"requires,omitempty"`
	// Markers and Extras, for a Python dependency, are the PEP 508
	// environment markers under which the project installs it and the
	// extras it enables (informational: the closure is their union).
	Markers []string `json:"markers,omitempty"`
	Extras  []string `json:"extras,omitempty"`
}

// ApplicationReachabilityRequest is the body of POST /reachability/application: the
// pinned closure and the project's call sites into it, as a graph fragment
// holding the project's functions that call a dependency, those calls and the
// project's supertypes.
type ApplicationReachabilityRequest struct {
	SchemaVersion       string                         `json:"schema_version"`
	Dependencies        []ApplicationDependency        `json:"dependencies"`
	CallSites           *graphfrag.GraphFragmentExport `json:"call_sites"`
	IncludeCallChains   bool                           `json:"include_call_chains"`
	MaxChainsPerFinding int                            `json:"max_chains_per_finding,omitempty"`
	// ConditionedRules are the scan's conditioned rules for the closure's
	// ecosystem. The API specializes the closure's generic findings with them
	// over the values one dependency passes another, as a dependency scan
	// specialized them locally.
	ConditionedRules []conditioned.Rule `json:"conditioned_rules,omitempty"`
}

// ApplicationReachabilitySummary counts findings by verdict.
type ApplicationReachabilitySummary struct {
	Reachable   int `json:"reachable"`
	Unknown     int `json:"unknown"`
	Unreachable int `json:"unreachable"`
}

// ApplicationAsset is a dependency finding's asset with the server's verdict.
type ApplicationAsset struct {
	Asset schema.CryptographicAsset `json:"-"`
	// Reachability is reachable, unreachable or unknown.
	Reachability string `json:"reachability"`
	// ReachabilityReason says why an unknown verdict is unknown.
	ReachabilityReason string `json:"reachability_reason,omitempty"`
	// CallChains are the routes from the project that prove a verdict, in the
	// callgraph export's chain frame form, when the request asked for them.
	CallChains json.RawMessage `json:"call_chains,omitempty"`
	// Analysis is the callgraph export's analysis block for the finding.
	Analysis json.RawMessage `json:"analysis,omitempty"`
}

// applicationVerdict is the part of an asset that is the server's verdict.
type applicationVerdict struct {
	Reachability       string          `json:"reachability"`
	ReachabilityReason string          `json:"reachability_reason,omitempty"`
	CallChains         json.RawMessage `json:"call_chains,omitempty"`
	Analysis           json.RawMessage `json:"analysis,omitempty"`
}

// UnmarshalJSON reads the asset as the interim schema reads it and the
// verdict beside it. CryptographicAsset has its own decoder, so it cannot be
// embedded: its UnmarshalJSON would be promoted and drop the verdict.
func (a *ApplicationAsset) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &a.Asset); err != nil {
		return err
	}
	var verdict applicationVerdict
	if err := json.Unmarshal(data, &verdict); err != nil {
		return err
	}
	a.Reachability, a.ReachabilityReason = verdict.Reachability, verdict.ReachabilityReason
	a.CallChains, a.Analysis = verdict.CallChains, verdict.Analysis
	return nil
}

// ApplicationFinding is one file of a dependency with its findings.
type ApplicationFinding struct {
	// FilePath names the file as module@version/path.
	FilePath            string                 `json:"file_path"`
	Language            string                 `json:"language"`
	DependencyInfo      *schema.DependencyInfo `json:"dependency_info,omitempty"`
	CryptographicAssets []ApplicationAsset     `json:"cryptographic_assets"`
}

// ApplicationDependencyAnswer is the server's answer for one pinned dependency.
type ApplicationDependencyAnswer struct {
	Purl         string                         `json:"purl"`
	Version      string                         `json:"version"`
	Direct       bool                           `json:"direct"`
	InfoCode     string                         `json:"info_code"`
	InfoMessage  string                         `json:"info_message,omitempty"`
	RulesVersion string                         `json:"rules_version,omitempty"`
	Summary      ApplicationReachabilitySummary `json:"summary"`
	Findings     []ApplicationFinding           `json:"findings"`
}

// ApplicationReachability is the /reachability/application answer.
type ApplicationReachability struct {
	SchemaVersion string                         `json:"schema_version"`
	RulesVersion  string                         `json:"rules_version,omitempty"`
	Dependencies  []ApplicationDependencyAnswer  `json:"dependencies,omitempty"`
	Summary       ApplicationReachabilitySummary `json:"summary"`
	InfoCode      string                         `json:"info_code"`
	InfoMessage   string                         `json:"info_message,omitempty"`
	// RequestBytes and ResponseBytes are the sizes of the body sent and
	// received; they are not part of the answer.
	RequestBytes  int `json:"-"`
	ResponseBytes int `json:"-"`
}

// ApplicationReachability sends the project's pinned closure and call sites to
// the API in one request and returns its verdict on every dependency finding.
// The outcome is in InfoCode; a non-200 status is an error.
func (c *Client) ApplicationReachability(ctx context.Context, request *ApplicationReachabilityRequest) (*ApplicationReachability, error) {
	if err := CheckBaseURL(c.baseURL, c.allowHTTP); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("apiclient: encode application reachability request: %w", err)
	}
	url := c.baseURL + applicationReachabilityEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("apiclient: create application reachability request: %w", err)
	}
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set(headerUserAgent, UserAgent())
	req.Header.Set("Content-Type", "application/json")

	// #nosec G704 -- URL is the configured API base URL plus a fixed endpoint.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apiclient: application reachability request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Msg("Failed to close application reachability response")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleHTTPError(resp, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxApplicationResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("apiclient: read application reachability response: %w", err)
	}
	var answer ApplicationReachability
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, fmt.Errorf("apiclient: decode application reachability response: %w", err)
	}
	answer.RequestBytes, answer.ResponseBytes = len(payload), len(body)
	return &answer, nil
}
