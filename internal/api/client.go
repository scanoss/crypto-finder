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

// Package apiclient provides an HTTP client for the SCANOSS REST API.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
)

const (
	// API endpoints.
	rulesetsEndpointFmt       = "/v2/cryptography/rulesets/%s/%s/download"
	rulesetsIndexEndpointFmt  = "/v2/cryptography/rulesets/%s/%s/index"
	rulesetsFilterEndpointFmt = "/v2/cryptography/rulesets/%s/%s/filter"

	// HTTP headers - Request.
	headerAPIKey      = "x-api-key"
	headerUserAgent   = "user-agent"
	headerContentType = "content-type"
	userAgentValue    = "scanoss-crypto-finder"
	contentTypeJSON   = "application/json"

	// HTTP headers - Response.
	headerRulesetName      = "scanoss-ruleset-name"
	headerRulesetVersion   = "scanoss-ruleset-version"
	headerChecksumSHA256   = "x-checksum-sha256"
	headerRulesetCreatedAt = "scanoss-ruleset-created-at"
	headerRulesetProfile   = "scanoss-ruleset-profile"
	headerRulesetRules     = "scanoss-ruleset-rules"
)

// Manifest represents the manifest.json file reconstructed from HTTP headers.
type Manifest struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	CreatedAt      time.Time `json:"created_at"`
	// Profile is the hash of the profile a filtered ruleset was reduced
	// with, and Rules its kept/total rule count; both empty for a full
	// download.
	Profile string `json:"profile,omitempty"`
	Rules   string `json:"rules,omitempty"`
}

// RulesetIndex is what the API publishes about a ruleset: the languages its
// rules name and, per import family, the modules its rules declare.
type RulesetIndex struct {
	Name           string              `json:"name"`
	Version        string              `json:"version"`
	ChecksumSHA256 string              `json:"checksum_sha256"`
	Languages      []string            `json:"languages"`
	Modules        map[string][]string `json:"modules"`
}

// RulesetProfile selects the rules of a filtered download: those with a
// listed language whose declared modules relate to a listed module of their
// family. A family absent from Modules keeps all its rules.
type RulesetProfile struct {
	Languages []string            `json:"languages"`
	Modules   map[string][]string `json:"modules"`
}

// Client is an HTTP client for the SCANOSS REST API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// NewClient creates a new API client.
func NewClient(baseURL, apiKey string) *Client {
	return NewClientWithHTTPClient(baseURL, apiKey, nil)
}

// NewClientWithHTTPClient creates a new API client with an optional custom HTTP client.
func NewClientWithHTTPClient(baseURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.DefaultTimeout,
		}
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
		apiKey:     apiKey,
	}
}

// DownloadRuleset downloads a ruleset tarball from the API
// Returns the tarball bytes and the parsed manifest.
func (c *Client) DownloadRuleset(ctx context.Context, name, version string) ([]byte, *Manifest, error) {
	url := c.baseURL + fmt.Sprintf(rulesetsEndpointFmt, name, version)

	log.Debug().
		Str("ruleset", name).
		Str("version", version).
		Str("url", url).
		Msg("Downloading ruleset")

	return c.downloadWithRetries(ctx, "download", http.MethodGet, url, nil)
}

// DownloadFilteredRuleset downloads the ruleset reduced to the rules the
// profile keeps: the languages the scanned sources have files of and, per
// import family, the index modules they use. The manifest carries the
// checksum of the returned tarball, the profile hash the server computed
// and the kept/total rule count.
func (c *Client) DownloadFilteredRuleset(ctx context.Context, name, version string, profile RulesetProfile) ([]byte, *Manifest, error) {
	url := c.baseURL + fmt.Sprintf(rulesetsFilterEndpointFmt, name, version)
	body, err := json.Marshal(profile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode ruleset profile: %w", err)
	}

	log.Debug().
		Str("ruleset", name).
		Str("version", version).
		Str("url", url).
		Int("languages", len(profile.Languages)).
		Msg("Downloading filtered ruleset")

	return c.downloadWithRetries(ctx, "filtered download", http.MethodPost, url, body)
}

// GetRulesetIndex fetches the languages and declared modules of a ruleset.
func (c *Client) GetRulesetIndex(ctx context.Context, name, version string) (*RulesetIndex, error) {
	url := c.baseURL + fmt.Sprintf(rulesetsIndexEndpointFmt, name, version)

	log.Debug().
		Str("ruleset", name).
		Str("version", version).
		Str("url", url).
		Msg("Fetching ruleset index")

	var index RulesetIndex
	err := c.withRetries(ctx, "index", func() error {
		resp, err := c.do(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		defer closeBody(resp)
		if resp.StatusCode != http.StatusOK {
			return c.handleHTTPError(resp, url)
		}
		if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
			return fmt.Errorf("failed to decode ruleset index: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &index, nil
}

// downloadWithRetries fetches a ruleset tarball and its header manifest
// with the retry policy of withRetries.
func (c *Client) downloadWithRetries(ctx context.Context, what, method, url string, body []byte) ([]byte, *Manifest, error) {
	var tarball []byte
	var manifest *Manifest
	err := c.withRetries(ctx, what, func() error {
		var err error
		tarball, manifest, err = c.doDownload(ctx, method, url, body)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return tarball, manifest, nil
}

// withRetries runs attempt with exponential backoff until it succeeds, fails
// with a non-retryable error, exhausts the retry budget or the context ends
// during a backoff, in which case the context's error is returned as is.
func (c *Client) withRetries(ctx context.Context, what string, attempt func() error) error {
	var lastErr error
	delay := config.DefaultRetryDelay

	for try := 0; try <= config.DefaultMaxRetries; try++ {
		if try > 0 {
			log.Debug().
				Int("attempt", try).
				Dur("delay", delay).
				Msg("Retrying " + what)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}

			delay *= 2
		}

		err := attempt()
		if err == nil {
			return nil
		}

		lastErr = err

		// Don't retry on client errors (4xx) except timeouts
		if !IsRetryable(err) {
			log.Debug().
				Err(err).
				Msg("Non-retryable error, stopping retries")
			break
		}

		log.Warn().
			Err(err).
			Int("attempt", try+1).
			Int("max_retries", config.DefaultMaxRetries).
			Msg("Request failed, will retry")
	}

	return fmt.Errorf("%s failed after %d retries: %w", what, config.DefaultMaxRetries, lastErr)
}

// do sends one request with the API key and user agent headers. A nil body
// sends no body; a body is sent as JSON.
func (c *Client) do(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set(headerUserAgent, userAgentValue)
	if body != nil {
		req.Header.Set(headerContentType, contentTypeJSON)
	}

	// #nosec G704 -- URL is constructed from configured API base URL plus a fixed endpoint format.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return resp, nil
}

func closeBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		log.Warn().Err(err).Msg("Failed to close response body")
	}
}

// doDownload performs a single download attempt.
func (c *Client) doDownload(ctx context.Context, method, url string, body []byte) ([]byte, *Manifest, error) {
	resp, err := c.do(ctx, method, url, body)
	if err != nil {
		return nil, nil, err
	}

	// Handle HTTP status codes
	if resp.StatusCode != http.StatusOK {
		return nil, nil, c.handleHTTPError(resp, url)
	}

	// Reconstruct manifest from response headers
	manifest, err := c.manifestFromHeaders(resp.Header)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct manifest from headers: %w", err)
	}

	// Read response body
	tarball, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Info().
		Str("ruleset", manifest.Name).
		Str("version", manifest.Version).
		Str("rules", manifest.Rules).
		Int("size_bytes", len(tarball)).
		Msg("Ruleset downloaded successfully")

	if err := resp.Body.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to close response body: %w", err)
	}

	return tarball, manifest, nil
}

// manifestFromHeaders reconstructs a Manifest from HTTP response headers.
func (c *Client) manifestFromHeaders(headers http.Header) (*Manifest, error) {
	name := c.getHeaderValue(headers, headerRulesetName)
	if name == "" {
		return nil, fmt.Errorf("missing required header: %s", headerRulesetName)
	}

	version := c.getHeaderValue(headers, headerRulesetVersion)
	if version == "" {
		return nil, fmt.Errorf("missing required header: %s", headerRulesetVersion)
	}

	checksum := c.getHeaderValue(headers, headerChecksumSHA256)
	if checksum == "" {
		return nil, fmt.Errorf("missing required header: %s", headerChecksumSHA256)
	}

	createdAtStr := c.getHeaderValue(headers, headerRulesetCreatedAt)
	if createdAtStr == "" {
		return nil, fmt.Errorf("missing required header: %s", headerRulesetCreatedAt)
	}

	createdAt, err := time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("invalid %s header format (expected RFC3339): %w", headerRulesetCreatedAt, err)
	}

	return &Manifest{
		Name:           name,
		Version:        version,
		ChecksumSHA256: checksum,
		CreatedAt:      createdAt,
		Profile:        c.getHeaderValue(headers, headerRulesetProfile),
		Rules:          c.getHeaderValue(headers, headerRulesetRules),
	}, nil
}

// getHeaderValue retrieves a header value, trying both direct and gRPC-prefixed versions.
// This handles cases where the API is behind a gRPC-Gateway which prefixes custom headers with "Grpc-Metadata-".
func (c *Client) getHeaderValue(headers http.Header, headerName string) string {
	if value := headers.Get(headerName); value != "" {
		return value
	}

	grpcHeaderName := "Grpc-Metadata-" + headerName
	return headers.Get(grpcHeaderName)
}

// handleHTTPError converts HTTP status codes to appropriate errors.
func (c *Client) handleHTTPError(resp *http.Response, url string) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	message := string(body)
	if message == "" {
		message = resp.Status
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", ErrUnauthorized, message)
	case http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrForbidden, message)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, message)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
		return fmt.Errorf("%w: %s", ErrServerError, message)
	default:
		return NewHTTPError(resp.StatusCode, message, url)
	}
}
