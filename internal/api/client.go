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
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
)

const (
	// API endpoints.
	rulesetsEndpointFmt = "/v2/cryptography/rulesets/%s/%s/download"

	// HTTP headers - Request.
	headerAPIKey    = "x-api-key"
	headerUserAgent = "user-agent"
	userAgentValue  = "scanoss-crypto-finder"

	// HTTP headers - Response.
	headerRulesetName      = "scanoss-ruleset-name"
	headerRulesetVersion   = "scanoss-ruleset-version"
	headerChecksumSHA256   = "x-checksum-sha256"
	headerRulesetCreatedAt = "scanoss-ruleset-created-at"
)

// Manifest represents the manifest.json file reconstructed from HTTP headers.
type Manifest struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	CreatedAt      time.Time `json:"created_at"`
}

// Client is an HTTP client for the SCANOSS REST API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// NewClient creates a new API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: config.DefaultTimeout,
		},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

// DownloadRuleset downloads a ruleset tarball from the API
// Returns the tarball bytes and the parsed manifest.
func (c *Client) DownloadRuleset(ctx context.Context, name, version string) ([]byte, *Manifest, error) {
	endpoint := fmt.Sprintf(rulesetsEndpointFmt, name, version)
	url := c.baseURL + endpoint

	log.Debug().
		Str("ruleset", name).
		Str("version", version).
		Str("url", url).
		Msg("Downloading ruleset")

	// Implement retry logic with exponential backoff
	var lastErr error
	delay := config.DefaultRetryDelay

	for attempt := 0; attempt <= config.DefaultMaxRetries; attempt++ {
		if attempt > 0 {
			log.Debug().
				Int("attempt", attempt).
				Dur("delay", delay).
				Msg("Retrying download")

			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(delay):
			}

			delay *= 2
		}

		tarball, manifest, err := c.doDownload(ctx, url)
		if err == nil {
			return tarball, manifest, nil
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
			Int("attempt", attempt+1).
			Int("max_retries", config.DefaultMaxRetries).
			Msg("Download failed, will retry")
	}

	return nil, nil, fmt.Errorf("download failed after %d retries: %w", config.DefaultMaxRetries, lastErr)
}

// doDownload performs a single download attempt.
func (c *Client) doDownload(ctx context.Context, url string) ([]byte, *Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set(headerUserAgent, userAgentValue)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, nil, ErrTimeout
		}
		return nil, nil, fmt.Errorf("request failed: %w", err)
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
