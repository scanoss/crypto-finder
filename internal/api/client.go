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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/ruleset"
)

const (
	// API endpoints.
	rulesetsDownloadFmt = "/v3/rulesets/%s/%s/download"
	rulesetsReleaseFmt  = "/v3/rulesets/%s/%s"

	// HTTP headers - Request.
	headerAPIKey    = "x-api-key"
	headerUserAgent = "user-agent"

	// HTTP headers - Response.
	headerRulesetName      = "scanoss-ruleset-name"
	headerRulesetVersion   = "scanoss-ruleset-version"
	headerChecksumSHA256   = "x-checksum-sha256"
	headerRulesetCreatedAt = "scanoss-ruleset-created-at"
	headerRulesetLease     = "scanoss-ruleset-lease"
)

// Manifest describes a downloaded ruleset bundle, read from the response
// headers.
type Manifest struct {
	Name           string
	Version        string
	ChecksumSHA256 string
	CreatedAt      time.Time

	// Lease is the signed lease JSON the server sent with the bundle.
	Lease []byte
}

// Client is an HTTP client for the SCANOSS REST API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	// retryDelay is the wait before the first download retry; it doubles
	// on each later retry.
	retryDelay time.Duration
	// allowHTTP lets the client talk plain HTTP to a remote host. Without
	// it, only https and loopback http are used (see CheckBaseURL).
	allowHTTP bool
}

// Option configures a Client.
type Option func(*options)

type options struct {
	allowHTTP bool
}

// WithAllowHTTP lets the client send requests, and the API key, over plain
// HTTP to a remote host, for an on-premises API that only serves HTTP.
func WithAllowHTTP(allow bool) Option {
	return func(o *options) { o.allowHTTP = allow }
}

// NewClient creates a new API client.
func NewClient(baseURL, apiKey string, opts ...Option) *Client {
	return NewClientWithHTTPClient(baseURL, apiKey, nil, opts...)
}

// NewClientWithHTTPClient creates a new API client with an optional custom
// HTTP client. The client is copied, never modified, to add the redirect
// policy.
func NewClientWithHTTPClient(baseURL, apiKey string, httpClient *http.Client, opts ...Option) *Client {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.DefaultTimeout,
		}
	}

	return &Client{
		httpClient: withRedirectPolicy(httpClient, o.allowHTTP),
		baseURL:    baseURL,
		apiKey:     apiKey,
		retryDelay: config.DefaultRetryDelay,
		allowHTTP:  o.allowHTTP,
	}
}

// WithRetryDelay sets the wait before the first download retry; it doubles
// on each later retry. It returns c.
func (c *Client) WithRetryDelay(delay time.Duration) *Client {
	c.retryDelay = delay
	return c
}

// APIKey returns the API key the client sends.
func (c *Client) APIKey() string {
	return c.apiKey
}

// DownloadRuleset downloads a ruleset bundle and its signed lease
// (Manifest.Lease) from /v3/rulesets. A 404 means the API has no such
// ruleset or does not serve /v3/rulesets; an answer without a lease is an
// error.
func (c *Client) DownloadRuleset(ctx context.Context, name, version string) ([]byte, *Manifest, error) {
	if err := CheckBaseURL(c.baseURL, c.allowHTTP); err != nil {
		return nil, nil, err
	}
	bundle, manifest, err := c.downloadWithRetry(ctx, name, version, c.baseURL+fmt.Sprintf(rulesetsDownloadFmt, name, version))
	if errors.Is(err, ErrNotFound) {
		return nil, nil, fmt.Errorf("ruleset %s@%s not found: the SCANOSS API has no such ruleset or does not serve /v3/rulesets (%w)", name, version, err)
	}
	return bundle, manifest, err
}

// GetRelease returns the release description of a ruleset version from the
// v3 API ("latest" resolves to the current release). It does not retry.
func (c *Client) GetRelease(ctx context.Context, name, version string) (*ruleset.Release, error) {
	if err := CheckBaseURL(c.baseURL, c.allowHTTP); err != nil {
		return nil, err
	}
	url := c.baseURL + fmt.Sprintf(rulesetsReleaseFmt, name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set(headerUserAgent, UserAgent())

	// #nosec G704 -- URL is constructed from configured API base URL plus a fixed endpoint format.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Debug().Err(err).Msg("Failed to close ruleset release response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, c.rulesetHTTPError(resp, url)
	}
	var release ruleset.Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode ruleset release: %w", err)
	}
	return &release, nil
}

// downloadWithRetry downloads url, retrying retryable failures with
// exponential backoff.
func (c *Client) downloadWithRetry(ctx context.Context, name, version, url string) ([]byte, *Manifest, error) {
	log.Debug().
		Str("ruleset", name).
		Str("version", version).
		Str("url", url).
		Msg("Downloading ruleset")

	// Implement retry logic with exponential backoff
	var lastErr error
	delay := c.retryDelay
	attempts := 0

	for attempt := 0; attempt <= config.DefaultMaxRetries; attempt++ {
		attempts++
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

	if attempts == 1 {
		return nil, nil, fmt.Errorf("download failed: %w", lastErr)
	}
	return nil, nil, fmt.Errorf("download failed after %d attempts: %w", attempts, lastErr)
}

// doDownload performs a single download attempt.
func (c *Client) doDownload(ctx context.Context, url string) ([]byte, *Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set(headerUserAgent, UserAgent())

	// #nosec G704 -- URL is constructed from configured API base URL plus a fixed endpoint format.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, nil, ErrTimeout
		}
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}

	// Handle HTTP status codes
	if resp.StatusCode != http.StatusOK {
		return nil, nil, c.rulesetHTTPError(resp, url)
	}

	// Reconstruct manifest from response headers
	manifest, err := c.manifestFromHeaders(resp.Header)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct manifest from headers: %w", err)
	}
	encoded := c.getHeaderValue(resp.Header, headerRulesetLease)
	if encoded == "" {
		return nil, nil, fmt.Errorf("the API sent ruleset %s@%s without a signed lease (missing header: %s)", manifest.Name, manifest.Version, headerRulesetLease)
	}
	manifest.Lease, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid %s header (expected base64): %w", headerRulesetLease, err)
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

// rulesetHTTPError converts the error answer of a ruleset request. 410 Gone
// and 426 Upgrade Required mean the API no longer serves this client: they
// become an *UpgradeRequiredError carrying the server's message. Every other
// status goes through handleHTTPError.
func (c *Client) rulesetHTTPError(resp *http.Response, url string) error {
	if resp.StatusCode != http.StatusGone && resp.StatusCode != http.StatusUpgradeRequired {
		return c.handleHTTPError(resp, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil {
		log.Debug().Err(err).Str("url", url).Msg("Failed to read the upgrade-required answer")
	}
	message := serverMessage(resp.Header, body)
	if message == "" {
		message = defaultUpgradeMessage
	}
	return &UpgradeRequiredError{StatusCode: resp.StatusCode, Message: message}
}

// handleHTTPError converts HTTP status codes to appropriate errors. The
// message is the server's (see serverMessage), or the HTTP status when the
// answer has none.
func (c *Client) handleHTTPError(resp *http.Response, url string) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	message := serverMessage(resp.Header, body)
	if message == "" {
		message = resp.Status
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &RefusedError{StatusCode: resp.StatusCode, Message: message, kind: ErrUnauthorized}
	case http.StatusForbidden:
		return &RefusedError{StatusCode: resp.StatusCode, Message: message, kind: ErrForbidden}
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, message)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
		return fmt.Errorf("%w: %s", ErrServerError, message)
	default:
		return NewHTTPError(resp.StatusCode, message, url)
	}
}
