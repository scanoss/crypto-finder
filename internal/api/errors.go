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
	"errors"
	"fmt"
)

var (
	// ErrUnauthorized indicates the API key is invalid or missing (401).
	ErrUnauthorized = errors.New("unauthorized: invalid API key")

	// ErrForbidden indicates access is denied (403).
	ErrForbidden = errors.New("forbidden: access denied")

	// ErrNotFound indicates the requested resource was not found (404).
	ErrNotFound = errors.New("not found: resource does not exist")

	// ErrServerError indicates a server-side error (500+).
	ErrServerError = errors.New("server error: please try again later")

	// ErrTimeout indicates a request timeout.
	ErrTimeout = errors.New("request timeout")

	// ErrInvalidChecksum indicates the downloaded content checksum doesn't match.
	ErrInvalidChecksum = errors.New("checksum verification failed")
)

// HTTPError wraps HTTP-specific errors with status code and message.
type HTTPError struct {
	StatusCode int
	Message    string
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s (URL: %s)", e.StatusCode, e.Message, e.URL)
}

// NewHTTPError creates a new HTTP error.
func NewHTTPError(statusCode int, message, url string) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Message:    message,
		URL:        url,
	}
}

// IsServerError returns true if the error is a server error (5xx).
func IsServerError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrServerError) {
		return true
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 500
	}
	return false
}

// IsTimeout returns true if the error is a timeout error.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrTimeout)
}

// IsRetryable returns true if the error should be retried.
func IsRetryable(err error) bool {
	// Retry on server errors and timeouts
	return IsServerError(err) || IsTimeout(err)
}
