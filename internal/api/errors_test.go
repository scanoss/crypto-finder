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
	"net/http"
	"testing"
)

func TestHTTPError_Error(t *testing.T) {
	err := &HTTPError{
		StatusCode: 503,
		Message:    "service unavailable",
		URL:        "https://api.example.com",
	}

	expected := "HTTP 503: service unavailable (URL: https://api.example.com)"
	if err.Error() != expected {
		t.Fatalf("Expected %q, got %q", expected, err.Error())
	}
}

func TestNewHTTPError(t *testing.T) {
	err := NewHTTPError(429, "rate limit", "https://api.example.com")
	if err.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", err.StatusCode)
	}
	if err.Message != "rate limit" {
		t.Errorf("Message = %s, want rate limit", err.Message)
	}
	if err.URL != "https://api.example.com" {
		t.Errorf("URL = %s, want https://api.example.com", err.URL)
	}
}

func TestIsServerError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		expects bool
	}{
		{
			name:    "nil error",
			err:     nil,
			expects: false,
		},
		{
			name:    "explicit server error",
			err:     ErrServerError,
			expects: true,
		},
		{
			name:    "http error 500",
			err:     NewHTTPError(500, "boom", "https://api.example.com"),
			expects: true,
		},
		{
			name:    "http error 418",
			err:     NewHTTPError(418, "teapot", "https://api.example.com"),
			expects: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsServerError(tt.err) != tt.expects {
				t.Fatalf("IsServerError(%v) = %v, want %v", tt.err, IsServerError(tt.err), tt.expects)
			}
		})
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		expects bool
	}{
		{
			name:    "nil error",
			err:     nil,
			expects: false,
		},
		{
			name:    "timeout error",
			err:     ErrTimeout,
			expects: true,
		},
		{
			name:    "non-timeout error",
			err:     ErrForbidden,
			expects: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsTimeout(tt.err) != tt.expects {
				t.Fatalf("IsTimeout(%v) = %v, want %v", tt.err, IsTimeout(tt.err), tt.expects)
			}
		})
	}
}
