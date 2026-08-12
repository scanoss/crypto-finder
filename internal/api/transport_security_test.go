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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// Real servers, not a stubbed RoundTripper: redirect handling and credential
// scope live in net/http itself, which a fake transport never executes.

const testAPIKey = "secret-key-value"

// writeRuleset responds with the metadata headers a successful download needs.
func writeRuleset(w http.ResponseWriter, body string) {
	w.Header().Set(headerRulesetName, "dca")
	w.Header().Set(headerRulesetVersion, "v1.0.0")
	w.Header().Set(headerChecksumSHA256, "abc123")
	w.Header().Set(headerRulesetCreatedAt, "2024-01-01T00:00:00Z")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// clientTrusting trusts the given test servers so multi-origin HTTPS redirects
// can be followed in-process.
func clientTrusting(servers ...*httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	for _, srv := range servers {
		pool.AddCert(srv.Certificate())
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

func TestValidateEndpoint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		url     string
		wantErr error
	}{
		{name: "https accepted", url: "https://api.scanoss.com", wantErr: nil},
		{name: "https with port accepted", url: "https://api.example.com:8443", wantErr: nil},
		{name: "http rejected", url: "http://api.scanoss.com", wantErr: ErrInsecureEndpoint},
		{name: "http loopback rejected", url: "http://127.0.0.1:8080", wantErr: ErrInsecureEndpoint},
		{name: "http localhost rejected", url: "http://localhost:8080", wantErr: ErrInsecureEndpoint},
		{name: "https loopback accepted", url: "https://127.0.0.1:8443", wantErr: nil},
		{name: "scheme-less rejected", url: "api.scanoss.com", wantErr: ErrInsecureEndpoint},
		{name: "hostless rejected", url: "https:/api.scanoss.com", wantErr: ErrInsecureEndpoint},
		{name: "userinfo rejected", url: "https://user:pw@api.scanoss.com", wantErr: ErrInsecureEndpoint},
		{name: "query rejected", url: "https://api.scanoss.com?token=abc", wantErr: ErrInsecureEndpoint},
		{name: "fragment rejected", url: "https://api.scanoss.com#frag", wantErr: ErrInsecureEndpoint},
		{name: "surrounding whitespace tolerated", url: "  https://api.scanoss.com\n", wantErr: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateEndpoint(tc.url)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("ValidateEndpoint(%q) = %v, want nil", tc.url, err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("ValidateEndpoint(%q) = %v, want %v", tc.url, err, tc.wantErr)
			}
		})
	}
}

// The rejection message must not echo userinfo or query values.
func TestValidateEndpoint_NeverLeaksCredentials(t *testing.T) {
	t.Parallel()

	err := ValidateEndpoint("http://user:hunter2@api.example.com/path?token=abcdef")
	if !errors.Is(err, ErrInsecureEndpoint) {
		t.Fatalf("expected ErrInsecureEndpoint, got %v", err)
	}
	for _, secret := range []string{"hunter2", "abcdef", "user:"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error message leaked %q: %s", secret, err.Error())
		}
	}
}

func TestNewClient_RejectsInsecureEndpoint(t *testing.T) {
	t.Parallel()

	client, err := NewClient("http://api.scanoss.com", testAPIKey)
	if !errors.Is(err, ErrInsecureEndpoint) {
		t.Fatalf("NewClient() error = %v, want ErrInsecureEndpoint", err)
	}
	if client != nil {
		t.Fatal("NewClient() returned a client for an insecure endpoint")
	}
}

// The cleartext host must not be contacted at all.
func TestDownload_RejectsDowngradeRedirect(t *testing.T) {
	t.Parallel()

	var cleartextHits atomic.Int64
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cleartextHits.Add(1)
		writeRuleset(w, "should never be reached")
	}))
	defer cleartext.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cleartext.URL+"/downgraded", http.StatusFound)
	}))
	defer secure.Close()

	client, err := NewClientWithHTTPClient(secure.URL, testAPIKey, clientTrusting(secure))
	if err != nil {
		t.Fatalf("NewClientWithHTTPClient() error = %v", err)
	}

	_, _, err = client.DownloadRuleset(context.Background(), "dca", "latest")
	if !errors.Is(err, ErrInsecureRedirect) {
		t.Fatalf("DownloadRuleset() error = %v, want ErrInsecureRedirect", err)
	}
	if got := cleartextHits.Load(); got != 0 {
		t.Fatalf("cleartext server received %d requests, want 0", got)
	}
	if strings.Contains(err.Error(), testAPIKey) {
		t.Fatal("error message leaked the API key")
	}
}

// Cross-origin HTTPS redirects are followed, but without the API key.
func TestDownload_WithholdsCredentialAcrossOrigins(t *testing.T) {
	t.Parallel()

	var sawKey atomic.Bool
	var reached atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		if r.Header.Get(headerAPIKey) != "" {
			sawKey.Store(true)
		}
		writeRuleset(w, "ruleset-bytes")
	}))
	defer other.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/tarball", http.StatusFound)
	}))
	defer origin.Close()

	client, err := NewClientWithHTTPClient(origin.URL, testAPIKey, clientTrusting(origin, other))
	if err != nil {
		t.Fatalf("NewClientWithHTTPClient() error = %v", err)
	}

	body, _, err := client.DownloadRuleset(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatalf("DownloadRuleset() error = %v, want success", err)
	}
	if !reached.Load() {
		t.Fatal("cross-origin redirect was not followed")
	}
	if sawKey.Load() {
		t.Fatal("API key was forwarded across origins")
	}
	if string(body) != "ruleset-bytes" {
		t.Fatalf("body = %q, want %q", string(body), "ruleset-bytes")
	}
}

// Stripping is scoped to origin changes; same-host redirects still authenticate.
func TestDownload_KeepsCredentialSameOrigin(t *testing.T) {
	t.Parallel()

	var sawKey atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			sawKey.Store(r.Header.Get(headerAPIKey) == testAPIKey)
			writeRuleset(w, "ruleset-bytes")
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	client, err := NewClientWithHTTPClient(srv.URL, testAPIKey, clientTrusting(srv))
	if err != nil {
		t.Fatalf("NewClientWithHTTPClient() error = %v", err)
	}

	if _, _, err := client.DownloadRuleset(context.Background(), "dca", "latest"); err != nil {
		t.Fatalf("DownloadRuleset() error = %v, want success", err)
	}
	if !sawKey.Load() {
		t.Fatal("API key was not preserved across a same-origin redirect")
	}
}

// A response that keeps streaming is cut off rather than buffered unbounded.
func TestDownload_RejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeRuleset(w, strings.Repeat("A", 4096))
	}))
	defer srv.Close()

	client, err := NewClientWithHTTPClient(srv.URL, testAPIKey, clientTrusting(srv))
	if err != nil {
		t.Fatalf("NewClientWithHTTPClient() error = %v", err)
	}
	client.maxResponseBytes = 1024

	if _, _, err := client.DownloadRuleset(context.Background(), "dca", "latest"); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("DownloadRuleset() error = %v, want ErrResponseTooLarge", err)
	}
}

// Replacing net/http's CheckRedirect must not remove its hop limit.
func TestDownload_StopsAfterRedirectLimit(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	client, err := NewClientWithHTTPClient(srv.URL, testAPIKey, clientTrusting(srv))
	if err != nil {
		t.Fatalf("NewClientWithHTTPClient() error = %v", err)
	}

	_, _, err = client.DownloadRuleset(context.Background(), "dca", "latest")
	if err == nil || !strings.Contains(err.Error(), "stopped after") {
		t.Fatalf("DownloadRuleset() error = %v, want a redirect-limit failure", err)
	}
}

// A cosmetic difference in how the same host is written is not an origin change.
func TestSameOrigin_NormalizesEquivalentHosts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "explicit default port", a: "https://api.example.com:443", b: "https://api.example.com", want: true},
		{name: "case difference", a: "https://API.example.com", b: "https://api.example.com", want: true},
		{name: "trailing dot", a: "https://api.example.com.", b: "https://api.example.com", want: true},
		{name: "different host", a: "https://api.example.com", b: "https://evil.example.com", want: false},
		{name: "different port", a: "https://api.example.com:8443", b: "https://api.example.com", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a, err := url.Parse(tc.a)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.a, err)
			}
			b, err := url.Parse(tc.b)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.b, err)
			}
			if got := sameOrigin(a, b); got != tc.want {
				t.Fatalf("sameOrigin(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// The size cap must also hold on the non-200 path, where the body is quoted
// into an error that reaches logs.
func TestDownload_BoundsAndSanitizesErrorBody(t *testing.T) {
	t.Parallel()

	hostile := strings.Repeat("A", 512<<10) + "\n{\"level\":\"fatal\",\"forged\":true}"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(hostile))
	}))
	defer srv.Close()

	client, err := NewClientWithHTTPClient(srv.URL, testAPIKey, clientTrusting(srv))
	if err != nil {
		t.Fatalf("NewClientWithHTTPClient() error = %v", err)
	}

	_, _, err = client.DownloadRuleset(context.Background(), "dca", "latest")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("DownloadRuleset() error = %v, want ErrNotFound", err)
	}
	if int64(len(err.Error())) > maxErrorBodyBytes+1024 {
		t.Fatalf("error message is %d bytes, want it bounded near %d", len(err.Error()), maxErrorBodyBytes)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Fatal("error message carries newlines from the remote body")
	}
}

// A base URL carrying secrets is refused, and the refusal does not echo it.
func TestDownload_RedactsCredentialsInURLs(t *testing.T) {
	t.Parallel()

	_, err := NewClient("https://user:hunter2@api.example.com?token=abcdef", testAPIKey)
	if !errors.Is(err, ErrInsecureEndpoint) {
		t.Fatalf("NewClient() error = %v, want ErrInsecureEndpoint", err)
	}
	for _, secret := range []string{"hunter2", "abcdef"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %q: %s", secret, err.Error())
		}
	}
}
