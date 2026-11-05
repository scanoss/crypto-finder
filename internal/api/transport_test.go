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
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCheckBaseURL(t *testing.T) {
	cases := []struct {
		url       string
		allowHTTP bool
		wantErr   bool
		insecure  bool
	}{
		{url: "https://api.scanoss.com"},
		{url: "HTTPS://api.scanoss.com"},
		{url: "http://api.scanoss.com", wantErr: true, insecure: true},
		{url: "HTTP://api.scanoss.com", wantErr: true, insecure: true},
		{url: "http://10.0.0.5:5443", wantErr: true, insecure: true},
		{url: "http://api.scanoss.com", allowHTTP: true},
		{url: "http://localhost:8080"},
		{url: "http://127.0.0.1:8080"},
		{url: "http://127.8.9.10"},
		{url: "http://[::1]:8080"},
		{url: "http://localhost.evil.com", wantErr: true, insecure: true},
		{url: "ftp://api.scanoss.com", wantErr: true},
		{url: "ftp://api.scanoss.com", allowHTTP: true, wantErr: true},
		{url: "api.scanoss.com", wantErr: true},
		{url: "https://", wantErr: true},
	}
	for _, tc := range cases {
		err := CheckBaseURL(tc.url, tc.allowHTTP)
		if (err != nil) != tc.wantErr {
			t.Errorf("CheckBaseURL(%q, %v) error = %v, wantErr %v", tc.url, tc.allowHTTP, err, tc.wantErr)
			continue
		}
		if got := errors.Is(err, ErrInsecureURL); got != tc.insecure {
			t.Errorf("CheckBaseURL(%q, %v) ErrInsecureURL = %v, want %v", tc.url, tc.allowHTTP, got, tc.insecure)
		}
	}
}

// failingTransport fails the test if the client ever dials: a refused URL
// must be refused before any byte, including the API key, is sent.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected request to %s", req.URL)
	return nil, errors.New("unexpected request")
}

func TestClient_RefusesRemoteHTTPBeforeSending(t *testing.T) {
	hc := &http.Client{Transport: failingTransport{t}}
	c := NewClientWithHTTPClient("http://api.example.com", "secret", hc)

	if _, _, err := c.DownloadRuleset(context.Background(), "dca", "latest"); !errors.Is(err, ErrInsecureURL) {
		t.Errorf("DownloadRuleset error = %v, want ErrInsecureURL", err)
	}
	if _, err := c.LookupComponent(context.Background(), "pkg:golang/x@v1", "v1"); !errors.Is(err, ErrInsecureURL) {
		t.Errorf("LookupComponent error = %v, want ErrInsecureURL", err)
	}
}

func TestClient_AllowHTTPSendsToRemoteHTTP(t *testing.T) {
	var sent atomic.Int32
	hc := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		sent.Add(1)
		return nil, errors.New("offline")
	})}
	c := NewClientWithHTTPClient("http://api.example.com", "secret", hc, WithAllowHTTP(true)).WithRetryDelay(0)

	_, err := c.LookupComponent(context.Background(), "pkg:golang/x@v1", "v1")
	if errors.Is(err, ErrInsecureURL) {
		t.Fatalf("LookupComponent refused an allowed URL: %v", err)
	}
	if sent.Load() == 0 {
		t.Error("the request was never sent")
	}
}

func TestClient_RefusesRedirectToRemoteHTTP(t *testing.T) {
	var followed atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://api.example.com/steal", http.StatusFound)
	}))
	defer srv.Close()
	hc := srv.Client()
	inner := hc.Transport
	hc.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.example.com" {
			followed.Store(true)
			return nil, errors.New("followed the redirect")
		}
		return inner.RoundTrip(req)
	})

	c := NewClientWithHTTPClient(srv.URL, "secret", hc)
	_, err := c.LookupComponent(context.Background(), "pkg:golang/x@v1", "v1")
	if !errors.Is(err, ErrInsecureURL) {
		t.Errorf("LookupComponent error = %v, want ErrInsecureURL", err)
	}
	if followed.Load() {
		t.Error("the client followed an https -> http redirect")
	}
}

func TestNewClientWithHTTPClient_DoesNotModifyCallerClient(t *testing.T) {
	hc := &http.Client{}
	NewClientWithHTTPClient("https://api.scanoss.com", "k", hc)
	if hc.CheckRedirect != nil {
		t.Error("NewClientWithHTTPClient set CheckRedirect on the caller's client")
	}
}
