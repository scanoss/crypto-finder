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
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrInsecureURL means a URL would send the API key over plain HTTP to a host
// off this machine, and plain HTTP was not allowed.
var ErrInsecureURL = errors.New("plain HTTP is not allowed")

// maxRedirects matches net/http's default redirect limit, which a custom
// CheckRedirect replaces.
const maxRedirects = 10

// CheckBaseURL accepts an https URL, an http URL to a loopback host, and,
// when allowHTTP is set, any http URL. Anything else is refused: an
// unparsable URL, another scheme, a missing host, or plain HTTP to a
// remote host without allowHTTP (ErrInsecureURL).
func CheckBaseURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("apiclient: parse API URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("apiclient: API URL %q has no host", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowHTTP || IsLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("apiclient: API URL %q: %w", raw, ErrInsecureURL)
	default:
		return fmt.Errorf("apiclient: API URL %q: unsupported scheme %q (use https)", raw, u.Scheme)
	}
}

// IsLoopbackHost reports whether host is localhost or a loopback IP, so
// traffic to it never leaves the machine.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// withRedirectPolicy returns a copy of hc whose redirects are held to
// CheckBaseURL, so an https server cannot send the client, and its API key
// header, to a plain-HTTP host. A CheckRedirect hc already had still runs.
func withRedirectPolicy(hc *http.Client, allowHTTP bool) *http.Client {
	wrapped := *hc
	previous := hc.CheckRedirect
	wrapped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := CheckBaseURL(req.URL.String(), allowHTTP); err != nil {
			return fmt.Errorf("apiclient: refusing redirect: %w", err)
		}
		if previous != nil {
			return previous(req, via)
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("apiclient: stopped after %d redirects", maxRedirects)
		}
		return nil
	}
	return &wrapped
}
