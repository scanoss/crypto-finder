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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"
)

// maxRedirects re-establishes the hop limit that setting CheckRedirect removes.
const maxRedirects = 10

// ValidateEndpoint accepts only HTTPS, with no exemption. Every rejection wraps
// ErrInsecureEndpoint so the sentinel and the reported failure code agree.
func ValidateEndpoint(rawURL string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("%w: api_url is empty", ErrInsecureEndpoint)
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		// Not echoed back: the value may carry credentials.
		return fmt.Errorf("%w: api_url is not a valid URL", ErrInsecureEndpoint)
	}

	if !strings.EqualFold(parsed.Scheme, "https") {
		scheme := parsed.Scheme
		if scheme == "" {
			scheme = "(none)"
		}
		return fmt.Errorf("%w: api_url uses scheme %s", ErrInsecureEndpoint, scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("%w: api_url has no host", ErrInsecureEndpoint)
	}

	// base+endpoint is string concatenation: a query here would push the endpoint
	// past it and GET the host root with the API key attached.
	switch {
	case parsed.User != nil:
		return fmt.Errorf("%w: api_url must not embed credentials", ErrInsecureEndpoint)
	case parsed.RawQuery != "":
		return fmt.Errorf("%w: api_url must not carry a query string", ErrInsecureEndpoint)
	case parsed.Fragment != "" || parsed.RawFragment != "":
		return fmt.Errorf("%w: api_url must not carry a fragment", ErrInsecureEndpoint)
	}

	return nil
}

// secureRedirectPolicy refuses non-HTTPS hops and withholds the API key from
// another origin. net/http strips only Authorization, Cookie and
// WWW-Authenticate, and re-copies headers per hop — hence the Del inside.
func secureRedirectPolicy() func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("api: stopped after %d redirects", maxRedirects)
		}

		if !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("%w: %s://%s", ErrInsecureRedirect, req.URL.Scheme, req.URL.Host)
		}

		origin := via[0].URL
		if !sameOrigin(origin, req.URL) {
			req.Header.Del(headerAPIKey)
			log.Warn().
				Str("from_host", origin.Host).
				Str("to_host", req.URL.Host).
				Msg("Redirect crosses origin, withholding API credential from the new host")
		}

		return nil
	}
}

// sameOrigin decides on normalized host; scheme is always https here.
func sameOrigin(a, b *url.URL) bool {
	return normalizedHost(a) == normalizedHost(b)
}

// normalizedHost ignores case, an explicit :443, and a trailing dot, which are
// cosmetic for HTTPS.
func normalizedHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")

	port := u.Port()
	if port == "" || port == "443" {
		return host
	}
	return host + ":" + port
}

// sanitizeErrorBody drops control characters so a remote body cannot forge log
// lines once quoted into an error.
func sanitizeErrorBody(body []byte) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, string(body))

	return strings.TrimSpace(cleaned)
}
