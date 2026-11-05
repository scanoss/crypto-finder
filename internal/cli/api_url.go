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

package cli

import (
	"net/url"

	"github.com/rs/zerolog/log"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/failure"
)

const allowHTTPFlag = "allow-http"

const allowHTTPUsage = "Allow a plain-HTTP --api-url on a remote host (sends the API key unencrypted; for on-premises APIs without TLS)"

// checkAPIURL refuses an API URL the client would refuse, before any
// request: a refused ruleset download would otherwise fall back to a stale
// cached ruleset and hide the cause. When plain HTTP to a remote host is
// allowed and used, it warns that the API key travels unencrypted.
func checkAPIURL(apiURL string, allowHTTP bool) error {
	if err := api.CheckBaseURL(apiURL, allowHTTP); err != nil {
		return failure.Wrap(
			err,
			failure.CodeInvalidArguments,
			failure.StageConfig,
			"refusing the SCANOSS API URL: use https, or pass --allow-http (env SCANOSS_ALLOW_HTTP=true) for an on-premises API without TLS",
			failure.WithDetail("api_url", apiURL),
		)
	}
	if u, err := url.Parse(apiURL); err == nil && u.Scheme == "http" && !api.IsLoopbackHost(u.Hostname()) {
		log.Warn().
			Str("api_url", apiURL).
			Msg("Using the SCANOSS API over plain HTTP: the API key and responses are not encrypted")
	}
	return nil
}
