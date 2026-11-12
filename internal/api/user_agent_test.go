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
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/version"
)

// gatewayProduct reads the client family and version from a User-Agent the
// way the SCANOSS gateway does (scanoss/gateway telemetry.ParseClient): the
// first token's product names the family ("crypto-finder" and
// "scanoss-crypto-finder" both map to crypto-finder) and a leading
// semver of its version is kept with the patch.
func gatewayProduct(userAgent string) (family, ver string) {
	fields := strings.Fields(userAgent)
	if len(fields) == 0 {
		return "unknown", "unknown"
	}
	product, rest, _ := strings.Cut(fields[0], "/")
	switch strings.ToLower(product) {
	case "crypto-finder", "scanoss-crypto-finder":
		family = "crypto-finder"
	default:
		return "other", "unknown"
	}
	m := regexp.MustCompile(`^v?(\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?`).FindStringSubmatch(rest)
	switch {
	case m == nil:
		return family, "unknown"
	case m[3] != "":
		return family, m[1] + "." + m[2] + "." + m[3]
	}
	return family, m[1] + "." + m[2]
}

// Every request crypto-finder sends to the SCANOSS API carries
// "crypto-finder/<version>", which the gateway reports as family
// crypto-finder with the real version. Not parallel: it sets version.Version.
func TestUserAgentOnEveryRequest(t *testing.T) {
	for _, tc := range []struct{ built, want string }{
		{"0.53.0", "0.53.0"},                   // goreleaser
		{"v0.53.0-2-gabc1234-dirty", "0.53.0"}, // make build (git describe)
		{"dev", "unknown"},                     // go build without ldflags
	} {
		saved := version.Version
		version.Version = tc.built

		agents := map[string]string{}
		client := newTestClient(t, "test-key", func(w http.ResponseWriter, r *http.Request) {
			agents[r.URL.Path] = r.Header.Get("User-Agent")
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		_, _, _ = client.DownloadRuleset(context.Background(), "dca", "latest")
		_, _ = client.GetRelease(context.Background(), "dca", "latest")
		_, _, _ = client.ComponentFindings(context.Background(), "pkg:npm/left-pad", "")
		version.Version = saved

		for _, path := range []string{
			"/v3/rulesets/dca/latest/download",
			"/v3/rulesets/dca/latest",
			"/v3/cryptography/reachability/component",
		} {
			agent, ok := agents[path]
			if !ok {
				t.Fatalf("%s: no request to %s (requests: %v)", tc.built, path, agents)
			}
			if agent != "crypto-finder/"+tc.built {
				t.Errorf("%s: %s sent User-Agent %q", tc.built, path, agent)
			}
			if family, got := gatewayProduct(agent); family != "crypto-finder" || got != tc.want {
				t.Errorf("%s: the gateway would read %q as %s %s, want crypto-finder %s", tc.built, agent, family, got, tc.want)
			}
		}
	}
}
