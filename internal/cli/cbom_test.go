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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
)

func runCBOMWith(t *testing.T, sbom, apiURL string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(input, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "cbom.json")
	cbomOutput, cbomAPIKey, cbomAPIURL, cbomMaxComponents = output, "key", apiURL, 2000
	t.Cleanup(func() { cbomOutput, cbomAPIKey, cbomAPIURL = "", "", "" })
	cbomCmd.SetContext(context.Background())
	return output, runCBOM(cbomCmd, []string{input})
}

func TestCBOMCommand_WritesTheCBOMOfTheSBOM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rules_version":"v1","info_code":"READY","data":[{"version":"1.3.1","findings":[{"file_path":"lib/aes.js","language":"javascript","cryptographic_assets":[
		  {"start_line":3,"end_line":3,"match":"forge.cipher.createCipher('AES-CBC', key)",
		   "metadata":{"assetType":"algorithm","algorithmName":"AES","algorithmFamily":"AES","algorithmPrimitive":"block-cipher"},
		   "rules":[{"id":"forge.aes"}]}]}]}]}`))
	}))
	t.Cleanup(server.Close)

	output, err := runCBOMWith(t, `{"bomFormat":"CycloneDX","components":[{"name":"node-forge","purl":"pkg:npm/node-forge@1.3.1"}]}`, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		SpecVersion  string `json:"specVersion"`
		Dependencies []struct {
			Ref string `json:"ref"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.SpecVersion != "1.7" || len(bom.Dependencies) != 1 || bom.Dependencies[0].Ref != "pkg:npm/node-forge@1.3.1" {
		t.Errorf("CBOM %s", data)
	}
}

func TestCBOMCommand_Failures(t *testing.T) {
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(refused.Close)

	for _, tc := range []struct {
		name, sbom string
		code       failure.Code
	}{
		{"not an SBOM", `{"name":"package.json"}`, failure.CodeInvalidArguments},
		{"refused key", `{"bomFormat":"CycloneDX","components":[{"purl":"pkg:npm/a@1.0.0"}]}`, failure.CodeComponentLookupFailed},
	} {
		_, err := runCBOMWith(t, tc.sbom, refused.URL)
		var typed *failure.Error
		if !errors.As(err, &typed) || typed.Code != tc.code {
			t.Errorf("%s: err %v, want code %s", tc.name, err, tc.code)
		}
	}
}
