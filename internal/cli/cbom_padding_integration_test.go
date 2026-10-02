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

package cli_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestCBOMPaddingCLIContract(t *testing.T) {
	if testing.Short() {
		t.Skip("compiled CLI conversion contract")
	}
	binary := buildCryptoFinder(t, repositoryRoot(t))
	for _, tc := range []struct {
		name, padding, expected, invalidField string
	}{
		{"java-pkcs5", "PKCS5Padding", "pkcs5", ""},
		{"java-pkcs7", "PKCS7Padding", "pkcs7", ""},
		{"java-none", "NoPadding", "raw", ""},
		{"canonical-pkcs5", "pkcs5", "pkcs5", ""},
		{"canonical-pkcs7", "pkcs7", "pkcs7", ""},
		{"canonical-raw", "raw", "raw", ""},
		{"canonical-pkcs1", "pkcs1v15", "pkcs1v15", ""},
		{"canonical-oaep", "oaep", "oaep", ""},
		{"canonical-other", "other", "other", ""},
		{"canonical-unknown", "unknown", "unknown", ""},
		{"case-and-space", " \tPkCs5PaDdInG\n", "pkcs5", ""},
		{"canonical-case", "PKCS5", "pkcs5", ""},
		{"unknown-padding", "not-a-padding", "", "padding"},
		{"whitespace-only", " \t", "", "padding"},
		{"unsupported-java-padding", "ISO10126Padding", "", "padding"},
		{"padding-in-mode", "pkcs5", "", "mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "findings.json"), filepath.Join(dir, "cbom.json")
			// Minimized real JCA finding: conversion must not repair unrelated metadata.
			metadata := map[string]string{
				"assetType": "algorithm", "algorithmPrimitive": "block-cipher",
				"algorithmFamily": "AES", "algorithmName": "AES-CBC-PKCS5Padding",
				"algorithmMode": "CBC", "algorithmPadding": tc.padding,
			}
			if tc.invalidField == "mode" {
				metadata["algorithmMode"] = "NoPadding"
			}
			const sourcePath = "src/main/java/example/AESCBC.java"
			const ruleID = "jca.algorithm.block-cipher.aes"
			const match = "Cipher cipher = Cipher.getInstance(CYPHER);"
			asset := map[string]any{
				"start_line": 31, "end_line": 31, "match": match, "metadata": metadata,
				"finding_id": "0cd9f372", "source": "direct", "status": "pending",
				"rules": []any{map[string]string{"id": ruleID, "message": "AES", "severity": "INFO"}},
			}
			// A separate registered algorithm guards unrelated OID and asset preservation.
			control := map[string]any{
				"start_line": 40, "end_line": 40, "match": "MessageDigest.getInstance(\"SHA-256\")",
				"finding_id": "sha256-control", "source": "direct", "status": "pending",
				"metadata": map[string]string{"assetType": "algorithm", "algorithmPrimitive": "hash", "algorithmFamily": "SHA-2", "algorithmName": "SHA-256"},
				"rules":    []any{map[string]string{"id": "jdk.sha256", "message": "SHA-256", "severity": "INFO"}},
			}
			report := map[string]any{
				"version":  "1.6",
				"tool":     map[string]string{"name": "crypto-finder", "version": "test"},
				"findings": []any{map[string]any{"file_path": sourcePath, "language": "java", "cryptographic_assets": []any{asset, control}}},
			}
			before, err := json.Marshal(report)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(input, before, 0o600))
			cmd := exec.CommandContext(t.Context(), binary, "--error-format", "json", "convert", input, "--output", output)
			cmd.Env = append(os.Environ(), "HOME="+filepath.Join(dir, "home"))
			result, err := cmd.CombinedOutput()
			after, readErr := os.ReadFile(input)
			require.NoError(t, readErr)
			require.Equal(t, before, after, "conversion must not rewrite findings, IDs or metadata")
			if tc.invalidField != "" {
				require.Error(t, err)
				require.Contains(t, string(result), ".algorithmProperties."+tc.invalidField)
				require.Contains(t, string(result), "must be one of the following")
				_, statErr := os.Stat(output)
				require.ErrorIs(t, statErr, os.ErrNotExist, "invalid CBOM must not be published")
				return
			}
			require.NoErrorf(t, err, "CLI output: %s", result)
			var bom cdx.BOM
			readJSON(t, output, &bom)
			require.Equal(t, cdx.SpecVersion1_7, bom.SpecVersion)
			require.NotNil(t, bom.Components)
			require.Len(t, *bom.Components, 2)
			byName := make(map[string]cdx.Component)
			for _, component := range *bom.Components {
				byName[component.Name] = component
				require.Equal(t, cdx.ComponentTypeCryptographicAsset, component.Type)
				require.NotEmpty(t, component.BOMRef)
			}
			aes := byName["AES-CBC-PKCS5Padding"]
			require.NotNil(t, aes.CryptoProperties)
			props := aes.CryptoProperties.AlgorithmProperties
			require.Equal(t, "block-cipher", string(props.Primitive))
			require.Equal(t, "cbc", string(props.Mode))
			require.Equal(t, tc.expected, string(props.Padding))
			require.Empty(t, aes.CryptoProperties.OID, "ambiguous AES family must not gain an OID")
			require.NotNil(t, aes.Evidence)
			require.Len(t, *aes.Evidence.Occurrences, 1)
			occurrence := (*aes.Evidence.Occurrences)[0]
			require.Equal(t, sourcePath, occurrence.Location)
			require.NotNil(t, occurrence.Line)
			require.Equal(t, 31, *occurrence.Line)
			require.Equal(t, "scanoss:match,"+match, occurrence.AdditionalContext)
			evidence, err := json.Marshal(aes.Evidence.Identity)
			require.NoError(t, err)
			require.Contains(t, string(evidence), "scanoss:ruleid,"+ruleID)
			sha := byName["SHA-256"]
			require.NotNil(t, sha.CryptoProperties)
			require.Equal(t, "2.16.840.1.101.3.4.2.1", sha.CryptoProperties.OID)
			require.Equal(t, "hash", string(sha.CryptoProperties.AlgorithmProperties.Primitive))
		})
	}
}
