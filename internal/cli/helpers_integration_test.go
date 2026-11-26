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
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// repositoryRoot is the root of this repository.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller")
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// buildCryptoFinder builds the CLI from the repository at root.
func buildCryptoFinder(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crypto-finder")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", path, "./cmd/crypto-finder")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build output:\n%s", output)
	return path
}

// readJSON decodes the JSON file at path into value.
func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoErrorf(t, json.Unmarshal(data, value), "decode %s:\n%s", path, data)
}

// allAssets lists the assets of every finding of report.
func allAssets(report entities.InterimReport) []entities.CryptographicAsset {
	count := 0
	for i := range report.Findings {
		count += len(report.Findings[i].CryptographicAssets)
	}
	assets := make([]entities.CryptographicAsset, 0, count)
	for _, finding := range report.Findings {
		assets = append(assets, finding.CryptographicAssets...)
	}
	return assets
}
