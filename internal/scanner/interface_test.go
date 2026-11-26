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

package scanner_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

func TestInfo_Fields(t *testing.T) {
	info := scanner.Info{
		Name:        "semgrep",
		Version:     "1.45.0",
		Description: "Static analysis tool",
	}

	if info.Name != "semgrep" {
		t.Errorf("Expected Name to be 'semgrep', got '%s'", info.Name)
	}

	if info.Version != "1.45.0" {
		t.Errorf("Expected Version to be '1.45.0', got '%s'", info.Version)
	}

	if info.Description != "Static analysis tool" {
		t.Errorf("Expected Description to be 'Static analysis tool', got '%s'", info.Description)
	}
}

func TestInfo_EmptyFields(t *testing.T) {
	// Test that Info can be created with empty fields
	info := scanner.Info{}

	if info.Name != "" {
		t.Errorf("Expected empty Name, got '%s'", info.Name)
	}

	if info.Version != "" {
		t.Errorf("Expected empty Version, got '%s'", info.Version)
	}

	if info.Description != "" {
		t.Errorf("Expected empty Description, got '%s'", info.Description)
	}
}

func TestConfig_TimeoutZeroValue(t *testing.T) {
	config := scanner.Config{
		Timeout: 0, // Zero value - should use default
	}

	if config.Timeout != 0 {
		t.Errorf("Expected Timeout to be 0 (zero value), got %v", config.Timeout)
	}
}
