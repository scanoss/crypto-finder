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

package scanner

import (
	"context"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// mockScanner implements Scanner interface for testing.
type mockScanner struct {
	name    string
	version string
}

func (m *mockScanner) Initialize(_ Config) error {
	return nil
}

func (m *mockScanner) Scan(_ context.Context, _ string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
	return &entities.InterimReport{}, nil
}

func (m *mockScanner) GetInfo() Info {
	return Info{
		Name:    m.name,
		Version: m.version,
	}
}

func TestNewRegistry(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	if registry == nil {
		t.Fatal("NewRegistry() returned nil")
	}

	if registry.scanners == nil {
		t.Error("Registry scanners map should be initialized")
	}
}

func TestRegistry_Register(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	scanner := &mockScanner{name: "test-scanner", version: "1.0.0"}

	registry.Register("test", scanner)

	// Verify it was registered
	if !registry.Has("test") {
		t.Error("Scanner should be registered")
	}
}

func TestRegistry_Get(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	scanner := &mockScanner{name: "semgrep", version: "1.0.0"}

	registry.Register("semgrep", scanner)

	// Test successful get
	retrieved, err := registry.Get("semgrep")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Retrieved scanner should not be nil")
	}

	// Verify it's the same scanner
	info := retrieved.GetInfo()
	if info.Name != "semgrep" {
		t.Errorf("Expected scanner name 'semgrep', got '%s'", info.Name)
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	_, err := registry.Get("nonexistent")

	if err == nil {
		t.Fatal("Expected error for non-existent scanner")
	}

	// Error should mention the scanner name
	errStr := err.Error()
	if errStr == "" {
		t.Error("Error message should not be empty")
	}
}

func TestRegistry_Available(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	// Empty registry
	available := registry.Available()
	if len(available) != 0 {
		t.Errorf("Expected 0 scanners, got %d", len(available))
	}

	// Add scanners
	registry.Register("semgrep", &mockScanner{name: "semgrep"})
	registry.Register("opengrep", &mockScanner{name: "opengrep"})
	registry.Register("cbom-toolkit", &mockScanner{name: "cbom"})

	available = registry.Available()
	if len(available) != 3 {
		t.Fatalf("Expected 3 scanners, got %d", len(available))
	}

	// Should be sorted
	expected := []string{"cbom-toolkit", "opengrep", "semgrep"}
	for i, name := range expected {
		if available[i] != name {
			t.Errorf("Expected scanner[%d] = '%s', got '%s'", i, name, available[i])
		}
	}
}

func TestRegistry_Has(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	scanner := &mockScanner{name: "test"}

	// Should not have scanner initially
	if registry.Has("test") {
		t.Error("Registry should not have 'test' scanner yet")
	}

	// Register and check again
	registry.Register("test", scanner)

	if !registry.Has("test") {
		t.Error("Registry should have 'test' scanner")
	}

	// Check non-existent
	if registry.Has("nonexistent") {
		t.Error("Registry should not have 'nonexistent' scanner")
	}
}

func TestRegistry_RegisterOverwrite(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	scanner1 := &mockScanner{name: "v1", version: "1.0.0"}
	scanner2 := &mockScanner{name: "v2", version: "2.0.0"}

	// Register first scanner
	registry.Register("test", scanner1)

	retrieved, _ := registry.Get("test")
	if retrieved.GetInfo().Version != "1.0.0" {
		t.Error("Expected version 1.0.0")
	}

	// Overwrite with second scanner
	registry.Register("test", scanner2)

	retrieved, _ = registry.Get("test")
	if retrieved.GetInfo().Version != "2.0.0" {
		t.Error("Expected version 2.0.0 after overwrite")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	// Simulate concurrent registration and access
	done := make(chan bool, 2)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			scanner := &mockScanner{name: "concurrent"}
			registry.Register("concurrent", scanner)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			registry.Get("concurrent")
			registry.Has("concurrent")
			registry.Available()
		}
		done <- true
	}()

	// Wait for both to complete
	<-done
	<-done

	// Verify registry is still functional
	if !registry.Has("concurrent") {
		t.Error("Scanner should be registered after concurrent access")
	}
}
