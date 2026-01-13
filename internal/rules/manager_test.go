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

package rules

import (
	"errors"
	"testing"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	source := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{"/path/to/rules"}, nil
		},
	}

	manager := NewManager(source)

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	if len(manager.sources) != 1 {
		t.Errorf("Expected 1 source, got %d", len(manager.sources))
	}
}

func TestManager_Load_SingleSource(t *testing.T) {
	t.Parallel()

	source := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{"/path/to/go.yaml", "/path/to/python.yaml"}, nil
		},
	}

	manager := NewManager(source)
	paths, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(paths))
	}
}

func TestManager_Load_MultipleSources(t *testing.T) {
	t.Parallel()

	source1 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{"/path/to/go.yaml"}, nil
		},
		nameFunc: func() string {
			return "source1"
		},
	}

	source2 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{"/path/to/python.yaml"}, nil
		},
		nameFunc: func() string {
			return "source2"
		},
	}

	manager := NewManager(source1, source2)
	paths, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// MultiSource should aggregate both
	if len(paths) != 2 {
		t.Errorf("Expected 2 paths from 2 sources, got %d", len(paths))
	}
}

func TestManager_Load_ErrorPropagation(t *testing.T) {
	t.Parallel()

	testErr := errors.New("failed to load rules")

	source := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return nil, testErr
		},
	}

	manager := NewManager(source)
	_, err := manager.Load()

	if err == nil {
		t.Fatal("Expected error but got none")
	}

	if !errors.Is(err, testErr) {
		t.Errorf("Expected testErr, got: %v", err)
	}
}

// mockRuleSource is a test helper.
type mockRuleSource struct {
	loadFunc func() ([]string, error)
	nameFunc func() string
}

func (m *mockRuleSource) Load() ([]string, error) {
	if m.loadFunc != nil {
		return m.loadFunc()
	}
	return []string{}, nil
}

func (m *mockRuleSource) Name() string {
	if m.nameFunc != nil {
		return m.nameFunc()
	}
	return "mock-source"
}
