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

// mockRuleSource is a test helper
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
