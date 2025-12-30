package rules

import (
	"errors"
	"testing"
)

func TestMultiSource_Load_AggregatesSources(t *testing.T) {
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

	multiSource := NewMultiSource(source1, source2)
	paths, err := multiSource.Load()

	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(paths) != 2 {
		t.Errorf("Expected 2 aggregated paths, got %d", len(paths))
	}
}

func TestMultiSource_Load_Deduplicates(t *testing.T) {
	t.Parallel()

	duplicatePath := "/path/to/go.yaml"

	source1 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{duplicatePath}, nil
		},
	}

	source2 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{duplicatePath}, nil
		},
	}

	multiSource := NewMultiSource(source1, source2)
	paths, err := multiSource.Load()

	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(paths) != 1 {
		t.Errorf("Expected 1 deduplicated path, got %d", len(paths))
	}
}

func TestMultiSource_Load_ErrorFromFirstSource(t *testing.T) {
	t.Parallel()

	testErr := errors.New("source1 error")

	source1 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return nil, testErr
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

	multiSource := NewMultiSource(source1, source2)
	_, err := multiSource.Load()

	if err == nil {
		t.Fatal("Expected error from first source")
	}

	if !errors.Is(err, testErr) {
		t.Errorf("Expected testErr, got: %v", err)
	}
}

func TestMultiSource_Load_AllSourcesFail(t *testing.T) {
	t.Parallel()

	err1 := errors.New("source1 error")
	err2 := errors.New("source2 error")

	source1 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return nil, err1
		},
		nameFunc: func() string {
			return "source1"
		},
	}

	source2 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return nil, err2
		},
		nameFunc: func() string {
			return "source2"
		},
	}

	multiSource := NewMultiSource(source1, source2)
	_, err := multiSource.Load()

	if err == nil {
		t.Fatal("Expected error when all sources fail")
	}
}

func TestMultiSource_Name(t *testing.T) {
	t.Parallel()

	source1 := &mockRuleSource{
		nameFunc: func() string {
			return "source1"
		},
	}

	source2 := &mockRuleSource{
		nameFunc: func() string {
			return "source2"
		},
	}

	multiSource := NewMultiSource(source1, source2)
	name := multiSource.Name()

	// Should contain both source names
	if name == "" {
		t.Error("Name() returned empty string")
	}
}

func TestMultiSource_Load_EmptySources(t *testing.T) {
	t.Parallel()

	multiSource := NewMultiSource()
	paths, err := multiSource.Load()

	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(paths) != 0 {
		t.Errorf("Expected 0 paths from empty sources, got %d", len(paths))
	}
}

func TestMultiSource_Load_SingleEmptySource(t *testing.T) {
	t.Parallel()

	source := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{}, nil
		},
	}

	multiSource := NewMultiSource(source)
	paths, err := multiSource.Load()

	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(paths) != 0 {
		t.Errorf("Expected 0 paths from empty source, got %d", len(paths))
	}
}

func TestMultiSource_Load_PartialSuccess(t *testing.T) {
	t.Parallel()

	source1 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return nil, errors.New("source1 failed")
		},
		nameFunc: func() string {
			return "failing-source"
		},
	}

	source2 := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{"/path/to/rules.yaml"}, nil
		},
		nameFunc: func() string {
			return "working-source"
		},
	}

	// First source fails, should propagate error
	multiSource := NewMultiSource(source1, source2)
	_, err := multiSource.Load()

	if err == nil {
		t.Fatal("Expected error when first source fails")
	}
}

func TestMultiSource_Load_Integration(t *testing.T) {
	t.Parallel()

	// Use real LocalRuleSource with testdata
	localSource := NewLocalRuleSource(
		[]string{"../../testdata/rules/go.yaml"},
		[]string{"../../testdata/rules"},
	)

	multiSource := NewMultiSource(localSource)
	paths, err := multiSource.Load()

	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should find rules from testdata (deduplicated)
	if len(paths) < 2 {
		t.Errorf("Expected at least 2 rule paths, got %d", len(paths))
	}
}

