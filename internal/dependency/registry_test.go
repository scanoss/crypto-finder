package dependency

import (
	"context"
	"strings"
	"testing"
)

type noopResolver struct{}

func (n *noopResolver) Resolve(_ context.Context, _ string) (*ResolveResult, error) {
	return &ResolveResult{}, nil
}

func (n *noopResolver) Ecosystem() string {
	return "noop"
}

func TestRegistry_RegisterGet(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	resolver := &noopResolver{}

	r.Register("go", resolver)

	got, err := r.Get("go")
	if err != nil {
		t.Fatalf("Get(go) unexpected error: %v", err)
	}
	if got != resolver {
		t.Fatal("registry returned unexpected resolver instance")
	}
}

func TestRegistry_GetMissing(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	_, err := r.Get("missing")
	if err == nil || !strings.Contains(err.Error(), "no resolver registered") {
		t.Fatalf("expected missing resolver error, got %v", err)
	}
}
