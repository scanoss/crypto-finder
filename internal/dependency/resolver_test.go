package dependency

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestDependencyRefKey(t *testing.T) {
	t.Parallel()

	if got := (Ref{}).Key(); got != "" {
		t.Fatalf("Key() = %q, want empty", got)
	}
	if got := (Ref{Module: "org.example:lib"}).Key(); got != "org.example:lib" {
		t.Fatalf("Key() = %q, want org.example:lib", got)
	}
	if got := (Ref{Module: "org.example:lib", Version: "1.2.3"}).Key(); got != "org.example:lib@1.2.3" {
		t.Fatalf("Key() = %q, want org.example:lib@1.2.3", got)
	}
}

// TestLocalAsUnpinned: an online request keeps the registry dependencies and
// lists each local one as unpinned, naming its directory from the target.
func TestLocalAsUnpinned(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	result := &ResolveResult{
		Source: "go.mod",
		Dependencies: []Dependency{
			{Module: "example.com/registry", Version: "v1.0.0"},
			{Module: "example.com/liba", Version: "v1.0.0", Dir: filepath.Join(root, "liba"), Local: true},
		},
	}
	moved := result.LocalAsUnpinned(filepath.Join(root, "app"))
	if len(moved) != 1 || moved[0].Module != "example.com/liba" {
		t.Errorf("moved %+v, want liba", moved)
	}
	if want := []Dependency{{Module: "example.com/registry", Version: "v1.0.0"}}; !reflect.DeepEqual(result.Dependencies, want) {
		t.Errorf("dependencies %+v, want %+v", result.Dependencies, want)
	}
	if want := []UnpinnedDependency{{Module: "example.com/liba", Specifier: "path ../liba", Manifest: "go.mod"}}; !reflect.DeepEqual(result.Unpinned, want) {
		t.Errorf("unpinned %+v, want %+v", result.Unpinned, want)
	}
}
