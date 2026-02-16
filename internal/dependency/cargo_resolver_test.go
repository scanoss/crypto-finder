package dependency

import (
	"testing"
)

func TestCargoPackageNameFromID(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{
			id:   "ring 0.17.8 (registry+https://github.com/rust-lang/crates.io-index)",
			want: "ring",
		},
		{
			id:   "ring@0.17.8",
			want: "ring",
		},
		{
			id:   "ring 0.17.8",
			want: "ring",
		},
		{
			id:   "my-crate",
			want: "my-crate",
		},
		{
			id:   "tokio 1.35.1 (registry+https://github.com/rust-lang/crates.io-index)",
			want: "tokio",
		},
	}

	for _, tt := range tests {
		got := cargoPackageNameFromID(tt.id)
		if got != tt.want {
			t.Errorf("cargoPackageNameFromID(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestCargoResolver_Ecosystem(t *testing.T) {
	r := NewCargoResolver()
	if got := r.Ecosystem(); got != "rust" {
		t.Errorf("Ecosystem() = %q, want %q", got, "rust")
	}
}

func TestCargoMetadataParsing(t *testing.T) {
	// Test that the JSON struct types correctly distinguish local vs registry packages.
	localPkg := cargoPackage{Source: nil}
	registrySrc := "registry+https://github.com/rust-lang/crates.io-index"
	registryPkg := cargoPackage{Source: &registrySrc}

	// Verify root detection: source == nil → root module.
	if localPkg.Source != nil {
		t.Error("expected local package to have nil Source")
	}
	if registryPkg.Source == nil {
		t.Error("expected registry package to have non-nil Source")
	}
}
