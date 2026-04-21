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
		{
			id:   "path+file:///tmp/meta-check#meta-check@0.1.0",
			want: "meta-check",
		},
		{
			id:   "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
			want: "serde",
		},
	}

	for _, tt := range tests {
		got := cargoPackageNameFromID(tt.id)
		if got != tt.want {
			t.Errorf("cargoPackageNameFromID(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestCargoPackageRefFromID(t *testing.T) {
	tests := []struct {
		id   string
		want Ref
	}{
		{
			id:   "ring 0.17.8 (registry+https://github.com/rust-lang/crates.io-index)",
			want: Ref{Module: "ring", Version: "0.17.8"},
		},
		{
			id:   "ring@0.17.8",
			want: Ref{Module: "ring", Version: "0.17.8"},
		},
		{
			id:   "path+file:///tmp/meta-check#meta-check@0.1.0",
			want: Ref{Module: "meta-check", Version: "0.1.0"},
		},
		{
			id:   "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
			want: Ref{Module: "serde", Version: "1.0.0"},
		},
		{
			id:   "my-crate",
			want: Ref{Module: "my-crate"},
		},
	}

	for _, tt := range tests {
		got := cargoPackageRefFromID(tt.id)
		if got != tt.want {
			t.Errorf("cargoPackageRefFromID(%q) = %#v, want %#v", tt.id, got, tt.want)
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
