package dependency

import (
	"encoding/json"
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
	raw := []byte(`{
		"packages": [
			{
				"id": "path+file:///workspace/app#app@0.1.0",
				"name": "app",
				"version": "0.1.0",
				"manifest_path": "/workspace/app/Cargo.toml",
				"source": null
			}
		],
		"workspace_members": ["path+file:///workspace/app#app@0.1.0"],
		"resolve": {
			"root": "path+file:///workspace/app#app@0.1.0",
			"nodes": []
		},
		"workspace_root": "/workspace/app"
	}`)

	var meta cargoMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if len(meta.WorkspaceMembers) != 1 || meta.WorkspaceMembers[0] != "path+file:///workspace/app#app@0.1.0" {
		t.Fatalf("unexpected workspace_members: %#v", meta.WorkspaceMembers)
	}
	if meta.Resolve.Root != "path+file:///workspace/app#app@0.1.0" {
		t.Fatalf("Resolve.Root = %q", meta.Resolve.Root)
	}
	if len(meta.Packages) != 1 || meta.Packages[0].ID != "path+file:///workspace/app#app@0.1.0" {
		t.Fatalf("unexpected package ids: %#v", meta.Packages)
	}
}

func TestNewCargoResolveResult_UsesWorkspaceMembersAndResolveRoot(t *testing.T) {
	registrySrc := "registry+https://github.com/rust-lang/crates.io-index"
	meta := &cargoMetadata{
		Packages: []cargoPackage{
			{
				ID:           "path+file:///workspace/app#app@0.1.0",
				Name:         "app",
				Version:      "0.1.0",
				ManifestPath: "/workspace/app/Cargo.toml",
				Source:       nil,
			},
			{
				ID:           "path+file:///workspace/vendor/local-helper#local-helper@0.2.0",
				Name:         "local-helper",
				Version:      "0.2.0",
				ManifestPath: "/workspace/vendor/local-helper/Cargo.toml",
				Source:       nil,
			},
			{
				ID:           "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
				Name:         "serde",
				Version:      "1.0.0",
				ManifestPath: "/cargo/registry/src/serde/Cargo.toml",
				Source:       &registrySrc,
			},
		},
		WorkspaceMembers: []string{"path+file:///workspace/app#app@0.1.0"},
		Resolve: cargoResolve{
			Root: "path+file:///workspace/app#app@0.1.0",
		},
	}

	result := newCargoResolveResult(meta)

	if result.RootModule != "app" {
		t.Fatalf("RootModule = %q, want app", result.RootModule)
	}
	if len(result.WorkspaceMembers) != 1 || result.WorkspaceMembers[0].Name != "app" {
		t.Fatalf("unexpected workspace members: %#v", result.WorkspaceMembers)
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("Dependencies len = %d, want 2", len(result.Dependencies))
	}
	if result.Dependencies[0].Module != "local-helper" {
		t.Fatalf("expected local path dependency to remain external, got %#v", result.Dependencies[0])
	}
}

func TestNewCargoResolveResult_FallsBackWhenCanonicalIDsMissing(t *testing.T) {
	meta := &cargoMetadata{
		Packages: []cargoPackage{
			{
				Name:         "app",
				Version:      "0.1.0",
				ManifestPath: "/workspace/app/Cargo.toml",
			},
			{
				Name:         "serde",
				Version:      "1.0.0",
				ManifestPath: "/cargo/registry/src/serde/Cargo.toml",
			},
		},
		WorkspaceMembers: []string{"path+file:///workspace/app#app@0.1.0"},
		Resolve: cargoResolve{
			Root: "path+file:///workspace/app#app@0.1.0",
		},
	}

	result := newCargoResolveResult(meta)

	if result.RootModule != "app" {
		t.Fatalf("RootModule = %q, want app", result.RootModule)
	}
	if len(result.WorkspaceMembers) != 1 || result.WorkspaceMembers[0].Name != "app" {
		t.Fatalf("unexpected workspace members: %#v", result.WorkspaceMembers)
	}
}

func TestNewCargoResolveResult_FallsBackWhenResolveRootMissing(t *testing.T) {
	meta := &cargoMetadata{
		Packages: []cargoPackage{
			{
				ID:           "path+file:///workspace/app#app@0.1.0",
				Name:         "app",
				Version:      "0.1.0",
				ManifestPath: "/workspace/app/Cargo.toml",
			},
			{
				ID:           "path+file:///workspace/lib#lib@0.2.0",
				Name:         "lib",
				Version:      "0.2.0",
				ManifestPath: "/workspace/lib/Cargo.toml",
			},
		},
		WorkspaceMembers: []string{
			"path+file:///workspace/app#app@0.1.0",
			"path+file:///workspace/lib#lib@0.2.0",
		},
	}

	result := newCargoResolveResult(meta)

	if result.RootModule != "app" {
		t.Fatalf("RootModule = %q, want app", result.RootModule)
	}
}
