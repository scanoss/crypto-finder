package dependency

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCargoResolver_Resolve(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "cargo", `#!/bin/sh
if [ "$1" = "metadata" ]; then
  cat <<'JSON'
{
  "packages": [
    {
      "name": "my-app",
      "version": "0.1.0",
      "manifest_path": "/workspace/my-app/Cargo.toml",
      "source": null
    },
    {
      "name": "crypto-lib",
      "version": "1.2.3",
      "manifest_path": "/cargo/registry/src/crypto-lib/Cargo.toml",
      "source": "registry+https://github.com/rust-lang/crates.io-index"
    },
    {
      "name": "serde",
      "version": "1.0.0",
      "manifest_path": "/cargo/registry/src/serde/Cargo.toml",
      "source": "registry+https://github.com/rust-lang/crates.io-index"
    }
  ],
  "resolve": {
    "nodes": [
      {
        "id": "my-app 0.1.0 (path+file:///workspace/my-app)",
        "deps": [
          {"pkg": "crypto-lib 1.2.3 (registry+https://github.com/rust-lang/crates.io-index)"}
        ]
      },
      {
        "id": "crypto-lib 1.2.3 (registry+https://github.com/rust-lang/crates.io-index)",
        "deps": [
          {"pkg": "serde@1.0.0"}
        ]
      },
      {
        "id": "serde@1.0.0",
        "deps": []
      }
    ]
  },
  "workspace_root": "/workspace/my-app"
}
JSON
  exit 0
fi
exit 1
`)
	prependPath(t, binDir)

	r := NewCargoResolver()
	result, err := r.Resolve(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if result.RootModule != "my-app" {
		t.Fatalf("RootModule = %q, want my-app", result.RootModule)
	}
	if len(result.WorkspaceMembers) != 1 || result.WorkspaceMembers[0].Name != "my-app" {
		t.Fatalf("unexpected workspace members: %#v", result.WorkspaceMembers)
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("Dependencies len = %d, want 2", len(result.Dependencies))
	}
	if len(result.Graph["my-app"]) != 1 || result.Graph["my-app"][0] != "crypto-lib" {
		t.Fatalf("unexpected graph for root: %#v", result.Graph)
	}
	if len(result.Graph["crypto-lib"]) != 1 || result.Graph["crypto-lib"][0] != "serde" {
		t.Fatalf("unexpected graph for crypto-lib: %#v", result.Graph)
	}
}

func TestCargoResolver_MetadataErrors(t *testing.T) {
	r := NewCargoResolver()

	t.Run("command-failure", func(t *testing.T) {
		binDir := t.TempDir()
		writeExecutable(t, binDir, "cargo", `#!/bin/sh
echo "boom" >&2
exit 2
`)
		prependPath(t, binDir)

		_, err := r.cargoMetadata(context.Background(), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "cargo metadata") {
			t.Fatalf("expected command error, got %v", err)
		}
	})

	t.Run("invalid-json", func(t *testing.T) {
		binDir := t.TempDir()
		writeExecutable(t, binDir, "cargo", `#!/bin/sh
echo "{invalid-json"
exit 0
`)
		prependPath(t, binDir)

		_, err := r.cargoMetadata(context.Background(), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "failed to parse cargo metadata output") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("resolve-wraps-error", func(t *testing.T) {
		binDir := t.TempDir()
		writeExecutable(t, binDir, "cargo", `#!/bin/sh
exit 1
`)
		prependPath(t, binDir)

		_, err := r.Resolve(context.Background(), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "failed to get cargo metadata") {
			t.Fatalf("expected wrapped resolve error, got %v", err)
		}
	})
}

func TestCargoResolver_MetadataManifestPathPassed(t *testing.T) {
	binDir := t.TempDir()
	argsLog := filepath.Join(binDir, "args.log")
	writeExecutable(t, binDir, "cargo", `#!/bin/sh
echo "$@" > "`+argsLog+`"
cat <<'JSON'
{"packages":[],"resolve":{"nodes":[]},"workspace_root":"/tmp"}
JSON
`)
	prependPath(t, binDir)

	r := NewCargoResolver()
	target := t.TempDir()
	if _, err := r.cargoMetadata(context.Background(), target); err != nil {
		t.Fatalf("cargoMetadata: %v", err)
	}

	args, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatalf("read args log: %v", err)
	}
	if !strings.Contains(string(args), "--manifest-path "+filepath.Join(target, "Cargo.toml")) {
		t.Fatalf("expected manifest path argument, got: %s", string(args))
	}
}
