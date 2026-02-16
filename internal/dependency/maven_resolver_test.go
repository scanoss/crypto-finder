package dependency

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMavenResolver_ParseRootModule(t *testing.T) {
	r := NewMavenResolver()

	t.Run("group-id", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId></project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}

		root, err := r.parseRootModule(dir)
		if err != nil {
			t.Fatalf("parseRootModule: %v", err)
		}
		if root != "com.acme" {
			t.Fatalf("root = %q, want com.acme", root)
		}
	})

	t.Run("parent-group-id", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project><parent><groupId>org.parent</groupId></parent><artifactId>app</artifactId></project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}

		root, err := r.parseRootModule(dir)
		if err != nil {
			t.Fatalf("parseRootModule: %v", err)
		}
		if root != "org.parent" {
			t.Fatalf("root = %q, want org.parent", root)
		}
	})

	t.Run("missing-group-id", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project><artifactId>app</artifactId></project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}

		_, err := r.parseRootModule(dir)
		if err == nil || !strings.Contains(err.Error(), "cannot determine groupId") {
			t.Fatalf("expected missing groupId error, got %v", err)
		}
	})
}

func TestMavenResolver_ParseOutputs(t *testing.T) {
	r := NewMavenResolver()

	deps := r.parseDependencyList(`
The following files have been resolved:
org.example:lib:jar:1.2.3:compile
org.example:lib:jar:1.2.3:compile
com.classified:native:jar:linux-x86_64:4.5.6:compile
none
com.acme:tool:jar:2.0.0:runtime
`) // parseDependencyList deduplicates by module
	if len(deps) != 3 {
		t.Fatalf("deps len = %d, want 3", len(deps))
	}

	if deps[1].Module != "com.classified:native" || deps[1].Version != "4.5.6" {
		t.Fatalf("classifier coordinate parsed incorrectly: %#v", deps[1])
	}

	graph := r.parseTreeOutput(`
com.acme:app:jar:1.0.0:compile
+- org.example:lib:jar:1.2.3:compile
|  \- com.acme:tool:jar:2.0.0:runtime
\- org.other:util:jar:3.0.0:compile
`)
	if len(graph["com.acme:app"]) != 2 {
		t.Fatalf("root children len = %d, want 2", len(graph["com.acme:app"]))
	}
	if len(graph["org.example:lib"]) != 1 || graph["org.example:lib"][0] != "com.acme:tool" {
		t.Fatalf("unexpected nested edge parsing: %#v", graph)
	}
}

func TestMavenResolver_Resolve(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	// Create source JAR for one dependency in ~/.m2/repository
	jarPath := filepath.Join(home, ".m2", "repository", "org", "example", "lib", "1.2.3", "lib-1.2.3-sources.jar")
	if err := os.MkdirAll(filepath.Dir(jarPath), 0o755); err != nil {
		t.Fatalf("mkdir m2 repo: %v", err)
	}
	createZipArchive(t, jarPath, map[string]string{"src/Lib.java": "class Lib {}", "README.md": "x"})

	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
  esac
done
if [ "$1" = "dependency:list" ]; then
  cat > "$out" <<'EOF_LIST'
org.example:lib:jar:1.2.3:compile
org.other:util:jar:3.0.0:compile
EOF_LIST
  exit 0
fi
if [ "$1" = "dependency:tree" ]; then
  cat > "$out" <<'EOF_TREE'
com.acme:app:jar:1.0.0:compile
+- org.example:lib:jar:1.2.3:compile
\- org.other:util:jar:3.0.0:compile
EOF_TREE
  exit 0
fi
if [ "$1" = "dependency:sources" ]; then
  exit 0
fi
echo "unexpected args: $*" >&2
exit 1
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project, -1)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if r.Ecosystem() != "java" {
		t.Fatalf("Ecosystem = %q, want java", r.Ecosystem())
	}
	if result.RootModule != "com.acme" {
		t.Fatalf("RootModule = %q, want com.acme", result.RootModule)
	}

	// All resolved dependencies should be included; source directory is best-effort.
	if len(result.Dependencies) != 2 {
		t.Fatalf("Dependencies len = %d, want 2", len(result.Dependencies))
	}

	withSources := result.Dependencies[0]
	if withSources.Module != "org.example:lib" || withSources.Version != "1.2.3" {
		t.Fatalf("unexpected dependency with sources: %#v", withSources)
	}
	if withSources.Dir == "" {
		t.Fatal("expected extracted source directory for dependency")
	}
	if _, err := os.Stat(filepath.Join(withSources.Dir, "src", "Lib.java")); err != nil {
		t.Fatalf("expected extracted source file: %v", err)
	}

	withoutSources := result.Dependencies[1]
	if withoutSources.Module != "org.other:util" || withoutSources.Version != "3.0.0" {
		t.Fatalf("unexpected dependency without sources: %#v", withoutSources)
	}
	if withoutSources.Dir != "" {
		t.Fatalf("expected empty source directory for dependency without sources, got %q", withoutSources.Dir)
	}

	if len(result.Graph["com.acme:app"]) != 2 {
		t.Fatalf("graph root children len = %d, want 2", len(result.Graph["com.acme:app"]))
	}
}
