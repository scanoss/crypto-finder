package dependency

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/javaruntime"
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
org.example:lib:jar:2.0.0:compile
com.classified:native:jar:linux-x86_64:4.5.6:compile
none
com.acme:tool:jar:2.0.0:runtime
`) // parseDependencyList deduplicates by module+version
	if len(deps) != 4 {
		t.Fatalf("deps len = %d, want 4", len(deps))
	}

	if deps[1].Module != "org.example:lib" || deps[1].Version != "2.0.0" {
		t.Fatalf("distinct version coordinate parsed incorrectly: %#v", deps[1])
	}
	if deps[2].Module != "com.classified:native" || deps[2].Version != "4.5.6" {
		t.Fatalf("classifier coordinate parsed incorrectly: %#v", deps[2])
	}
	if deps[3].Module != "com.acme:tool" || deps[3].Version != "2.0.0" {
		t.Fatalf("unexpected dependency ordering: %#v", deps)
	}
	if deps[1].Module == deps[0].Module && deps[1].Version == deps[0].Version {
		t.Fatalf("expected distinct versioned coordinates to be preserved, got %#v", deps)
	}

	graph := r.parseTreeOutput(`
com.acme:app:jar:1.0.0:compile
+- org.example:lib:jar:1.2.3:compile
|  \- com.acme:tool:jar:2.0.0:runtime
\- org.other:util:jar:3.0.0:compile
`)
	if len(graph["com.acme:app@1.0.0"]) != 2 {
		t.Fatalf("root children len = %d, want 2", len(graph["com.acme:app@1.0.0"]))
	}
	if len(graph["org.example:lib@1.2.3"]) != 1 || graph["org.example:lib@1.2.3"][0].Module != "com.acme:tool" || graph["org.example:lib@1.2.3"][0].Version != "2.0.0" {
		t.Fatalf("unexpected nested edge parsing: %#v", graph)
	}
}

func TestMavenResolver_ParseTreeOutput_PreservesDistinctVersions(t *testing.T) {
	r := NewMavenResolver()

	graph := r.parseTreeOutput(`
com.acme:core:jar:1.0.0:compile
\- org.example:lib:jar:8.0.2:compile
com.acme:web:jar:1.0.0:compile
\- org.example:lib:jar:5.39.0:compile
`)

	coreChildren := graph["com.acme:core@1.0.0"]
	if len(coreChildren) != 1 || coreChildren[0].Module != "org.example:lib" || coreChildren[0].Version != "8.0.2" {
		t.Fatalf("unexpected core children: %#v", coreChildren)
	}

	webChildren := graph["com.acme:web@1.0.0"]
	if len(webChildren) != 1 || webChildren[0].Module != "org.example:lib" || webChildren[0].Version != "5.39.0" {
		t.Fatalf("unexpected web children: %#v", webChildren)
	}
}

func TestMavenResolver_ListDependenciesPerModule_PreservesDistinctVersions(t *testing.T) {
	project := t.TempDir()
	pom := `<project>
		<groupId>com.acme</groupId>
		<artifactId>parent</artifactId>
		<packaging>pom</packaging>
		<modules><module>core</module><module>web</module></modules>
	</project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	os.MkdirAll(filepath.Join(project, "core"), 0o755)
	os.MkdirAll(filepath.Join(project, "web"), 0o755)

	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
pl_module=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
    -pl) pl_module="NEXT" ;;
    *)
      if [ "$pl_module" = "NEXT" ]; then
        pl_module="$arg"
      fi
      ;;
  esac
done
if echo "$@" | grep -q "dependency:list"; then
  if [ "$pl_module" = "core" ]; then
    cat > "$out" <<'EOF_CORE'
org.example:lib:jar:8.0.2:compile
EOF_CORE
    exit 0
  fi
  if [ "$pl_module" = "web" ]; then
    cat > "$out" <<'EOF_WEB'
org.example:lib:jar:5.39.0:compile
EOF_WEB
    exit 0
  fi
fi
exit 1
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.listDependenciesPerModule(context.Background(), project, []string{"core", "web"})
	if err != nil {
		t.Fatalf("listDependenciesPerModule: %v", err)
	}
	if len(result.deps) != 2 {
		t.Fatalf("deps len = %d, want 2", len(result.deps))
	}
	if result.deps[0].Module != "org.example:lib" || result.deps[0].Version != "8.0.2" {
		t.Fatalf("unexpected first dep: %#v", result.deps[0])
	}
	if result.deps[1].Module != "org.example:lib" || result.deps[1].Version != "5.39.0" {
		t.Fatalf("unexpected second dep: %#v", result.deps[1])
	}
}

func TestMavenResolver_ListDependencies_UsesConfiguredJavaHome(t *testing.T) {
	project := t.TempDir()
	pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	jdkHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(jdkHome, "release"), []byte("JAVA_VERSION=\"21.0.5\"\n"), 0o600); err != nil {
		t.Fatalf("write release: %v", err)
	}

	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
  esac
done
if [ "$JAVA_HOME" != "`+jdkHome+`" ]; then
  echo "unexpected JAVA_HOME=$JAVA_HOME" >&2
  exit 1
fi
cat > "$out" <<'EOF_LIST'
org.example:lib:jar:1.2.3:compile
EOF_LIST
exit 0
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	cfg, err := javaruntime.NewConfig("21", map[string]string{"21": jdkHome})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	r.SetJavaRuntime(cfg)

	result, err := r.listDependencies(context.Background(), project)
	if err != nil {
		t.Fatalf("listDependencies: %v", err)
	}
	if len(result.deps) != 1 || result.deps[0].Module != "org.example:lib" {
		t.Fatalf("unexpected deps: %#v", result.deps)
	}
}

func TestMavenResolver_RunMavenCommand_FailsForMismatchedConfiguredJavaHome(t *testing.T) {
	jdkHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(jdkHome, "release"), []byte("JAVA_VERSION=\"17.0.12\"\n"), 0o600); err != nil {
		t.Fatalf("write release: %v", err)
	}

	r := NewMavenResolver()
	cfg, err := javaruntime.NewConfig("21", map[string]string{"21": jdkHome})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	r.SetJavaRuntime(cfg)

	if _, err := r.runMavenCommand(context.Background(), mavenCommandOptions{
		dir:  t.TempDir(),
		args: []string{"-v"},
	}); err == nil {
		t.Fatal("expected mismatched configured JDK home to fail")
	}
}

func TestMavenResolver_InstallModules_ReturnsConfigureErrorWhenCommandResultIsNil(t *testing.T) {
	r := NewMavenResolver()
	r.SetJavaRuntime(javaruntime.Config{RequestedMajor: "21"})

	if err := r.installModules(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected installModules to return configure error")
	}
}

func TestMavenResolver_Resolve(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	// Create source JAR for one dependency in ~/.m2/repository
	jarPath := filepath.Join(home, ".m2", "repository", "org", "example", "lib", "1.2.3", "lib-1.2.3-sources.jar")
	if err := os.MkdirAll(filepath.Dir(jarPath), 0o755); err != nil {
		t.Fatalf("mkdir m2 repo: %v", err)
	}
	createZipArchive(t, jarPath, map[string]string{"src/Lib.java": "class Lib {}", "README.md": "x"})
	compiledJarPath := filepath.Join(home, ".m2", "repository", "org", "example", "lib", "1.2.3", "lib-1.2.3.jar")
	if err := os.WriteFile(compiledJarPath, []byte("jar"), 0o600); err != nil {
		t.Fatalf("write compiled jar: %v", err)
	}

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
	result, err := r.Resolve(context.Background(), project)
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
	if withSources.CompiledArtifactPath != compiledJarPath {
		t.Fatalf("CompiledArtifactPath = %q, want %q", withSources.CompiledArtifactPath, compiledJarPath)
	}
	if withSources.SourceArchivePath != jarPath {
		t.Fatalf("SourceArchivePath = %q, want %q", withSources.SourceArchivePath, jarPath)
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

	// Graph / VersionedGraph are intentionally not populated by Maven anymore:
	// `mvn dependency:tree` was minutes of work whose output had no consumer.
	// They exist on ResolveResult only because other resolvers (Gradle, Cargo)
	// still produce them. If a Maven downstream consumer ever needs the graph,
	// re-enable Step 6 in maven_resolver.go behind a flag and restore these
	// assertions.
	if len(result.Graph) != 0 {
		t.Fatalf("expected Graph to be empty (Maven no longer runs dependency:tree), got %d entries", len(result.Graph))
	}
	if len(result.VersionedGraph) != 0 {
		t.Fatalf("expected VersionedGraph to be empty, got %d entries", len(result.VersionedGraph))
	}
}

func TestMavenResolver_Resolve_SourceFallbackDownloadsMissingJar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	fixture := filepath.Join(t.TempDir(), "lib-1.2.3-sources.jar")
	createZipArchive(t, fixture, map[string]string{"src/Lib.java": "class Lib {}"})

	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
artifact=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
    -Dartifact=*) artifact="${arg#-Dartifact=}" ;;
  esac
done
case "$1" in
  dependency:list)
    cat > "$out" <<'EOF_LIST'
org.example:lib:jar:1.2.3:compile
EOF_LIST
    exit 0
    ;;
  dependency:tree)
    echo "com.acme:app:jar:1.0.0:compile" > "$out"
    exit 0
    ;;
  dependency:sources)
    exit 1
    ;;
  org.apache.maven.plugins:maven-dependency-plugin:*:get)
    if [ "$artifact" = "org.example:lib:1.2.3:jar:sources" ]; then
      dest="$HOME/.m2/repository/org/example/lib/1.2.3/lib-1.2.3-sources.jar"
      mkdir -p "$(dirname "$dest")"
      cp "`+fixture+`" "$dest"
      exit 0
    fi
    exit 1
    ;;
esac
exit 1
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1", len(result.Dependencies))
	}
	if result.Dependencies[0].Dir == "" {
		t.Fatal("expected fallback-downloaded source directory")
	}
	if _, err := os.Stat(filepath.Join(result.Dependencies[0].Dir, "src", "Lib.java")); err != nil {
		t.Fatalf("expected extracted fallback source file: %v", err)
	}
}

func TestMavenResolver_Resolve_SourceFallbackSkipsExistingJar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	jarPath := filepath.Join(home, ".m2", "repository", "org", "example", "lib", "1.2.3", "lib-1.2.3-sources.jar")
	if err := os.MkdirAll(filepath.Dir(jarPath), 0o755); err != nil {
		t.Fatalf("mkdir m2 repo: %v", err)
	}
	createZipArchive(t, jarPath, map[string]string{"src/Lib.java": "class Lib {}"})

	fallbackCalled := filepath.Join(t.TempDir(), "fallback-called")

	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
  esac
done
case "$1" in
  dependency:list)
    cat > "$out" <<'EOF_LIST'
org.example:lib:jar:1.2.3:compile
EOF_LIST
    exit 0
    ;;
  dependency:tree)
    echo "com.acme:app:jar:1.0.0:compile" > "$out"
    exit 0
    ;;
  dependency:sources)
    exit 0
    ;;
  org.apache.maven.plugins:maven-dependency-plugin:*:get)
    touch "`+fallbackCalled+`"
    exit 1
    ;;
esac
exit 1
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1", len(result.Dependencies))
	}
	if result.Dependencies[0].Dir == "" {
		t.Fatal("expected existing source jar to be used")
	}
	if _, err := os.Stat(fallbackCalled); !os.IsNotExist(err) {
		t.Fatalf("expected fallback fetch to be skipped, got stat err=%v", err)
	}
}

func TestMavenResolver_Resolve_SourceFallbackPartialSuccess(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	fixture := filepath.Join(t.TempDir(), "lib-1.2.3-sources.jar")
	createZipArchive(t, fixture, map[string]string{"src/Lib.java": "class Lib {}"})

	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
artifact=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
    -Dartifact=*) artifact="${arg#-Dartifact=}" ;;
  esac
done
case "$1" in
  dependency:list)
    cat > "$out" <<'EOF_LIST'
org.example:lib:jar:1.2.3:compile
org.other:util:jar:3.0.0:compile
EOF_LIST
    exit 0
    ;;
  dependency:tree)
    cat > "$out" <<'EOF_TREE'
com.acme:app:jar:1.0.0:compile
+- org.example:lib:jar:1.2.3:compile
\- org.other:util:jar:3.0.0:compile
EOF_TREE
    exit 0
    ;;
  dependency:sources)
    exit 1
    ;;
  org.apache.maven.plugins:maven-dependency-plugin:*:get)
    if [ "$artifact" = "org.example:lib:1.2.3:jar:sources" ]; then
      dest="$HOME/.m2/repository/org/example/lib/1.2.3/lib-1.2.3-sources.jar"
      mkdir -p "$(dirname "$dest")"
      cp "`+fixture+`" "$dest"
      exit 0
    fi
    exit 1
    ;;
esac
exit 1
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(result.Dependencies) != 2 {
		t.Fatalf("Dependencies len = %d, want 2", len(result.Dependencies))
	}
	if result.Dependencies[0].Dir == "" {
		t.Fatal("expected first dependency to have sources after fallback")
	}
	if result.Dependencies[1].Dir != "" {
		t.Fatalf("expected second dependency to remain without sources, got %q", result.Dependencies[1].Dir)
	}
}

func TestMavenResolver_ParseModules(t *testing.T) {
	r := NewMavenResolver()

	t.Run("multi-module", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project>
			<groupId>com.acme</groupId>
			<artifactId>parent</artifactId>
			<packaging>pom</packaging>
			<modules>
				<module>core</module>
				<module>web</module>
			</modules>
		</project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		// Create module directories
		os.MkdirAll(filepath.Join(dir, "core"), 0o755)
		os.MkdirAll(filepath.Join(dir, "web"), 0o755)

		modules, isMulti := r.parseModules(dir)
		if !isMulti {
			t.Fatal("expected multi-module project")
		}
		if len(modules) != 2 {
			t.Fatalf("modules len = %d, want 2", len(modules))
		}
	})

	t.Run("single-module", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project><groupId>com.acme</groupId><artifactId>app</artifactId></project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}

		_, isMulti := r.parseModules(dir)
		if isMulti {
			t.Fatal("expected single-module project")
		}
	})

	t.Run("missing-module-dir", func(t *testing.T) {
		dir := t.TempDir()
		pom := `<project>
			<groupId>com.acme</groupId>
			<modules><module>missing</module><module>exists</module></modules>
		</project>`
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		os.MkdirAll(filepath.Join(dir, "exists"), 0o755)

		modules, isMulti := r.parseModules(dir)
		if !isMulti {
			t.Fatal("expected multi-module (one valid module)")
		}
		if len(modules) != 1 || modules[0] != "exists" {
			t.Fatalf("modules = %v, want [exists]", modules)
		}
	})
}

func TestMavenResolver_Resolve_SkipsMavenWhenNoDependencies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	// pom.xml with NO dependencies - should skip Maven invocation entirely
	pom := `<project><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	// Create a fake mvn that fails if called
	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
echo "ERROR: Maven should not be called for pom.xml without dependencies" >&2
exit 1
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if result.RootModule != "org.bouncycastle" {
		t.Fatalf("RootModule = %q, want org.bouncycastle", result.RootModule)
	}

	// No dependencies should be found - the key is that we didn't call Maven
	if len(result.Dependencies) != 0 {
		t.Fatalf("Dependencies len = %d, want 0", len(result.Dependencies))
	}
}

func TestMavenResolver_IsInterModuleFailure(t *testing.T) {
	tests := []struct {
		name       string
		stderr     string
		groupID    string
		modules    []string
		wantResult bool
	}{
		{
			name:       "inter-module failure",
			stderr:     `Could not resolve dependencies for project me.zhengjie:eladmin-logging:jar:2.7\ndependency: me.zhengjie:eladmin-common:jar:2.7`,
			groupID:    "me.zhengjie",
			modules:    []string{"eladmin-common", "eladmin-logging"},
			wantResult: true,
		},
		{
			name:       "external dependency failure",
			stderr:     `Could not resolve dependencies for project com.acme:app:jar:1.0\nCould not find artifact org.unknown:lib:jar:1.0`,
			groupID:    "com.acme",
			modules:    []string{"core", "web"},
			wantResult: false,
		},
		{
			name:       "no resolution error",
			stderr:     `Some other Maven warning`,
			groupID:    "com.acme",
			modules:    []string{"core"},
			wantResult: false,
		},
		{
			name:       "empty inputs",
			stderr:     `Could not resolve dependencies`,
			groupID:    "",
			modules:    nil,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInterModuleFailure(tt.stderr, tt.groupID, tt.modules)
			if got != tt.wantResult {
				t.Fatalf("isInterModuleFailure() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func TestMavenResolver_Resolve_MultiModule_PartialSuccess(t *testing.T) {
	// Tier 1: mvn dependency:list exits non-zero but writes partial output.
	// The resolver should return the partial deps instead of failing.
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project>
		<groupId>com.acme</groupId>
		<artifactId>parent</artifactId>
		<packaging>pom</packaging>
		<modules><module>core</module><module>web</module></modules>
	</project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	os.MkdirAll(filepath.Join(project, "core"), 0o755)
	os.MkdirAll(filepath.Join(project, "web"), 0o755)
	// Write module pom.xml files for artifactId collection
	os.WriteFile(filepath.Join(project, "core", "pom.xml"),
		[]byte(`<project><artifactId>core</artifactId></project>`), 0o600)
	os.WriteFile(filepath.Join(project, "web", "pom.xml"),
		[]byte(`<project><artifactId>web</artifactId></project>`), 0o600)

	binDir := t.TempDir()
	// Mock mvn: dependency:list writes partial output but exits 1 (simulating reactor partial failure).
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
  esac
done
if echo "$@" | grep -q "dependency:list"; then
  if [ -n "$out" ]; then
    cat > "$out" <<'EOF_LIST'
org.example:lib:jar:1.2.3:compile
org.springframework:spring-core:jar:5.3.0:compile
EOF_LIST
  fi
  echo "BUILD FAILURE: some module failed" >&2
  exit 1
fi
if echo "$@" | grep -q "dependency:tree"; then
  if [ -n "$out" ]; then
    echo "" > "$out"
  fi
  exit 1
fi
if echo "$@" | grep -q "dependency:sources"; then
  exit 0
fi
exit 0
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve should not fail on partial success: %v", err)
	}

	// Should have captured partial deps from Tier 1
	if len(result.Dependencies) != 2 {
		t.Fatalf("Dependencies len = %d, want 2 (partial results)", len(result.Dependencies))
	}
	if result.Dependencies[0].Module != "org.example:lib" {
		t.Fatalf("unexpected first dep: %v", result.Dependencies[0])
	}

	// WorkspaceMembers should be populated for multi-module project
	if len(result.WorkspaceMembers) != 2 {
		t.Fatalf("WorkspaceMembers len = %d, want 2", len(result.WorkspaceMembers))
	}
}

func TestMavenResolver_Resolve_MultiModule_Tier2Fallback(t *testing.T) {
	// Tier 1 returns zero deps. Tier 2 (per-module) should be tried.
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project>
		<groupId>com.acme</groupId>
		<artifactId>parent</artifactId>
		<packaging>pom</packaging>
		<modules><module>core</module><module>web</module></modules>
	</project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	os.MkdirAll(filepath.Join(project, "core"), 0o755)
	os.MkdirAll(filepath.Join(project, "web"), 0o755)
	os.WriteFile(filepath.Join(project, "core", "pom.xml"),
		[]byte(`<project><artifactId>core</artifactId></project>`), 0o600)
	os.WriteFile(filepath.Join(project, "web", "pom.xml"),
		[]byte(`<project><artifactId>web</artifactId></project>`), 0o600)

	binDir := t.TempDir()
	// Mock mvn: reactor dependency:list writes nothing (simulates complete failure).
	// Per-module (-pl) calls succeed for "core" but fail for "web".
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
out=""
pl_module=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
    -pl) pl_module="NEXT" ;;
    *)
      if [ "$pl_module" = "NEXT" ]; then
        pl_module="$arg"
      fi
      ;;
  esac
done
if echo "$@" | grep -q "dependency:list"; then
  if [ -n "$pl_module" ] && [ "$pl_module" != "NEXT" ]; then
    # Per-module mode
    if [ "$pl_module" = "core" ]; then
      cat > "$out" <<'EOF_LIST'
org.example:lib:jar:1.2.3:compile
EOF_LIST
      exit 0
    else
      exit 1
    fi
  fi
  # Reactor mode: write empty file, exit 1
  if [ -n "$out" ]; then
    echo "" > "$out"
  fi
  exit 1
fi
if echo "$@" | grep -q "dependency:tree"; then
  if [ -n "$out" ]; then
    echo "" > "$out"
  fi
  exit 0
fi
if echo "$@" | grep -q "dependency:sources"; then
  exit 0
fi
exit 0
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Tier 2 should have resolved core's dependency
	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1 (from Tier 2 per-module)", len(result.Dependencies))
	}
	if result.Dependencies[0].Module != "org.example:lib" {
		t.Fatalf("unexpected dep: %v", result.Dependencies[0])
	}
}

func TestMavenResolver_ResolveModuleDependencies_ReturnsCreateTempError(t *testing.T) {
	missingTmp := filepath.Join(t.TempDir(), "missing-tmpdir")
	t.Setenv("TMPDIR", missingTmp)

	r := NewMavenResolver()
	deps, partial, err := r.resolveModuleDependencies(context.Background(), t.TempDir(), "core")
	if err == nil {
		t.Fatal("expected resolveModuleDependencies to return CreateTemp error")
	}
	if deps != nil {
		t.Fatalf("deps = %#v, want nil", deps)
	}
	if partial {
		t.Fatal("partial = true, want false")
	}
}

func TestMavenResolver_Resolve_MultiModule_Tier3Fallback(t *testing.T) {
	// Tier 1 returns zero deps. Tier 2 returns zero deps.
	// stderr indicates inter-module failure → Tier 3 (install + retry).
	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	pom := `<project>
		<groupId>me.zhengjie</groupId>
		<artifactId>eladmin</artifactId>
		<packaging>pom</packaging>
		<modules><module>eladmin-common</module><module>eladmin-logging</module></modules>
	</project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	os.MkdirAll(filepath.Join(project, "eladmin-common"), 0o755)
	os.MkdirAll(filepath.Join(project, "eladmin-logging"), 0o755)
	os.WriteFile(filepath.Join(project, "eladmin-common", "pom.xml"),
		[]byte(`<project><artifactId>eladmin-common</artifactId></project>`), 0o600)
	os.WriteFile(filepath.Join(project, "eladmin-logging", "pom.xml"),
		[]byte(`<project><artifactId>eladmin-logging</artifactId></project>`), 0o600)

	// Track state: after install, dependency:list should succeed.
	stateFile := filepath.Join(t.TempDir(), "installed")

	binDir := t.TempDir()
	writeExecutable(t, binDir, "mvn", `#!/bin/sh
STATE_FILE="`+stateFile+`"
out=""
pl_module=""
for arg in "$@"; do
  case "$arg" in
    -DoutputFile=*) out="${arg#-DoutputFile=}" ;;
    -pl) pl_module="NEXT" ;;
    *)
      if [ "$pl_module" = "NEXT" ]; then
        pl_module="$arg"
      fi
      ;;
  esac
done
if [ "$1" = "install" ]; then
  touch "$STATE_FILE"
  exit 0
fi
if echo "$@" | grep -q "dependency:list"; then
  # Per-module mode also returns nothing (simulates all modules failing due to inter-dep)
  if [ -n "$pl_module" ] && [ "$pl_module" != "NEXT" ]; then
    if [ -n "$out" ]; then echo "" > "$out"; fi
    exit 1
  fi
  # Reactor mode: succeeds after install
  if [ -f "$STATE_FILE" ]; then
    cat > "$out" <<'EOF_LIST'
org.springframework:spring-core:jar:5.3.0:compile
com.mysql:mysql-connector-java:jar:8.0.33:compile
EOF_LIST
    exit 0
  fi
  # Before install: fail with inter-module error
  if [ -n "$out" ]; then echo "" > "$out"; fi
  echo "Could not resolve dependencies for project me.zhengjie:eladmin-logging:jar:2.7" >&2
  echo "Could not find artifact me.zhengjie:eladmin-common:jar:2.7" >&2
  exit 1
fi
if echo "$@" | grep -q "dependency:tree"; then
  if [ -n "$out" ]; then echo "" > "$out"; fi
  exit 0
fi
if echo "$@" | grep -q "dependency:sources"; then
  exit 0
fi
exit 0
`)
	prependPath(t, binDir)

	r := NewMavenResolver()
	result, err := r.Resolve(context.Background(), project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Tier 3 should have resolved deps after install
	if len(result.Dependencies) != 2 {
		t.Fatalf("Dependencies len = %d, want 2 (from Tier 3 install+retry)", len(result.Dependencies))
	}
	if result.Dependencies[0].Module != "org.springframework:spring-core" {
		t.Fatalf("unexpected first dep: %v", result.Dependencies[0])
	}
}
