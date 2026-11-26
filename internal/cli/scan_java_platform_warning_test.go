package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/scanoss/reach/javaruntime"

	"github.com/scanoss/crypto-finder/internal/entities"
)

const javaPlatformWarning = "Java platform signatures are unavailable"

// fakeJDKWithoutJmods writes a JDK 21 home that has a release file but no
// jmods/ directory, the shape of a JRE or a jlink'd runtime image.
func fakeJDKWithoutJmods(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	release := "JAVA_VERSION=\"21.0.1\"\n"
	if err := os.WriteFile(filepath.Join(home, "release"), []byte(release), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func writeJavaProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := "package demo;\n\npublic class App {\n    public static void main(String[] args) {\n        System.out.println(\"hi\".toUpperCase());\n    }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := zlog.Logger
	zlog.Logger = zerolog.New(&buf).Level(zerolog.WarnLevel)
	t.Cleanup(func() { zlog.Logger = old })
	return &buf
}

// A Java scan whose JDK has no jmods/ falls back to name-only dispatch; the
// scan says so once, naming the JDK it tried, instead of degrading silently.
// Not parallel: it swaps the package-level logger and JAVA_HOME.
func TestJavaScanWarnsOnceWhenJDKHasNoJmods(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := fakeJDKWithoutJmods(t)
	t.Setenv("JAVA_HOME", home)
	buf := captureWarnings(t)

	target := writeJavaProject(t)
	graphs := newGraphStore(target, "")
	if _, err := buildStandaloneCallGraphResultForEcosystem(graphs, target, &entities.InterimReport{}, "java", javaruntime.Config{}, false, "", nil, true); err != nil {
		t.Fatalf("build: %v", err)
	}
	// A second Java graph of the same scan (a dependency's sources) does not repeat it.
	other := writeJavaProject(t)
	if _, err := buildStandaloneCallGraphResultForEcosystem(graphs, other, &entities.InterimReport{}, "java", javaruntime.Config{}, false, "", nil, true); err != nil {
		t.Fatalf("build: %v", err)
	}

	out := buf.String()
	if n := countWarnLines(t, out, javaPlatformWarning); n != 1 {
		t.Fatalf("want exactly 1 warning containing %q, got %d:\n%s", javaPlatformWarning, n, out)
	}
	for _, want := range []string{home, "jmods", "JDK 21"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning does not mention %q:\n%s", want, out)
		}
	}
}

// A configured JDK home (--java-jdk-home with --java-jdk-major) is the path the
// warning names, not JAVA_HOME.
func TestJavaScanWarningNamesConfiguredJDKHome(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("JAVA_HOME", "")
	home := fakeJDKWithoutJmods(t)
	runtime, err := javaruntime.NewConfig("21", map[string]string{"21": home})
	if err != nil {
		t.Fatal(err)
	}
	buf := captureWarnings(t)

	target := writeJavaProject(t)
	if _, err := buildStandaloneCallGraphResultForEcosystem(newGraphStore(target, ""), target, &entities.InterimReport{}, "java", runtime, false, "", nil, true); err != nil {
		t.Fatalf("build: %v", err)
	}
	out := buf.String()
	if countWarnLines(t, out, javaPlatformWarning) != 1 || !strings.Contains(out, home) {
		t.Fatalf("want one warning naming %s:\n%s", home, out)
	}
}

// A JDK with jmods/ gives full dispatch, so the scan says nothing.
func TestJavaScanDoesNotWarnWithFullJDK(t *testing.T) {
	home := os.Getenv("JAVA_HOME")
	if matches, _ := filepath.Glob(filepath.Join(home, "jmods", "*.jmod")); home == "" || len(matches) == 0 {
		t.Skip("needs JAVA_HOME pointing at a JDK with jmods/")
	}
	buf := captureWarnings(t)

	target := writeJavaProject(t)
	if _, err := buildStandaloneCallGraphResultForEcosystem(newGraphStore(target, ""), target, &entities.InterimReport{}, "java", javaruntime.Config{}, false, "", nil, true); err != nil {
		t.Fatalf("build: %v", err)
	}
	if n := countWarnLines(t, buf.String(), javaPlatformWarning); n != 0 {
		t.Fatalf("want no warning with a full JDK, got %d:\n%s", n, buf.String())
	}
}
