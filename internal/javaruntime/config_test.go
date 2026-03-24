package javaruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewConfig(t *testing.T) {
	cfg, err := NewConfig("21", map[string]string{"21": " /opt/jdk21 "})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.RequestedMajor != "21" {
		t.Fatalf("RequestedMajor = %q, want 21", cfg.RequestedMajor)
	}
	if cfg.Homes["21"] != "/opt/jdk21" {
		t.Fatalf("Homes[21] = %q, want /opt/jdk21", cfg.Homes["21"])
	}
}

func TestNormalizeMajor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty", input: "", want: AutoMajor},
		{name: "trimmed-auto", input: " auto ", want: AutoMajor},
		{name: "supported-8", input: "8", want: "8"},
		{name: "supported-11", input: "11", want: "11"},
		{name: "supported-17", input: "17", want: "17"},
		{name: "supported-21", input: "21", want: "21"},
		{name: "invalid", input: "22", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeMajor(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeMajor: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeMajor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsSupportedMajor(t *testing.T) {
	t.Parallel()

	if !IsSupportedMajor("17") {
		t.Fatal("expected 17 to be supported")
	}
	if IsSupportedMajor("22") {
		t.Fatal("expected 22 to be unsupported")
	}
}

func TestNormalizeHomes(t *testing.T) {
	t.Parallel()

	got, err := NormalizeHomes(map[string]string{"17": " /jdk17 ", "21": "/jdk21"})
	if err != nil {
		t.Fatalf("NormalizeHomes: %v", err)
	}
	if got["17"] != "/jdk17" || got["21"] != "/jdk21" {
		t.Fatalf("NormalizeHomes() = %#v", got)
	}

	if _, err := NormalizeHomes(map[string]string{"auto": "/jdk"}); err == nil {
		t.Fatal("expected auto key to fail")
	}
	if _, err := NormalizeHomes(map[string]string{"21": "   "}); err == nil {
		t.Fatal("expected empty path to fail")
	}
	if _, err := NormalizeHomes(map[string]string{"22": "/jdk22"}); err == nil {
		t.Fatal("expected unsupported major to fail")
	}
}

func TestParseHomeEntriesAndEnv(t *testing.T) {
	t.Parallel()

	got, err := ParseHomeEntries([]string{"17=/jdk17", "21=/jdk21"})
	if err != nil {
		t.Fatalf("ParseHomeEntries: %v", err)
	}
	if got["17"] != "/jdk17" || got["21"] != "/jdk21" {
		t.Fatalf("ParseHomeEntries() = %#v", got)
	}

	got, err = ParseHomeEnv("17=/jdk17, 21=/jdk21")
	if err != nil {
		t.Fatalf("ParseHomeEnv: %v", err)
	}
	if got["17"] != "/jdk17" || got["21"] != "/jdk21" {
		t.Fatalf("ParseHomeEnv() = %#v", got)
	}

	if _, err := ParseHomeEntries([]string{"bad"}); err == nil {
		t.Fatal("expected malformed entry to fail")
	}
	if _, err := ParseHomeEnv("auto=/jdk"); err == nil {
		t.Fatal("expected auto entry to fail")
	}
}

func TestMergeHomes(t *testing.T) {
	t.Parallel()

	got := MergeHomes(map[string]string{"17": "/jdk17"}, map[string]string{"17": "/override", "21": "/jdk21"})
	if got["17"] != "/override" || got["21"] != "/jdk21" {
		t.Fatalf("MergeHomes() = %#v", got)
	}
}

func TestConfigMethods(t *testing.T) {
	t.Parallel()

	if cfg := (Config{}); cfg.RequestedMajorOrAuto() != AutoMajor || cfg.IsExplicitMajor() {
		t.Fatalf("zero config methods returned unexpected values: %#v", cfg)
	}
	if cfg := (Config{RequestedMajor: "21"}); cfg.RequestedMajorOrAuto() != "21" || !cfg.IsExplicitMajor() {
		t.Fatalf("explicit config methods returned unexpected values: %#v", cfg)
	}
}

func TestCacheKeyToken(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		if got := (Config{RequestedMajor: "21"}).CacheKeyToken(); got != "jdk-21" {
			t.Fatalf("CacheKeyToken() = %q, want jdk-21", got)
		}
	})

	t.Run("auto-no-java-home", func(t *testing.T) {
		t.Setenv("JAVA_HOME", "")
		if got := (Config{}).CacheKeyToken(); got != "jdk-auto" {
			t.Fatalf("CacheKeyToken() = %q, want jdk-auto", got)
		}
	})

	t.Run("auto-supported-java-home", func(t *testing.T) {
		javaHome := writeReleaseFile(t, "21.0.5")
		t.Setenv("JAVA_HOME", javaHome)
		if got := (Config{}).CacheKeyToken(); got != "jdk-21" {
			t.Fatalf("CacheKeyToken() = %q, want jdk-21", got)
		}
	})

	t.Run("auto-unsupported-major", func(t *testing.T) {
		javaHome := writeReleaseFile(t, "22.0.1")
		t.Setenv("JAVA_HOME", javaHome)
		if got := (Config{}).CacheKeyToken(); got != "jdk-auto" {
			t.Fatalf("CacheKeyToken() = %q, want jdk-auto", got)
		}
	})

	t.Run("auto-unreadable-release", func(t *testing.T) {
		javaHome := t.TempDir()
		t.Setenv("JAVA_HOME", javaHome)
		if got := (Config{}).CacheKeyToken(); got != "jdk-auto" {
			t.Fatalf("CacheKeyToken() = %q, want jdk-auto", got)
		}
	})
}

func TestResolveExplicitSelection(t *testing.T) {
	t.Run("auto", func(t *testing.T) {
		selection, err := ResolveExplicitSelection(Config{})
		if err != nil {
			t.Fatalf("ResolveExplicitSelection: %v", err)
		}
		if selection != nil {
			t.Fatalf("selection = %#v, want nil", selection)
		}
	})

	t.Run("missing-home", func(t *testing.T) {
		if _, err := ResolveExplicitSelection(Config{RequestedMajor: "21"}); err == nil {
			t.Fatal("expected missing home to fail")
		}
	})

	t.Run("missing-release", func(t *testing.T) {
		if _, err := ResolveExplicitSelection(Config{
			RequestedMajor: "21",
			Homes:          map[string]string{"21": t.TempDir()},
		}); err == nil {
			t.Fatal("expected missing release file to fail")
		}
	})

	t.Run("mismatched-major", func(t *testing.T) {
		javaHome := writeReleaseFile(t, "17.0.12")
		if _, err := ResolveExplicitSelection(Config{
			RequestedMajor: "21",
			Homes:          map[string]string{"21": javaHome},
		}); err == nil {
			t.Fatal("expected mismatched major to fail")
		}
	})

	t.Run("success", func(t *testing.T) {
		javaHome := writeReleaseFile(t, "1.8.0_412")
		selection, err := ResolveExplicitSelection(Config{
			RequestedMajor: "8",
			Homes:          map[string]string{"8": javaHome},
		})
		if err != nil {
			t.Fatalf("ResolveExplicitSelection: %v", err)
		}
		if selection.RequestedMajor != "8" || selection.EffectiveMajor != "8" || selection.RuntimeVersion != "1.8.0_412" || selection.JavaHome != javaHome {
			t.Fatalf("selection = %#v", selection)
		}
	})
}

func TestRuntimeVersionAndParseReleaseFile(t *testing.T) {
	javaHome := t.TempDir()
	releasePath := filepath.Join(javaHome, "release")
	content := strings.Join([]string{
		"JAVA_VERSION=\"21.0.5\"",
		"IMPLEMENTOR=\"ACME\"",
		"BADLINE",
		"",
	}, "\n")
	if err := os.WriteFile(releasePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write release: %v", err)
	}

	props, err := ParseReleaseFile(javaHome)
	if err != nil {
		t.Fatalf("ParseReleaseFile: %v", err)
	}
	if props["JAVA_VERSION"] != "\"21.0.5\"" || props["IMPLEMENTOR"] != "\"ACME\"" {
		t.Fatalf("props = %#v", props)
	}

	version, err := RuntimeVersion(javaHome)
	if err != nil {
		t.Fatalf("RuntimeVersion: %v", err)
	}
	if version != "21.0.5" {
		t.Fatalf("RuntimeVersion() = %q, want 21.0.5", version)
	}

	if _, err := RuntimeVersion(t.TempDir()); err == nil {
		t.Fatal("expected missing release file to fail")
	}

	emptyVersionHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(emptyVersionHome, "release"), []byte("IMPLEMENTOR=\"ACME\"\n"), 0o600); err != nil {
		t.Fatalf("write release: %v", err)
	}
	if _, err := RuntimeVersion(emptyVersionHome); err == nil {
		t.Fatal("expected missing JAVA_VERSION to fail")
	}
}

func TestMajorFromVersion(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"1.8.0_412":  "8",
		"17.0.12":    "17",
		"21":         "21",
		"\"21.0.5\"": "21",
	}
	for input, want := range tests {
		if got := MajorFromVersion(input); got != want {
			t.Fatalf("MajorFromVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEnvWithJavaHome(t *testing.T) {
	t.Parallel()

	javaHome := "/opt/jdks/jdk21"

	updated := EnvWithJavaHome([]string{"JAVA_HOME=/old", "PATH=/usr/bin", "FOO=bar"}, javaHome)
	if !containsEnv(updated, "JAVA_HOME="+javaHome) {
		t.Fatalf("updated env missing JAVA_HOME: %#v", updated)
	}
	if !containsPrefixEnv(updated, "PATH="+filepath.Join(javaHome, "bin")+string(os.PathListSeparator)) {
		t.Fatalf("updated env missing prefixed PATH: %#v", updated)
	}

	appended := EnvWithJavaHome([]string{"FOO=bar"}, javaHome)
	if !containsEnv(appended, "JAVA_HOME="+javaHome) || !containsEnv(appended, "PATH="+filepath.Join(javaHome, "bin")) {
		t.Fatalf("appended env = %#v", appended)
	}
}

func TestParseHomeEntry(t *testing.T) {
	t.Parallel()

	major, path, err := parseHomeEntry("17=/opt/jdk17")
	if err != nil {
		t.Fatalf("parseHomeEntry: %v", err)
	}
	if major != "17" || path != "/opt/jdk17" {
		t.Fatalf("parseHomeEntry() = (%q, %q)", major, path)
	}

	if _, _, err := parseHomeEntry("17="); err == nil {
		t.Fatal("expected empty path to fail")
	}
	if _, _, err := parseHomeEntry("bad"); err == nil {
		t.Fatal("expected malformed entry to fail")
	}
}

func writeReleaseFile(t *testing.T, version string) string {
	t.Helper()

	javaHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(javaHome, "release"), []byte("JAVA_VERSION=\""+version+"\"\n"), 0o600); err != nil {
		t.Fatalf("write release: %v", err)
	}
	return javaHome
}

func containsEnv(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}

func containsPrefixEnv(env []string, prefix string) bool {
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}
