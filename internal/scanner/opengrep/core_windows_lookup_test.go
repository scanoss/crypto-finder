package opengrep

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCoreExecutableName(t *testing.T) {
	if got := coreExecutableName("windows"); got != "opengrep-core.exe" {
		t.Fatalf("windows: %q", got)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if got := coreExecutableName(goos); got != "opengrep-core" {
			t.Fatalf("%s: %q", goos, got)
		}
	}
}

// Windows reports no execute bits, so a regular file without them must still
// count as runnable there, and only there.
func TestIsExecutableFile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !isExecutableFile(info, "windows") {
		t.Fatal("windows: a regular file without execute bits must be accepted")
	}
	if isExecutableFile(info, "linux") {
		t.Fatal("linux: a file without execute bits must be rejected")
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if isExecutableFile(dirInfo, "windows") || isExecutableFile(dirInfo, "linux") {
		t.Fatal("a directory is never an executable")
	}
}

// OpenGrep gets a private TMPDIR/TMP/TEMP that the cleanup removes, with what
// it wrote there.
func TestSetCommandEnvPrivateTemp(t *testing.T) {
	s := &Scanner{env: map[string]string{"TMP": "/should/be/overridden", "X": "1"}}
	cmd := exec.CommandContext(t.Context(), "true")
	cleanup, err := s.setCommandEnv(cmd)
	if err != nil {
		t.Fatal(err)
	}
	last := map[string]string{}
	for _, kv := range cmd.Env {
		for i := range kv {
			if kv[i] == '=' {
				last[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	dir := last["TMPDIR"]
	if dir == "" || last["TMP"] != dir || last["TEMP"] != dir || last["X"] != "1" {
		t.Fatalf("env: TMPDIR=%q TMP=%q TEMP=%q X=%q", dir, last["TMP"], last["TEMP"], last["X"])
	}
	leftover := filepath.Join(dir, "semgrep-123.rules")
	if err := os.WriteFile(leftover, []byte("rules: []"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temporary directory still there: %v", err)
	}
}
