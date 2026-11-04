package dependency

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
)

const (
	msManifest = `{"name":"fixture","version":"1.0.0","dependencies":{"ms":"2.1.3"}}`
	msLockfile = `{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "fixture", "version": "1.0.0", "dependencies": {"ms": "2.1.3"}},
    "node_modules/ms": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
      "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==",
      "license": "MIT"
    }
  }
}`
)

// fakeNpm returns an npm that records its arguments and, when it succeeds,
// installs ms into the node_modules of the directory it runs in.
func fakeNpm(t *testing.T, body string) (npmPath, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	writeExecutable(t, dir, "npm", `#!/bin/sh
echo "$*" >> '`+argsFile+`'
`+body)
	return filepath.Join(dir, "npm"), argsFile
}

const npmInstallsMs = `mkdir -p node_modules/ms && echo '{"name":"ms","version":"2.1.3"}' > node_modules/ms/package.json
`

func npmResolverWith(npmPath string, opts ...NpmResolverOption) *NpmResolver {
	r := NewNpmResolver(opts...)
	r.lookPath = func(name string) (string, error) {
		if name == "npm" && npmPath != "" {
			return npmPath, nil
		}
		return "", errors.New("not found")
	}
	return r
}

func readArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	raw, err := os.ReadFile(argsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func TestNpmInstall_RunsCIWhenRequiredPackagesAreAbsent(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []NpmResolverOption
		want string
	}{
		{"production", []NpmResolverOption{WithNpmInstall()}, "ci --ignore-scripts --no-audit --no-fund --omit=dev"},
		{"with dev", []NpmResolverOption{WithNpmInstall(), WithNpmDevDependencies()}, "ci --ignore-scripts --no-audit --no-fund"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{npmManifest: msManifest, npmLockfile: msLockfile})
			npm, argsFile := fakeNpm(t, npmInstallsMs)

			result, err := npmResolverWith(npm, tc.opts...).Resolve(context.Background(), root)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := readArgs(t, argsFile); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("npm invocations = %q, want exactly %q", got, tc.want)
			}
			ms, ok := depsByModule(result)["ms"]
			if !ok || ms.Version != "2.1.3" || ms.Dir != filepath.Join(root, "node_modules", "ms") {
				t.Fatalf("ms = %+v (found %v), want 2.1.3 at the installed node_modules/ms", ms, ok)
			}
		})
	}
}

func TestNpmInstall_SkipsInstallWhenTreeIsComplete(t *testing.T) {
	root := writeTree(t, map[string]string{
		npmManifest:                msManifest,
		npmLockfile:                msLockfile,
		"node_modules/ms/index.js": "module.exports = 1",
	})
	npm, argsFile := fakeNpm(t, "exit 1\n")

	result, err := npmResolverWith(npm, WithNpmInstall()).Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := readArgs(t, argsFile); got != nil {
		t.Fatalf("npm ran %q on a complete tree", got)
	}
	if _, ok := depsByModule(result)["ms"]; !ok {
		t.Fatalf("ms not resolved: %+v", result.Dependencies)
	}
}

func TestNpmInstall_DisabledNeverRunsNpm(t *testing.T) {
	root := writeTree(t, map[string]string{npmManifest: msManifest, npmLockfile: msLockfile})
	npm, argsFile := fakeNpm(t, npmInstallsMs)

	_, err := npmResolverWith(npm).Resolve(context.Background(), root)
	if err == nil || !strings.Contains(err.Error(), "--install-dependencies") {
		t.Fatalf("err = %v, want the not-installed error naming --install-dependencies", err)
	}
	if got := readArgs(t, argsFile); got != nil {
		t.Fatalf("npm ran %q without install enabled", got)
	}
}

func TestNpmInstall_CIFailureCarriesStderr(t *testing.T) {
	root := writeTree(t, map[string]string{npmManifest: msManifest, npmLockfile: msLockfile})
	npm, _ := fakeNpm(t, "echo 'npm ERR! 404 Not Found - GET https://registry.npmjs.org/ms' >&2\nexit 1\n")

	_, err := npmResolverWith(npm, WithNpmInstall()).Resolve(context.Background(), root)
	structured, ok := failure.As(err)
	if !ok || structured.Code != failure.CodeDependencyResolutionFailed {
		t.Fatalf("err = %v, want a %s failure", err, failure.CodeDependencyResolutionFailed)
	}
	if !strings.Contains(err.Error(), "npm ERR! 404 Not Found") {
		t.Fatalf("err = %v, want npm's stderr in it", err)
	}
}

func TestNpmInstall_MissingNpmNamesTheFlag(t *testing.T) {
	root := writeTree(t, map[string]string{npmManifest: msManifest, npmLockfile: msLockfile})

	_, err := npmResolverWith("", WithNpmInstall()).Resolve(context.Background(), root)
	if err == nil || !strings.Contains(err.Error(), "npm is not on PATH") || !strings.Contains(err.Error(), "--install-dependencies") {
		t.Fatalf("err = %v, want it to say npm is missing and name --install-dependencies", err)
	}
}

func TestTailForFailure_KeepsTheEnd(t *testing.T) {
	if got := tailForFailure("abcdef", 3); got != "...def" {
		t.Fatalf("tailForFailure = %q, want ...def", got)
	}
	if got := tailForFailure("abc", 3); got != "abc" {
		t.Fatalf("tailForFailure = %q, want abc", got)
	}
}
