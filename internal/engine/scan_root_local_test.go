package engine

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/dependency"
)

// TestResolveScanRoot_GoReplaceInsideTheScannedTreeIsProjectCode: a scan root
// with no go.mod resolves each module root below it. A replace directory that
// is a sibling of the module root but inside the scanned tree is the project's
// own code and stays unpinned; only one outside the scanned tree is local.
func TestResolveScanRoot_GoReplaceInsideTheScannedTreeIsProjectCode(t *testing.T) {
	repo := writeRepoTree(t, map[string]string{
		"apps/svc/go.mod": `module example.com/svc

go 1.22

require (
	example.com/common v0.0.0
	example.com/vendored v0.0.0
)

replace example.com/common => ../common

replace example.com/vendored => ../../vendored
`,
		"apps/common/go.mod":   "module example.com/common\n",
		"apps/common/c.go":     "package common\n",
		"vendored/go.mod":      "module example.com/vendored\n",
		"vendored/vendored.go": "package vendored\n",
	})
	scanRoot := filepath.Join(repo, "apps")
	resolved, _, err := resolveScanRoot(context.Background(), &dependency.GoResolver{}, scanRoot, nil)
	if err != nil {
		t.Fatalf("resolveScanRoot: %v", err)
	}
	var local []string
	for _, dep := range resolved.Dependencies {
		if dep.Local {
			local = append(local, dep.Module)
		}
	}
	if len(local) != 1 || local[0] != "example.com/vendored" {
		t.Errorf("local dependencies = %v, want only example.com/vendored, the one outside the scanned tree", local)
	}
	if !unpinnedHas(resolved, "example.com/common") {
		t.Errorf("unpinned = %+v, want example.com/common: its directory is inside the scanned tree", resolved.Unpinned)
	}
}

// TestResolveScanRoot_CargoPathCrateInsideTheScannedTreeIsAMember: a scan
// root with no Cargo.toml resolves each crate root below it. A path crate that
// is a sibling of the crate root but inside the scanned tree is a path member,
// the project's own code, not a local dependency.
func TestResolveScanRoot_CargoPathCrateInsideTheScannedTreeIsAMember(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is not installed")
	}
	repo := writeRepoTree(t, map[string]string{
		"svc/Cargo.toml":           "[package]\nname = \"svc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ncommon = { path = \"../crates/common\" }\n",
		"svc/src/lib.rs":           "",
		"svc/Cargo.lock":           "version = 3\n\n[[package]]\nname = \"common\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"svc\"\nversion = \"0.1.0\"\ndependencies = [\n \"common\",\n]\n",
		"crates/common/Cargo.toml": "[package]\nname = \"common\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
		"crates/common/src/lib.rs": "",
		"crates/common/Cargo.lock": "version = 3\n\n[[package]]\nname = \"common\"\nversion = \"0.1.0\"\n",
	})
	resolver := dependency.NewCargoResolver()
	resolver.SetOffline(true)
	resolved, _, err := resolveScanRoot(context.Background(), resolver, repo, nil)
	if err != nil {
		t.Fatalf("resolveScanRoot: %v", err)
	}
	for _, dep := range resolved.Dependencies {
		if dep.Local {
			t.Errorf("%s is a local dependency, want project code: its directory is inside the scanned tree", dep.Module)
		}
	}
	if len(resolved.Unpinned) != 0 {
		t.Errorf("unpinned = %+v, want none", resolved.Unpinned)
	}
	common := filepath.Join(repo, "crates", "common")
	var svcSawCommon bool
	for _, m := range resolved.WorkspaceMembers {
		if m.Name == "common" && sameDir(m.Dir, common) {
			svcSawCommon = true
		}
	}
	if !svcSawCommon {
		t.Errorf("members = %+v, want common at %s", resolved.WorkspaceMembers, common)
	}
	if deps := resolved.Graph["svc"]; len(deps) != 0 {
		t.Errorf("svc's dependency edges = %v, want none: common is a member", deps)
	}
}

func unpinnedHas(r *dependency.ResolveResult, module string) bool {
	for _, u := range r.Unpinned {
		if u.Module == module {
			return true
		}
	}
	return false
}

func sameDir(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// TestCanonicalDependencies_RegistryVersionWinsOverALocalOneOfTheSameVersion:
// two module roots may need one module@version, one from the registry and the
// other from a local directory (a fork that kept the upstream version). The
// closure holds one entry per module@version, and it is the registry one, so
// an online request still names the published version.
func TestCanonicalDependencies_RegistryVersionWinsOverALocalOneOfTheSameVersion(t *testing.T) {
	registry := dependency.Dependency{Module: "github.com/foo/bar", Version: "v1.2.0"}
	local := dependency.Dependency{Module: "github.com/foo/bar", Version: "v1.2.0", Dir: "/forks/bar", Local: true}
	for _, deps := range [][]dependency.Dependency{{registry, local}, {local, registry}} {
		got := canonicalDependencies(deps)
		if len(got) != 1 || got[0].Local || got[0].Dir != "" {
			t.Errorf("canonicalDependencies(%+v) = %+v, want only the registry entry", deps, got)
		}
	}
}
