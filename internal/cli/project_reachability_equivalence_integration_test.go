// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cli_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// projectReachabilityCase names a fixture under
// testdata/projects/project_reachability/<language>, whose app/ is the target.
type projectReachabilityCase struct {
	language string
	tools    []string
	// env prepares the toolchain for both passes and returns extra variables.
	env func(t *testing.T) []string
}

type reachabilityVerdict struct {
	findingID, location, reachability string
}

// A run with --export-callgraph-project-reachability and no dependency
// resolution must reach the same verdict for every first-party finding as a
// --scan-dependencies run of the same target: that is the flag's contract.
func TestProjectReachabilityMatchesDependencyScan(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI test with real scanner and toolchains")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	t.Parallel()

	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	rules := filepath.Join(root, "testdata", "rules", "project-reachability.yaml")

	cases := []projectReachabilityCase{
		{language: "go", tools: []string{"go"}, env: isolatedHome},
		{language: "python", tools: []string{"python3"}, env: pythonVenvWithDependency},
		// Maven resolution reads the real ~/.m2, so this case keeps HOME.
		{language: "java", tools: []string{"mvn", "java"}, env: func(*testing.T) []string { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.language, func(t *testing.T) {
			t.Parallel()
			for _, tool := range tc.tools {
				if _, err := exec.LookPath(tool); err != nil {
					t.Skipf("%s not installed", tool)
				}
			}
			// The whole fixture is copied so relative wiring such as a Go
			// replace directive survives.
			work := t.TempDir()
			fixture := filepath.Join(work, "fixture")
			require.NoError(t, os.CopyFS(fixture, os.DirFS(filepath.Join(root, "testdata", "projects", "project_reachability", tc.language))))
			target := filepath.Join(fixture, "app")
			env := append(withoutEnv(os.Environ(), "VIRTUAL_ENV"), tc.env(t)...)

			full := runReachabilityPass(t, binary, env, rules, tc.language, target, filepath.Join(work, "full"), "--scan-dependencies")
			project := runReachabilityPass(t, binary, env, rules, tc.language, target, filepath.Join(work, "project"), "--export-callgraph-project-reachability")

			require.Positive(t, full.dependencyFindings, "the --scan-dependencies pass exported no dependency finding, so resolution did not run")
			var mismatches []string
			for _, v := range project.verdicts {
				want, ok := full.byID[v.findingID]
				switch {
				case !ok:
					mismatches = append(mismatches, fmt.Sprintf("%s %s: %s with the flag, absent from the dependency scan", v.findingID, v.location, v.reachability))
				case want.reachability != v.reachability:
					mismatches = append(mismatches, fmt.Sprintf("%s %s: %s with the flag, %s in the dependency scan", v.findingID, v.location, v.reachability, want.reachability))
				}
			}
			require.Empty(t, mismatches, "first-party reachability differs from the dependency scan")

			counts := map[string]int{}
			for _, v := range project.verdicts {
				counts[v.reachability]++
			}
			require.Positive(t, counts[graphfrag.ReachabilityReachable], "project pass has no reachable verdict: %v", project.verdicts)
			require.Positive(t, counts[graphfrag.ReachabilityUnreachable], "project pass has no unreachable verdict: %v", project.verdicts)

			t.Logf("%s: %d first-party findings, %d dependency findings in the full pass", tc.language, len(project.verdicts), full.dependencyFindings)
			for _, v := range project.verdicts {
				t.Logf("  %-40s %s", v.location, v.reachability)
			}
		})
	}
}

type reachabilityPass struct {
	verdicts           []reachabilityVerdict
	byID               map[string]reachabilityVerdict
	dependencyFindings int
}

func runReachabilityPass(t *testing.T, binary string, env []string, rules, language, target, outDir string, extra ...string) reachabilityPass {
	t.Helper()
	require.NoError(t, os.MkdirAll(outDir, 0o750))
	findingsPath := filepath.Join(outDir, "findings.json")
	callgraphPath := filepath.Join(outDir, "callgraph.json")
	args := []string{
		"--error-format", "json", "scan", "--scanner", "opengrep", "--no-remote-rules", "--findings-cache", "none",
		"--languages", language, "--rules", rules, "--output", findingsPath, "--export-callgraph", callgraphPath,
	}
	args = append(append(args, extra...), target)
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "crypto-finder %s output:\n%s", strings.Join(extra, " "), output)

	var report entities.InterimReport
	readJSON(t, findingsPath, &report)
	var export graphfrag.CallgraphExport
	readJSON(t, callgraphPath, &export)

	locations := map[string]string{}
	pass := reachabilityPass{byID: map[string]reachabilityVerdict{}}
	for _, finding := range report.Findings {
		for i := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[i]
			locations[asset.FindingID] = fmt.Sprintf("%s:%d", finding.FilePath, asset.StartLine)
			if asset.Source == "dependency" {
				pass.dependencyFindings++
			}
		}
	}
	for i := range export.FindingGraphs {
		graph := &export.FindingGraphs[i]
		v := reachabilityVerdict{findingID: graph.FindingID, location: locations[graph.FindingID], reachability: graph.Reachability}
		pass.verdicts = append(pass.verdicts, v)
		pass.byID[v.findingID] = v
	}
	sort.Slice(pass.verdicts, func(i, j int) bool { return pass.verdicts[i].location < pass.verdicts[j].location })
	return pass
}

func isolatedHome(t *testing.T) []string {
	t.Helper()
	return []string{"HOME=" + t.TempDir()}
}

// pythonVenvWithDependency builds a venv outside the fixture holding one
// hand-installed package with its own hashing. A venv inside the target would
// be project source to the flag but a dependency to the full run, which is a
// documented difference rather than the contract under test.
func pythonVenvWithDependency(t *testing.T) []string {
	t.Helper()
	venv := filepath.Join(t.TempDir(), "venv")
	if output, err := exec.CommandContext(t.Context(), "python3", "-m", "venv", venv).CombinedOutput(); err != nil {
		t.Skipf("python3 -m venv unavailable: %v\n%s", err, output)
	}
	out, err := exec.CommandContext(t.Context(), filepath.Join(venv, "bin", "python"), "-c", `import sysconfig; print(sysconfig.get_paths()["purelib"])`).Output()
	require.NoError(t, err, "locate venv site-packages")
	sitePackages := strings.TrimSpace(string(out))
	distInfo := filepath.Join(sitePackages, "reachlib-1.0.0.dist-info")
	files := map[string]string{
		filepath.Join(sitePackages, "reachlib", "__init__.py"): "import hashlib\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n",
		filepath.Join(distInfo, "METADATA"):                    "Metadata-Version: 2.1\nName: reachlib\nVersion: 1.0.0\n",
		filepath.Join(distInfo, "RECORD"):                      "reachlib/__init__.py,,\nreachlib-1.0.0.dist-info/METADATA,,\nreachlib-1.0.0.dist-info/RECORD,,\n",
		filepath.Join(distInfo, "top_level.txt"):               "reachlib\n",
		filepath.Join(distInfo, "INSTALLER"):                   "pip\n",
	}
	for path, content := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	return append(isolatedHome(t), "VIRTUAL_ENV="+venv)
}

func withoutEnv(env []string, key string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		if !strings.HasPrefix(entry, key+"=") {
			out = append(out, entry)
		}
	}
	return out
}
