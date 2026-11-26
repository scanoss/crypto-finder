// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A Python target is scanned for its Python, and --scan-dependencies --offline
// mines its pinned dependencies from the installed distributions it is given
// (--offline-python-packages: here a site-packages directory outside the
// project), as the API would serve them: the first-party finding, the
// dependency's finding under its distribution with its verdict (reachable:
// app.auth.mac -> jwt.sign), and the unpinned requirement listed with reason
// unpinned.
func TestScanPythonProjectOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	rules, err := filepath.Abs(v3TestRuleset)
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(dir, "project")
	writeAnnotateCardsFile(t, filepath.Join(project, "requirements.txt"), "pyjwt==2.10.1\nrequests>=2.0\n")
	writeAnnotateCardsFile(t, filepath.Join(project, "app", "__init__.py"), "")
	writeAnnotateCardsFile(t, filepath.Join(project, "app", "auth.py"), `import jwt


def token(key):
    return jwt.encode({"sub": "x"}, key, algorithm="HS256")


def mac(key, msg):
    return jwt.sign(key, msg)
`)
	site := filepath.Join(dir, "env", "lib", "python3.12", "site-packages")
	writeAnnotateCardsFile(t, filepath.Join(site, "jwt", "__init__.py"), "from .api_jwt import sign\n")
	writeAnnotateCardsFile(t, filepath.Join(site, "jwt", "api_jwt.py"), `from cryptography.hazmat.primitives.asymmetric import ec


def sign(key, msg):
    return ec.generate_private_key(ec.SECP256R1())
`)
	writeAnnotateCardsFile(t, filepath.Join(site, "PyJWT-2.10.1.dist-info", "METADATA"), "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.10.1\n")
	writeAnnotateCardsFile(t, filepath.Join(site, "PyJWT-2.10.1.dist-info", "RECORD"), "jwt/__init__.py,,\njwt/api_jwt.py,,\nPyJWT-2.10.1.dist-info/METADATA,,\nPyJWT-2.10.1.dist-info/RECORD,,\n")

	scan := func(name string, extra ...string) (map[string]string, map[string]any) {
		t.Helper()
		out := filepath.Join(dir, name)
		args := append([]string{
			"scan", "--no-remote-rules", "--rules-dir", rules, "--progress",
			"--scan-dependencies", "--offline", "--offline-cache-dir", filepath.Join(dir, "cache"),
			"--offline-python-packages", filepath.Join(dir, "env"),
			"--output", out + ".json", "--export-callgraph", out + ".callgraph.json",
		}, extra...)
		cmd := exec.CommandContext(t.Context(), binary, append(args, project)...)
		cmd.Env = append(progressTestEnv(dir), "VIRTUAL_ENV=")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("scan: %v\n%s", err, stderr.String())
		}
		var report struct {
			Findings []struct {
				FilePath            string `json:"file_path"`
				CryptographicAssets []struct {
					FindingID      string `json:"finding_id"`
					Source         string `json:"source"`
					DependencyInfo *struct {
						Module, Version, PURL string
					} `json:"dependency_info"`
				} `json:"cryptographic_assets"`
			} `json:"findings"`
		}
		readPythonScanJSON(t, out+".json", &report)
		var callgraph struct {
			FindingGraphs []struct {
				FindingID        string `json:"finding_id"`
				Reachability     string `json:"reachability"`
				UnresolvedReason string `json:"unresolved_reason"`
			} `json:"finding_graphs"`
		}
		readPythonScanJSON(t, out+".callgraph.json", &callgraph)
		verdicts := map[string]string{}
		for _, g := range callgraph.FindingGraphs {
			verdicts[g.FindingID] = g.Reachability + ":" + g.UnresolvedReason
		}
		got := map[string]string{}
		for _, f := range report.Findings {
			for _, a := range f.CryptographicAssets {
				where := a.Source + " " + f.FilePath
				if a.DependencyInfo != nil {
					where += " " + a.DependencyInfo.Module + "@" + a.DependencyInfo.Version
					got[where] = verdicts[a.FindingID]
					continue
				}
				got[where] = "-"
			}
		}
		var details map[string]any
		for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
			var event map[string]any
			if json.Unmarshal([]byte(line), &event) == nil && event["phase"] == "dependencies" && event["status"] == "completed" {
				details, _ = event["details"].(map[string]any)
			}
		}
		return got, details
	}

	got, details := scan("verdicts")
	want := map[string]string{
		"direct app/auth.py":                     "-",
		"dependency jwt/api_jwt.py pyjwt@2.10.1": "reachable:",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
	unpinned := []any{map[string]any{"module": "requests", "version": "", "purl": "pkg:pypi/requests", "reason": "unpinned", "specifier": ">=2.0"}}
	if !reflect.DeepEqual(details["deps_skipped_list"], unpinned) || details["ecosystems"].([]any)[0] != "python" {
		t.Errorf("dependency phase details = %v", details)
	}
}

func readPythonScanJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := json.Unmarshal(readBytes(t, path), value); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// A target holding Java and Python source is scanned for both, each against
// its own rules, cards and call graph, as main scans every ecosystem with
// source (#902). Its Python project lives below the scan root
// (services/py), so the dependency scan finds it as a resolution root, as
// it finds Maven and Gradle modules: the Python closure is resolved there and
// its dependency finding is served, while Java, with no build manifest,
// resolves nothing.
func TestScanMixedJavaPythonTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	rules, err := filepath.Abs(v3TestRuleset)
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(dir, "project")
	writeAnnotateCardsFile(t, filepath.Join(project, "src", "Use.java"), "import javax.crypto.Cipher;\nclass Use { void run() throws Exception { "+progressMatched+"; } }\n")
	py := filepath.Join(project, "services", "py")
	writeAnnotateCardsFile(t, filepath.Join(py, "requirements.txt"), "pyjwt==2.10.1\n")
	writeAnnotateCardsFile(t, filepath.Join(py, "app", "__init__.py"), "")
	writeAnnotateCardsFile(t, filepath.Join(py, "app", "auth.py"), "import jwt\n\n\ndef token(key):\n    return jwt.encode({\"sub\": \"x\"}, key, algorithm=\"HS256\")\n")
	site := filepath.Join(dir, "env", "lib", "python3.12", "site-packages")
	writeAnnotateCardsFile(t, filepath.Join(site, "jwt", "__init__.py"), "from .api_jwt import sign\n")
	writeAnnotateCardsFile(t, filepath.Join(site, "jwt", "api_jwt.py"), "from cryptography.hazmat.primitives.asymmetric import ec\n\n\ndef sign(key, msg):\n    return ec.generate_private_key(ec.SECP256R1())\n")
	writeAnnotateCardsFile(t, filepath.Join(site, "PyJWT-2.10.1.dist-info", "METADATA"), "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.10.1\n")
	writeAnnotateCardsFile(t, filepath.Join(site, "PyJWT-2.10.1.dist-info", "RECORD"), "jwt/__init__.py,,\njwt/api_jwt.py,,\nPyJWT-2.10.1.dist-info/METADATA,,\nPyJWT-2.10.1.dist-info/RECORD,,\n")

	out := filepath.Join(dir, "report.json")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--no-remote-rules", "--rules-dir", rules, "--progress",
		"--scan-dependencies", "--offline", "--offline-cache-dir", filepath.Join(dir, "cache"),
		"--offline-python-packages", filepath.Join(dir, "env"), "--output", out, project)
	cmd.Env = append(progressTestEnv(dir), "VIRTUAL_ENV=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	var report struct {
		Findings []struct {
			FilePath            string `json:"file_path"`
			Language            string `json:"language"`
			CryptographicAssets []struct {
				Source         string `json:"source"`
				DependencyInfo *struct {
					Module, Version string
				} `json:"dependency_info"`
			} `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	readPythonScanJSON(t, out, &report)
	got := map[string]bool{}
	for _, f := range report.Findings {
		for _, a := range f.CryptographicAssets {
			where := a.Source + " " + f.Language + " " + f.FilePath
			if a.DependencyInfo != nil {
				where += " " + a.DependencyInfo.Module + "@" + a.DependencyInfo.Version
			}
			got[where] = true
		}
	}
	want := map[string]bool{
		"direct java src/Use.java":                      true,
		"direct python services/py/app/auth.py":         true,
		"dependency python jwt/api_jwt.py pyjwt@2.10.1": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
	var details, detection map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) != nil || event["status"] != "completed" {
			continue
		}
		switch event["phase"] {
		case "dependencies":
			details, _ = event["details"].(map[string]any)
		case "detection":
			detection, _ = event["details"].(map[string]any)
		}
	}
	if !reflect.DeepEqual(details["ecosystems"], []any{"python"}) {
		t.Errorf("dependency phase details = %v, want ecosystems [python]", details)
	}
	if _, named := detection["unsupported_languages"]; named {
		t.Errorf("detection details = %v, want no unsupported language", detection)
	}
	progressTransitions(t, stderr.String())
}
