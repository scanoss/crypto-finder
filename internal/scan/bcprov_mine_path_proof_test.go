// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

// bcprov_mine_path_proof_test.go — wall-clock proof that the full mine path
// (scan + findings + --export-graph-fragment) completes under the mining job
// budget on the pathological BouncyCastle provider corpus.
//
// Ticket: #216
// Corpus: Maven Central org.bouncycastle:bcprov-jdk18on:1.84 sources.jar
//
// Never runs in default CI. Enable explicitly:
//
//	CRYPTO_FINDER_BCPROV_MINE_PROOF=1 go test -run TestMinePathBcprovJdk18on184_WallClockBudget \
//	  -timeout 15m -count=1 ./internal/scan/
//
// Or via Makefile (downloads sources if needed, builds the CLI, runs the proof):
//
//	make proof-bcprov-mine
//
// Recorded result (2026-08-10, Apple Silicon developer laptop, post-#214/#215 main):
//
//	gated proof wall_clock ≈ 2m31s including go build (budget fail at 10m; mining JOB_TIMEOUT is 30m)
//	manual CLI wall ≈ 100s (opengrep ≈ 60–75s, callgraph ≈ 10s, fragment export ≈ 22s)
//	crypto_annotations ≥ 2500, functions ≈ 24231
//
// Before #214 the same corpus timed out at 30m (fragment export alone multi-tens-of-minutes).

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	bcprovMineProofGroup    = "org.bouncycastle"
	bcprovMineProofArtifact = "bcprov-jdk18on"
	bcprovMineProofVersion  = "1.84"
	// Comfortably under crypto-mining-service JOB_TIMEOUT=30m; target is single-digit minutes.
	bcprovMineProofMaxWall = 10 * time.Minute
	// Floor checks — lock that we produced a real dense-library export, not an empty success.
	bcprovMineProofMinFunctions   = 20000
	bcprovMineProofMinAnnotations = 2000
	bcprovMineProofMinFindings    = 400
)

func TestMinePathBcprovJdk18on184_WallClockBudget(t *testing.T) {
	if os.Getenv("CRYPTO_FINDER_BCPROV_MINE_PROOF") == "" {
		t.Skip("set CRYPTO_FINDER_BCPROV_MINE_PROOF=1 to run the bcprov-jdk18on@1.84 mine-path wall-clock proof (#216)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), bcprovMineProofMaxWall+2*time.Minute)
	defer cancel()

	workDir := t.TempDir()
	workspace, err := prepareBcprovJdk18on184Workspace(ctx, workDir)
	if err != nil {
		t.Fatalf("prepare workspace: %v", err)
	}

	bin := os.Getenv("CRYPTO_FINDER_BIN")
	if bin == "" {
		bin, err = buildCryptoFinderBinary(t, workDir)
		if err != nil {
			t.Fatalf("build crypto-finder: %v", err)
		}
	}

	findingsPath := filepath.Join(workDir, "findings.json")
	fragmentPath := filepath.Join(workDir, "fragment.json")
	stderrPath := filepath.Join(workDir, "stderr.log")

	args := []string{
		"scan",
		"--timeout=30m",
		"--output", findingsPath,
		"--export-graph-fragment", fragmentPath,
		"--dep-ecosystem", "java",
		"-v",
	}
	// Optional remote rules (same as production mine). Falls back to cached/local rules.
	if key := os.Getenv("SCANOSS_API_KEY"); key != "" {
		args = append(args, "--api-key", key)
		if url := os.Getenv("SCANOSS_API_URL"); url != "" {
			args = append(args, "--api-url", url)
		}
	}
	args = append(args, workspace)

	cmd := exec.CommandContext(ctx, bin, args...)
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatalf("create stderr log: %v", err)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderrFile

	start := time.Now()
	runErr := cmd.Run()
	wall := time.Since(start)
	_ = stderrFile.Close()

	t.Logf("bcprov-jdk18on@%s mine-path wall_clock=%s budget=%s", bcprovMineProofVersion, wall.Round(time.Millisecond), bcprovMineProofMaxWall)
	if runErr != nil {
		t.Fatalf("crypto-finder scan failed after %s: %v\nstderr: %s", wall, runErr, tailFile(stderrPath, 40))
	}
	if wall > bcprovMineProofMaxWall {
		t.Fatalf("mine-path wall_clock %s exceeds budget %s (mining JOB_TIMEOUT is 30m; target is single-digit minutes)", wall, bcprovMineProofMaxWall)
	}

	findingsRaw, err := os.ReadFile(findingsPath)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	var findings struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(findingsRaw, &findings); err != nil {
		t.Fatalf("parse findings: %v", err)
	}
	if len(findings.Findings) < bcprovMineProofMinFindings {
		t.Fatalf("findings files = %d, want >= %d", len(findings.Findings), bcprovMineProofMinFindings)
	}

	fragmentRaw, err := os.ReadFile(fragmentPath)
	if err != nil {
		t.Fatalf("read fragment: %v", err)
	}
	var fragment struct {
		Functions         []json.RawMessage `json:"functions"`
		CryptoAnnotations []json.RawMessage `json:"crypto_annotations"`
		CryptoEntryPoints []json.RawMessage `json:"crypto_entry_points"`
		SupportingCalls   []json.RawMessage `json:"supporting_calls"`
		ExternalCalls     []json.RawMessage `json:"external_calls"`
	}
	if err := json.Unmarshal(fragmentRaw, &fragment); err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	if len(fragment.Functions) < bcprovMineProofMinFunctions {
		t.Fatalf("fragment functions = %d, want >= %d", len(fragment.Functions), bcprovMineProofMinFunctions)
	}
	if len(fragment.CryptoAnnotations) < bcprovMineProofMinAnnotations {
		t.Fatalf("fragment crypto_annotations = %d, want >= %d", len(fragment.CryptoAnnotations), bcprovMineProofMinAnnotations)
	}
	if len(fragment.CryptoEntryPoints) == 0 {
		t.Fatal("fragment crypto_entry_points is empty")
	}

	// Phase smoke from verbose log — callgraph + fragment export must both appear and finish.
	stderrText := readFileString(stderrPath)
	for _, needle := range []string{
		"Built call graph",
		"Starting graph fragment export",
		"Graph fragment export complete",
		"Scan output write complete",
	} {
		if !strings.Contains(stderrText, needle) {
			t.Fatalf("stderr missing phase marker %q (path still unhealthy?)\n%s", needle, tailFile(stderrPath, 60))
		}
	}

	t.Logf("proof OK: findings_files=%d functions=%d annotations=%d entry_points=%d supporting=%d external_calls=%d fragment_bytes=%d wall=%s",
		len(findings.Findings),
		len(fragment.Functions),
		len(fragment.CryptoAnnotations),
		len(fragment.CryptoEntryPoints),
		len(fragment.SupportingCalls),
		len(fragment.ExternalCalls),
		len(fragmentRaw),
		wall.Round(time.Millisecond),
	)
}

func prepareBcprovJdk18on184Workspace(ctx context.Context, workDir string) (string, error) {
	if override := os.Getenv("CRYPTO_FINDER_BCPROV_SRC"); override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("CRYPTO_FINDER_BCPROV_SRC=%s: %w", override, err)
		}
		return override, nil
	}

	cacheRoot := filepath.Join(workDir, "bcprov-cache")
	if envCache := os.Getenv("CRYPTO_FINDER_BCPROV_CACHE"); envCache != "" {
		cacheRoot = envCache
	}
	workspace := filepath.Join(cacheRoot, bcprovMineProofArtifact+"-"+bcprovMineProofVersion)
	marker := filepath.Join(workspace, ".proof-ready")
	if _, err := os.Stat(marker); err == nil {
		return workspace, nil
	}

	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return "", err
	}
	base := fmt.Sprintf(
		"https://repo1.maven.org/maven2/%s/%s/%s",
		"org/bouncycastle", bcprovMineProofArtifact, bcprovMineProofVersion,
	)
	sourcesJAR := filepath.Join(cacheRoot, fmt.Sprintf("%s-%s-sources.jar", bcprovMineProofArtifact, bcprovMineProofVersion))
	pomPath := filepath.Join(workspace, "pom.xml")

	if err := downloadFile(ctx, base+"/"+bcprovMineProofArtifact+"-"+bcprovMineProofVersion+"-sources.jar", sourcesJAR); err != nil {
		return "", fmt.Errorf("download sources.jar: %w", err)
	}
	if err := downloadFile(ctx, base+"/"+bcprovMineProofArtifact+"-"+bcprovMineProofVersion+".pom", pomPath); err != nil {
		return "", fmt.Errorf("download pom: %w", err)
	}
	if err := unzipTo(sourcesJAR, workspace); err != nil {
		return "", fmt.Errorf("extract sources: %w", err)
	}
	if err := os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return "", err
	}
	return workspace, nil
}

func buildCryptoFinderBinary(t *testing.T, workDir string) (string, error) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	modRoot := wd
	for {
		if _, e := os.Stat(filepath.Join(modRoot, "go.mod")); e == nil {
			break
		}
		parent := filepath.Dir(modRoot)
		if parent == modRoot {
			return "", fmt.Errorf("could not locate module root from %s", wd)
		}
		modRoot = parent
	}
	out := filepath.Join(workDir, "crypto-finder")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", out, "./cmd/crypto-finder")
	cmd.Dir = modRoot
	cmd.Env = os.Environ()
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, outBytes)
	}
	return out, nil
}

func downloadFile(ctx context.Context, url, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".tmp"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SCANOSS-crypto-finder-mine-path-proof/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func unzipTo(zipPath, dest string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			_ = rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		_ = out.Close()
		_ = rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func readFileString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func tailFile(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	lines := splitLines(string(b))
	if len(lines) <= n {
		return string(b)
	}
	return joinLines(lines[len(lines)-n:])
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

func joinLines(lines []string) string {
	return strings.Join(lines, "\n")
}
