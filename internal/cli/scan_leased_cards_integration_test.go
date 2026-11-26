// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/ruleset"
	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

// A leased ruleset (#900) reaches the cards detector as it reached OpenGrep:
// the scan downloads the bundle from /v3 with its signed lease, opens it for
// the run, compiles the index from its rules and reports its findings under
// the ruleset's version, and the report's rules block carries the release
// payload hash and the lease (expiry and signing key), never the per-tenant
// bundle hash, key or tenant.
func TestScanLeasedRulesetThroughCards(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	rule := "rules:\n  - id: " + progressRuleID + "\n    message: aes cipher\n    severity: INFO\n    languages: [java]\n    pattern: javax.crypto." + progressMatched + "\n    metadata:\n      crypto:\n        assetType: algorithm\n        algorithmFamily: AES\n        algorithmPrimitive: block-cipher\n"
	issued := rulesettest.Issue(t, signer, defaultRulesetName, "v1.40.0", map[string]string{"semgrep-rules/java/aes.yaml": rule}, time.Now().Add(30*24*time.Hour))
	srv := rulesettest.NewServer(t, issued)
	project := filepath.Join(dir, "project")
	writeAnnotateCardsFile(t, filepath.Join(project, "src", "Use.java"), "import javax.crypto.Cipher;\nclass Use { void run() throws Exception { "+progressMatched+"; } }\n")

	out := filepath.Join(dir, "report.json")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--api-url", srv.URL, "--api-key", "test-key", "--output", out, project)
	cmd.Env = append(progressTestEnv(dir), ruleset.PubKeysEnv+"="+os.Getenv(ruleset.PubKeysEnv))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	raw := readBytes(t, out)
	var report struct {
		Rules struct {
			Source, Name, Version string
			ChecksumSHA256        string `json:"checksum_sha256"`
			Lease                 *struct {
				SigningKeyID string `json:"signing_key_id"`
			} `json:"lease"`
		} `json:"rules"`
		Findings []struct {
			FilePath            string `json:"file_path"`
			CryptographicAssets []struct {
				Rules []struct{ ID, Version string } `json:"rules"`
			} `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].FilePath != "src/Use.java" || len(report.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("findings = %s, want the one Java finding", raw)
	}
	if rules := report.Findings[0].CryptographicAssets[0].Rules; len(rules) != 1 || rules[0].Version != "v1.40.0" {
		t.Errorf("asset rules = %+v, want one stamped v1.40.0", rules)
	}
	if r := report.Rules; r.Version != "v1.40.0" || r.ChecksumSHA256 != issued.Lease.PayloadSHA || r.Lease == nil || r.Lease.SigningKeyID != "test-key-1" {
		t.Errorf("rules block = %+v", r)
	}
	for _, secret := range []string{issued.Lease.BundleSHA, issued.Lease.KeyRef, issued.Lease.Tenant} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("report reveals %q", secret)
		}
	}
	if downloads, _ := srv.Counts(); downloads != 1 {
		t.Errorf("downloads = %d, want 1", downloads)
	}
}
