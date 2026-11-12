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

package cache

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/ruleset"
	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

const testAPIKey = "test-key"

var testRules = map[string]string{"rules/java/aes.yaml": rulesettest.RuleYAML}

func newLeasedManager(t *testing.T, url string) *Manager {
	t.Helper()
	return &Manager{
		apiClient:        api.NewClient(url, testAPIKey).WithRetryDelay(time.Millisecond),
		cacheDir:         t.TempDir(),
		maxStaleCacheAge: config.DefaultMaxStaleCacheAge,
	}
}

// yamlFilesUnder lists the rule files under dir, outside the per-run dirs.
func yamlFilesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ext := filepath.Ext(path); !d.IsDir() && (ext == ".yaml" || ext == ".yml") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestLeased_DownloadKeepsCacheEncrypted(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour))
	srv := rulesettest.NewServer(t, issued)
	m := newLeasedManager(t, srv.URL)

	path, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := leasedCacheUsable(path); err != nil {
		t.Fatal(err)
	}
	if got := yamlFilesUnder(t, m.cacheDir); len(got) != 0 {
		t.Fatalf("plaintext rule files in the cache: %v", got)
	}
	sealed, err := os.ReadFile(filepath.Join(path, bundleFileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, issued.Bundle[:64]) {
		t.Fatal("bundle.enc holds the plaintext bundle")
	}
	meta, err := LoadMetadata(filepath.Join(path, metadataFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !meta.ExpiresAt.Equal(issued.Lease.ExpiresAt) || meta.Version != "v1.40.0" || meta.ChecksumSHA256 != issued.Lease.PayloadSHA {
		t.Fatalf("metadata = %+v", meta)
	}
}

func TestLeased_OpenLeasedExtractsIntoRemovableRunDir(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	srv := rulesettest.NewServer(t, rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour)))
	m := newLeasedManager(t, srv.URL)
	if _, err := m.GetRulesetPath(context.Background(), "dca", "latest"); err != nil {
		t.Fatal(err)
	}

	dir, cleanup, err := m.OpenLeased("dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(dir) != RunsDir(m.cacheDir, "dca", "latest") {
		t.Fatalf("run dir %s is not under %s", dir, RunsDir(m.cacheDir, "dca", "latest"))
	}
	if got := yamlFilesUnder(t, dir); len(got) != 1 || got[0] != filepath.Join(dir, "rules", "java", "aes.yaml") {
		t.Fatalf("run dir holds %v, want only the bundle's rule file", got)
	}

	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("run dir still exists: %v", err)
	}
	if got := yamlFilesUnder(t, m.cacheDir); len(got) != 0 {
		t.Fatalf("plaintext rule files left in the cache: %v", got)
	}
}

func TestLeased_TamperedBundleRejected(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour))
	other := rulesettest.Issue(t, signer, "dca", "v1.40.0", map[string]string{"rules/java/aes.yaml": "rules: []\n"}, time.Now().Add(30*24*time.Hour))
	tampered := *issued
	tampered.Bundle = other.Bundle // served bytes no longer match the lease
	srv := rulesettest.NewServer(t, &tampered)
	m := newLeasedManager(t, srv.URL)

	_, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if !errors.Is(err, ruleset.ErrHashMismatch) {
		t.Fatalf("got %v, want a bundle hash mismatch", err)
	}
	if _, statErr := os.Stat(filepath.Join(m.cacheDir, "dca", "latest")); !os.IsNotExist(statErr) {
		t.Fatalf("a rejected bundle was cached: %v", statErr)
	}

	// A cached bundle altered at rest no longer decrypts.
	srv.Set(issued)
	path, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	sealedPath := filepath.Join(path, bundleFileName)
	sealed, _ := os.ReadFile(sealedPath)
	sealed[len(sealed)-1] ^= 0xff
	if err := os.WriteFile(sealedPath, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.OpenLeased("dca", "latest"); err == nil {
		t.Fatal("a tampered bundle.enc was opened")
	}
}

func TestLeased_UnknownSigningKeyRejected(t *testing.T) {
	rulesettest.NewSigner(t, "trusted", true)
	untrusted := rulesettest.NewSigner(t, "untrusted", false)
	srv := rulesettest.NewServer(t, rulesettest.Issue(t, untrusted, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour)))
	m := newLeasedManager(t, srv.URL)

	if _, err := m.GetRulesetPath(context.Background(), "dca", "latest"); !errors.Is(err, ruleset.ErrUnknownKey) {
		t.Fatalf("got %v, want an unknown key error", err)
	}

	// Only the embedded production key is trusted without PubKeysEnv.
	t.Setenv(ruleset.PubKeysEnv, "")
	if _, err := m.GetRulesetPath(context.Background(), "dca", "latest"); !errors.Is(err, ruleset.ErrUnknownKey) {
		t.Fatalf("got %v, want an unknown key error", err)
	}
}

func TestLeased_TamperedLeaseRejected(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour))
	var env ruleset.Envelope
	if err := json.Unmarshal(issued.LeaseJSON, &env); err != nil {
		t.Fatal(err)
	}
	// A later expiry, as someone extending their lease would write it.
	later := issued.Lease.ExpiresAt.Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)
	env.Lease = []byte(strings.Replace(string(env.Lease), issued.Lease.ExpiresAt.UTC().Format(time.RFC3339), later, 1))
	tampered := *issued
	tampered.LeaseJSON, _ = json.Marshal(env)
	srv := rulesettest.NewServer(t, &tampered)
	m := newLeasedManager(t, srv.URL)

	if _, err := m.GetRulesetPath(context.Background(), "dca", "latest"); !errors.Is(err, ruleset.ErrBadSignature) {
		t.Fatalf("got %v, want a bad signature", err)
	}
	if _, err := os.Stat(m.getRulesetCachePath("dca", "latest")); !os.IsNotExist(err) {
		t.Fatalf("a bundle with a tampered lease was cached: %v", err)
	}

	// A lease altered in the cache after download is refused when opened.
	srv.Set(issued)
	path, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, leaseFileName), tampered.LeaseJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.OpenLeased("dca", "latest"); !errors.Is(err, ruleset.ErrBadSignature) {
		t.Fatalf("OpenLeased: got %v, want a bad signature", err)
	}
}

func TestLeased_ExpiredLeaseIsNotUsedAsStaleCache(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	expired := rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(-time.Hour))
	m := newLeasedManager(t, "http://127.0.0.1:1") // unreachable API
	m.apiClient = api.NewClientWithHTTPClient("http://127.0.0.1:1", testAPIKey, &http.Client{Timeout: time.Second}).WithRetryDelay(time.Millisecond)
	path := m.getRulesetCachePath("dca", "latest")
	if err := m.storeLeased("dca", path, expired.Bundle, expired.LeaseJSON, expired.Lease, 1); err != nil {
		t.Fatal(err)
	}

	_, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	var expiredErr *ExpiredLeaseError
	if !errors.As(err, &expiredErr) || !errors.Is(err, ruleset.ErrExpired) {
		t.Fatalf("got %v, want an expired lease error", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, expired.Lease.ExpiresAt.UTC().Format(time.RFC3339)) || !strings.Contains(msg, "--rules-dir") {
		t.Fatalf("error does not name the expiry and --rules-dir: %s", msg)
	}
	if _, _, err := m.OpenLeased("dca", "latest"); !errors.Is(err, ruleset.ErrExpired) {
		t.Fatalf("OpenLeased: got %v, want expired", err)
	}
}

func TestLeased_V3NotFoundIsAnError(t *testing.T) {
	rulesettest.NewSigner(t, "test-key-1", true)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	m := newLeasedManager(t, srv.URL)

	_, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if !errors.Is(err, api.ErrNotFound) || !strings.Contains(err.Error(), "ruleset dca@latest not found") || !strings.Contains(err.Error(), "/v3/rulesets") {
		t.Fatalf("got %v, want a not found error naming /v3/rulesets", err)
	}
	if len(paths) != 1 || paths[0] != "/v3/rulesets/dca/latest/download" {
		t.Fatalf("requested %v, want only the v3 download", paths)
	}
	if _, err := os.Stat(m.getRulesetCachePath("dca", "latest")); !os.IsNotExist(err) {
		t.Fatalf("something was cached: %v", err)
	}
}

// writeOlderPlaintextCache writes a ruleset as older crypto-finder versions
// cached it: extracted rule files, manifest.json and fresh cache metadata.
func writeOlderPlaintextCache(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "rules", "java"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"rules/java/aes.yaml": rulesettest.RuleYAML,
		"manifest.json":       `{"name":"dca","version":"v1.39.0"}`,
	} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewMetadata("dca", "v1.39.0", "abc", int64(time.Hour.Seconds())).Save(filepath.Join(path, metadataFileName)); err != nil {
		t.Fatal(err)
	}
}

// A successful download replaces an older plaintext cache.
func TestLeased_OlderPlaintextCacheIsReplaced(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	srv := rulesettest.NewServer(t, rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour)))
	m := newLeasedManager(t, srv.URL)
	path := m.getRulesetCachePath("dca", "latest")
	writeOlderPlaintextCache(t, path)
	if !olderCacheFormat(path) {
		t.Fatal("older plaintext cache not recognized")
	}

	got, err := m.GetRulesetPath(context.Background(), "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if downloads, _ := srv.Counts(); got != path || downloads != 1 {
		t.Fatalf("path %s downloads %d; want %s downloaded once", got, downloads, path)
	}
	if err := leasedCacheUsable(path); err != nil {
		t.Fatal(err)
	}
	if olderCacheFormat(path) {
		t.Fatal("older cache still recognized after the download")
	}
	if yaml := yamlFilesUnder(t, m.cacheDir); len(yaml) != 0 {
		t.Fatalf("plaintext rule files left in the cache: %v", yaml)
	}
	if _, err := os.Stat(filepath.Join(path, "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("manifest.json left in the cache: %v", err)
	}
}

// An older plaintext cache is never used, and a failed download does not
// touch it.
func TestLeased_OlderPlaintextCacheIsNeverUsed(t *testing.T) {
	rulesettest.NewSigner(t, "test-key-1", true)
	m := newLeasedManager(t, "http://127.0.0.1:1") // unreachable API
	m.apiClient = api.NewClientWithHTTPClient("http://127.0.0.1:1", testAPIKey, &http.Client{Timeout: time.Second}).WithRetryDelay(time.Millisecond)
	path := m.getRulesetCachePath("dca", "latest")
	writeOlderPlaintextCache(t, path)

	// Neither as a fresh cache nor as the stale fallback.
	if _, err := m.GetRulesetPath(context.Background(), "dca", "latest"); err == nil || !strings.Contains(err.Error(), "failed to download ruleset") {
		t.Fatalf("got %v, want the download error", err)
	}
	if _, _, err := m.OpenLeased("dca", "latest"); err == nil {
		t.Fatal("an older plaintext cache was opened")
	}
	// A failed download leaves the older cache as it was.
	for _, name := range []string{"rules/java/aes.yaml", "manifest.json", metadataFileName} {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Fatalf("older cache changed by a failed download: %v", err)
		}
	}
	if meta, err := LoadMetadata(filepath.Join(path, metadataFileName)); err != nil || meta.Version != "v1.39.0" {
		t.Fatalf("older cache metadata = %+v, %v", meta, err)
	}
}

func TestLeased_FreshnessCheckDownloadsOnlyOnChange(t *testing.T) {
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	v1 := rulesettest.Issue(t, signer, "dca", "v1.40.0", testRules, time.Now().Add(30*24*time.Hour))
	srv := rulesettest.NewServer(t, v1)
	m := newLeasedManager(t, srv.URL)
	ctx := context.Background()

	path, err := m.GetRulesetPath(ctx, "dca", "latest")
	if err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(path, metadataFileName)
	expireTTL := func() {
		t.Helper()
		meta, err := LoadMetadata(metaPath)
		if err != nil {
			t.Fatal(err)
		}
		meta.DownloadedAt = time.Now().Add(-48 * time.Hour)
		meta.CheckedAt = time.Time{}
		if err := meta.Save(metaPath); err != nil {
			t.Fatal(err)
		}
	}

	// Same release: one check, no download.
	expireTTL()
	if _, err := m.GetRulesetPath(ctx, "dca", "latest"); err != nil {
		t.Fatal(err)
	}
	if downloads, checks := srv.Counts(); downloads != 1 || checks != 1 {
		t.Fatalf("same release: downloads=%d checks=%d, want 1 and 1", downloads, checks)
	}
	if meta, _ := LoadMetadata(metaPath); meta.CheckedAt.IsZero() || meta.IsExpired() {
		t.Fatalf("check not recorded: %+v", meta)
	}

	// New release: downloaded.
	srv.Set(rulesettest.Issue(t, signer, "dca", "v1.41.0", map[string]string{"rules/java/aes.yaml": rulesettest.RuleYAML + "# v1.41\n"}, time.Now().Add(30*24*time.Hour)))
	expireTTL()
	if _, err := m.GetRulesetPath(ctx, "dca", "latest"); err != nil {
		t.Fatal(err)
	}
	if downloads, _ := srv.Counts(); downloads != 2 {
		t.Fatalf("new release: downloads=%d, want 2", downloads)
	}
	if meta, _ := LoadMetadata(metaPath); meta.Version != "v1.41.0" {
		t.Fatalf("cached version %s, want v1.41.0", meta.Version)
	}

	// Same release but the lease expires within the refresh window: renewed.
	soon := rulesettest.Issue(t, signer, "dca", "v1.42.0", testRules, time.Now().Add(2*24*time.Hour))
	srv.Set(soon)
	if err := m.storeLeased("dca", path, soon.Bundle, soon.LeaseJSON, soon.Lease, 1); err != nil {
		t.Fatal(err)
	}
	expireTTL()
	if _, err := m.GetRulesetPath(ctx, "dca", "latest"); err != nil {
		t.Fatal(err)
	}
	if downloads, _ := srv.Counts(); downloads != 3 {
		t.Fatalf("expiring lease: downloads=%d, want 3", downloads)
	}
}

func writeOtherRules(tw *tar.Writer) {
	content := []byte("rules: []\n")
	_ = tw.WriteHeader(&tar.Header{Name: "ruleset/example.yaml", Mode: 0o600, Size: int64(len(content))})
	_, _ = tw.Write(content)
}
