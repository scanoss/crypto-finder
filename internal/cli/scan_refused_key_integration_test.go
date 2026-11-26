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

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/ruleset"
	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

// A scan fetches the crypto-cards ruleset by default and caches it. Once the
// cache TTL has elapsed, an API that refuses the key (401 or 403) fails the
// next scan with rules_load_failed and no findings, although the stale cache
// is valid; an API answering 503 lets the scan use that stale cache.
func TestScanRefusedKeyNeverUsesStaleCache(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	rule := "rules:\n  - id: " + progressRuleID + "\n    message: aes cipher\n    severity: INFO\n    languages: [java]\n    pattern: javax.crypto." + progressMatched + "\n    metadata:\n      crypto:\n        assetType: algorithm\n        algorithmFamily: AES\n        algorithmPrimitive: block-cipher\n"
	issued := rulesettest.Issue(t, signer, defaultRulesetName, "v1.40.0", map[string]string{"semgrep-rules/java/aes.yaml": rule}, time.Now().Add(30*24*time.Hour))
	rulesets := rulesettest.NewServer(t, issued)

	// answer is the status the API answers every request with; 0 serves the ruleset.
	var answer atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status := int(answer.Load()); status != 0 {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(status)
			_, _ = w.Write([]byte("key revoked"))
			return
		}
		rulesets.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(api.Close)

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			dir := t.TempDir()
			project := filepath.Join(dir, "project")
			writeAnnotateCardsFile(t, filepath.Join(project, "src", "Use.java"), "import javax.crypto.Cipher;\nclass Use { void run() throws Exception { "+progressMatched+"; } }\n")
			env := append(progressTestEnv(dir), ruleset.PubKeysEnv+"="+os.Getenv(ruleset.PubKeysEnv))
			scan := func(out string) (string, error) {
				cmd := exec.CommandContext(t.Context(), binary, "scan", "--api-url", api.URL, "--api-key", "test-key",
					"--error-format", "json", "--output", out, project)
				cmd.Env = env
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				err := cmd.Run()
				return stderr.String(), err
			}

			answer.Store(0)
			if stderr, err := scan(filepath.Join(dir, "first.json")); err != nil {
				t.Fatalf("first scan: %v\n%s", err, stderr)
			}
			expireRulesetTTL(t, filepath.Join(dir, ".scanoss", "crypto-finder", "cache", "rulesets", defaultRulesetName, "latest"))

			answer.Store(int32(status))
			out := filepath.Join(dir, "second.json")
			stderr, err := scan(out)
			if status == http.StatusServiceUnavailable {
				if err != nil {
					t.Fatalf("503: scan failed instead of using the stale cache: %v\n%s", err, stderr)
				}
				if !strings.Contains(string(readBytes(t, out)), progressRuleID) {
					t.Fatalf("503: the stale ruleset's finding is missing: %s", readBytes(t, out))
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("HTTP %d: scan = %v, want a failed scan\n%s", status, err, stderr)
			}
			if _, statErr := os.Stat(out); statErr == nil {
				t.Fatalf("HTTP %d: a report was written: %s", status, readBytes(t, out))
			}
			if !strings.Contains(stderr, `"rules_load_failed"`) || !strings.Contains(stderr, "refused the ruleset download") {
				t.Fatalf("HTTP %d: stderr lacks the rules_load_failed refusal:\n%s", status, stderr)
			}
		})
	}
}

// expireRulesetTTL makes the cached ruleset's TTL elapse, leaving its lease
// valid, so the next scan asks the API before using it.
func expireRulesetTTL(t *testing.T, rulesetPath string) {
	t.Helper()
	path := filepath.Join(rulesetPath, ".cache-meta.json")
	var meta map[string]any
	if err := json.Unmarshal(readBytes(t, path), &meta); err != nil {
		t.Fatal(err)
	}
	meta["downloaded_at"] = time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	meta["ttl_seconds"] = 1
	delete(meta, "checked_at")
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
