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
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
)

// filteredServer serves the index, the filtered download and the full
// download of one ruleset and counts the requests per path.
type filteredServer struct {
	t        *testing.T
	requests map[string]int
	bodies   []string
	fail     map[string]int
}

func newFilteredServer(t *testing.T) *filteredServer {
	t.Helper()
	return &filteredServer{t: t, requests: make(map[string]int), fail: make(map[string]int)}
}

func (s *filteredServer) client() *api.Client {
	return newMockAPIClient(func(w http.ResponseWriter, r *http.Request) {
		s.requests[r.URL.Path]++
		if status := s.fail[r.URL.Path]; status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("failed"))
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/index"):
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"name":"dca","version":"v1.0.0","checksum_sha256":"full","languages":["java","python"],"modules":{"java":["javax.crypto"],"python":["hashlib"]}}`))
		case strings.HasSuffix(r.URL.Path, "/filter"), strings.HasSuffix(r.URL.Path, "/download"):
			body, _ := io.ReadAll(r.Body)
			s.bodies = append(s.bodies, string(body))
			var buf bytes.Buffer
			gzWriter := gzip.NewWriter(&buf)
			if err := writeRulesetTarball(gzWriter); err != nil {
				s.t.Fatalf("Failed to write tarball: %v", err)
			}
			_ = gzWriter.Close()
			tarball := buf.Bytes()
			w.Header().Set("scanoss-ruleset-name", "dca")
			w.Header().Set("scanoss-ruleset-version", "v1.0.0")
			w.Header().Set("x-checksum-sha256", CalculateSHA256(tarball))
			w.Header().Set("scanoss-ruleset-created-at", time.Now().Format(time.RFC3339))
			if strings.HasSuffix(r.URL.Path, "/filter") {
				w.Header().Set("scanoss-ruleset-profile", "server-hash")
				w.Header().Set("scanoss-ruleset-rules", "2/300")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(tarball)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newFilteredManager(t *testing.T, server *filteredServer) *Manager {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	manager, err := NewManager(server.client())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return manager
}

func TestManager_GetFilteredRulesetPath(t *testing.T) {
	server := newFilteredServer(t)
	manager := newFilteredManager(t, server)
	profile := api.RulesetProfile{Languages: []string{"python", "java"}, Modules: map[string][]string{"java": {"javax.crypto"}}}
	ctx := context.Background()

	path, err := manager.GetFilteredRulesetPath(ctx, "dca", "latest", profile)
	if err != nil {
		t.Fatalf("GetFilteredRulesetPath: %v", err)
	}
	wantDir := filepath.Join(manager.cacheDir, "dca", "profiles", "latest", profileHash(profile))
	if path != wantDir {
		t.Errorf("path = %s, want %s", path, wantDir)
	}
	if _, err := os.Stat(filepath.Join(path, "semgrep-rules", "java", "example.yaml")); err != nil {
		t.Errorf("filtered rules not extracted: %v", err)
	}
	if server.bodies[0] != `{"languages":["python","java"],"modules":{"java":["javax.crypto"]}}` {
		t.Errorf("unexpected filter body %s", server.bodies[0])
	}
	meta, err := LoadMetadata(filepath.Join(path, metadataFileName))
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if meta.Profile != profileHash(profile) || meta.Version != "v1.0.0" || meta.TTLSeconds != int64(manager.getTTL("latest").Seconds()) {
		t.Errorf("unexpected metadata %+v", meta)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if manifest.Rules != "2/300" || manifest.Profile != "server-hash" {
		t.Errorf("unexpected manifest %+v", manifest)
	}

	// A second call with the same modules in another order is a cache hit.
	again, err := manager.GetFilteredRulesetPath(ctx, "dca", "latest", api.RulesetProfile{Languages: []string{"java", "python"}, Modules: map[string][]string{"java": {"javax.crypto"}}})
	if err != nil || again != path {
		t.Errorf("second call: path=%s err=%v", again, err)
	}
	if n := server.requests["/v2/cryptography/rulesets/dca/latest/filter"]; n != 1 {
		t.Errorf("filter requests = %d, want 1", n)
	}

	// The full ruleset lives beside the profiles and is untouched by them.
	full, err := manager.GetRulesetPath(ctx, "dca", "latest")
	if err != nil {
		t.Fatalf("GetRulesetPath: %v", err)
	}
	if strings.HasPrefix(path, full+string(filepath.Separator)) {
		t.Errorf("filtered path %s must not lie below the full ruleset %s", path, full)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("full download must keep the filtered cache: %v", err)
	}
}

func TestManager_GetFilteredRulesetPath_ErrorsAreReported(t *testing.T) {
	server := newFilteredServer(t)
	server.fail["/v2/cryptography/rulesets/dca/latest/filter"] = http.StatusBadRequest
	manager := newFilteredManager(t, server)

	_, err := manager.GetFilteredRulesetPath(context.Background(), "dca", "latest", api.RulesetProfile{Languages: []string{"java"}})
	if err == nil {
		t.Fatal("expected the filter failure to be reported")
	}
}

func TestManager_GetRulesetIndex(t *testing.T) {
	server := newFilteredServer(t)
	manager := newFilteredManager(t, server)
	ctx := context.Background()

	index, err := manager.GetRulesetIndex(ctx, "dca", "latest")
	if err != nil {
		t.Fatalf("GetRulesetIndex: %v", err)
	}
	if index.Version != "v1.0.0" || index.Modules["java"][0] != "javax.crypto" {
		t.Errorf("unexpected index %+v", index)
	}
	indexPath := filepath.Join(manager.cacheDir, "dca", "profiles", "latest", indexFileName)
	if _, err := os.Stat(indexPath); err != nil {
		t.Fatalf("index not cached: %v", err)
	}

	if _, err := manager.GetRulesetIndex(ctx, "dca", "latest"); err != nil {
		t.Fatalf("second GetRulesetIndex: %v", err)
	}
	if n := server.requests["/v2/cryptography/rulesets/dca/latest/index"]; n != 1 {
		t.Errorf("index requests = %d, want 1 (cached)", n)
	}

	expired := time.Now().Add(-2 * manager.getTTL("latest"))
	if err := os.Chtimes(indexPath, expired, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GetRulesetIndex(ctx, "dca", "latest"); err != nil {
		t.Fatalf("third GetRulesetIndex: %v", err)
	}
	if n := server.requests["/v2/cryptography/rulesets/dca/latest/index"]; n != 2 {
		t.Errorf("index requests = %d, want 2 (expired)", n)
	}

	server.fail["/v2/cryptography/rulesets/dca/latest/index"] = http.StatusNotFound
	manager.SetNoCache(true)
	if _, err := manager.GetRulesetIndex(ctx, "dca", "latest"); err == nil {
		t.Error("an index failure must be reported")
	}
}

func TestProfileHash(t *testing.T) {
	t.Parallel()

	a := profileHash(api.RulesetProfile{Languages: []string{"python", "java"}, Modules: map[string][]string{"python": {"hashlib", "cryptography.hazmat"}, "java": {"javax.crypto"}}})
	b := profileHash(api.RulesetProfile{Languages: []string{"java", "python"}, Modules: map[string][]string{"java": {"javax.crypto"}, "python": {"cryptography.hazmat", "hashlib"}}})
	if a != b {
		t.Errorf("hash depends on order: %s != %s", a, b)
	}
	if a == profileHash(api.RulesetProfile{Languages: []string{"java"}}) {
		t.Error("different profiles must hash differently")
	}
}
