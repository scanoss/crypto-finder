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

package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/ruleset/rulesettest"
)

func TestRemoteRuleSource_LeasedRulesetLivesOnlyForTheRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	signer := rulesettest.NewSigner(t, "test-key-1", true)
	issued := rulesettest.Issue(t, signer, "dca", "v1.40.0", map[string]string{"rules/java/aes.yaml": rulesettest.RuleYAML}, time.Now().Add(30*24*time.Hour))
	srv := rulesettest.NewServer(t, issued)
	manager, err := cache.NewManager(api.NewClient(srv.URL, "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	source := NewRemoteRuleSource(context.Background(), "dca", "latest", manager)

	paths, err := source.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || !source.Leased() {
		t.Fatalf("Load() = %v, leased=%v", paths, source.Leased())
	}
	runDir := paths[0]
	if _, err := os.Stat(filepath.Join(runDir, "rules", "java", "aes.yaml")); err != nil {
		t.Fatalf("rules not extracted into the run dir: %v", err)
	}
	again, err := source.Load()
	if err != nil || again[0] != runDir {
		t.Fatalf("second Load() = %v, %v; want the same run dir", again, err)
	}
	if downloads, _ := srv.Counts(); downloads != 1 {
		t.Fatalf("downloads = %d, want 1", downloads)
	}

	info := source.Info()
	if info.Version != "v1.40.0" || info.ChecksumSHA256 != issued.Lease.PayloadSHA || info.Lease == nil ||
		info.Lease.SigningKeyID != "test-key-1" || !info.Lease.ExpiresAt.Equal(issued.Lease.ExpiresAt) {
		t.Fatalf("Info() = %+v (lease %+v)", info, info.Lease)
	}
	// The report never carries the per-tenant bundle hash, the key or the tenant.
	report, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{issued.Lease.BundleSHA, issued.Lease.KeyRef, issued.Lease.Tenant} {
		if strings.Contains(string(report), s) {
			t.Fatalf("rules info %s reveals %q", report, s)
		}
	}

	source.Close()
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatalf("run dir survives Close(): %v", err)
	}
	if source.Info().Lease == nil {
		t.Fatal("Info() lost the lease after Close()")
	}
}
