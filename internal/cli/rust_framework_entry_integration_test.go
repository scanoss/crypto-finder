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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// A Rust web service whose handlers hash and sign through a helper module:
// the axum app registers them with get()/post() from axum::routing, the
// actix-web one with a #[post] attribute and web::post().to(). Each
// handler's crypto is reachable with a chain that starts at the handler as a
// framework_entry, and names the catalog entry that recognized it. The helper
// nothing calls stays unreachable. Both apps carry their real crate
// dependencies and Cargo.lock.
func TestRustFrameworkEntryReachability(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI test with real scanner")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	t.Parallel()

	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	rules := filepath.Join(root, "testdata", "rules", "rust-framework-entry.yaml")

	type want struct {
		reachability, first, rule string
	}
	for _, tc := range []struct {
		app      string
		findings map[string]want
	}{
		{
			app: "axum",
			findings: map[string]want{
				"axum/src/crypto.rs:7":  {graphfrag.ReachabilityReachable, "axum_signer::handlers.digest", "rust/axum:registration_call:get"},
				"axum/src/crypto.rs:12": {graphfrag.ReachabilityReachable, "axum_signer::handlers.sign", "rust/axum:registration_call:get"},
				"axum/src/crypto.rs:19": {reachability: graphfrag.ReachabilityUnreachable},
			},
		},
		{
			app: "actix",
			findings: map[string]want{
				"actix/src/crypto.rs:7":  {graphfrag.ReachabilityReachable, "actix_signer.digest", "rust/actix-web:decorator:get"},
				"actix/src/crypto.rs:12": {graphfrag.ReachabilityReachable, "actix_signer.sign", "rust/actix-web:registration_call:to"},
				"actix/src/crypto.rs:19": {reachability: graphfrag.ReachabilityUnreachable},
			},
		},
	} {
		t.Run(tc.app, func(t *testing.T) {
			t.Parallel()
			work := t.TempDir()
			target := filepath.Join(work, tc.app)
			require.NoError(t, os.CopyFS(target, os.DirFS(filepath.Join(root, "testdata", "projects", "rust_framework_entry", tc.app))))
			require.FileExists(t, filepath.Join(target, "Cargo.lock"))
			env := append(os.Environ(), isolatedHome(t)...)

			pass := runReachabilityPass(t, binary, env, rules, "rust", target, filepath.Join(work, "out"), "--export-callgraph-project-reachability")
			byLocation := map[string]graphfrag.ExportFindingGraph{}
			for _, v := range pass.verdicts {
				for i := range pass.export.FindingGraphs {
					if pass.export.FindingGraphs[i].FindingID == v.findingID {
						byLocation[v.location] = pass.export.FindingGraphs[i]
					}
				}
			}
			require.Len(t, byLocation, len(tc.findings), "findings: %v", keys(byLocation))
			for location, w := range tc.findings {
				graph, ok := byLocation[location]
				require.Truef(t, ok, "no finding at %s; findings: %v", location, keys(byLocation))
				require.Equal(t, w.reachability, graph.Reachability, "reachability of %s", location)
				if w.first == "" {
					continue
				}
				found := false
				for _, chain := range graph.CallChains {
					first := chain[0]
					// The handler calls the helper that holds the crypto.
					if first.RootKind == "framework_entry" && first.EntryRule == w.rule && len(chain) > 1 {
						found = true
					}
				}
				require.Truef(t, found, "%s: no chain starts at a framework_entry recognized by %s; chains: %+v", location, w.rule, graph.CallChains)
				require.Contains(t, pass.export.Functions[graph.CallChainIndexes[0][0]].FunctionName, w.first, "first frame of %s", location)
			}
		})
	}
}
