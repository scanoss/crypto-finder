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

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// TestExportCallGraph_RefutedConditionVerdict: a rule's parameterCondition
// refutes a chain when the argument its caller passes contradicts it. A finding
// whose every chain is refuted does not run the crypto the rule describes on
// any known route, so it reads unreachable, not reachable with no chain,
// as the fragment's entry-point index already says by leaving it out. When
// the chain budget left a route or a call site unexamined, that one may satisfy
// the condition, so the verdict is unknown. hashWith is called twice from one
// function (two call sites on one route); hashOther once from each of two
// functions (two routes).
func TestExportCallGraph_RefutedConditionVerdict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, span, condition string
		maxChains             int
		wantReachability      string
		wantReachable         *bool
		wantReason            string
		wantChains            int
	}{
		{
			name: "every call site refuted", span: "MessageDigest.getInstance(alg)", condition: "param[0]==MD5",
			wantReachability: graphfrag.ReachabilityUnreachable, wantReachable: boolPtr(false),
		},
		{
			name: "every route refuted", span: "MessageDigest.getInstance(algorithm)", condition: "param[0]==MD5",
			wantReachability: graphfrag.ReachabilityUnreachable, wantReachable: boolPtr(false),
		},
		{
			name: "one call site matches", span: "MessageDigest.getInstance(alg)", condition: "param[0]==SHA-256",
			wantReachability: graphfrag.ReachabilityReachable, wantReachable: boolPtr(true), wantChains: 1,
		},
		{
			name: "budget dropped the matching call site", span: "MessageDigest.getInstance(alg)", condition: "param[0]==SHA-256", maxChains: 1,
			wantReachability: graphfrag.ReachabilityUnknown, wantReason: unresolvedTraversalTruncated,
		},
		{
			name: "budget dropped a route", span: "MessageDigest.getInstance(algorithm)", condition: "param[0]==MD5", maxChains: 1,
			wantReachability: graphfrag.ReachabilityUnknown, wantReason: unresolvedTraversalTruncated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := fluentConditionFixture(t, "refuted_conditions/java", "maven", "java", callgraph.NewJavaParser(),
				[]fluentConditionCase{{id: "finding", file: "src/main/java/com/app/Digests.java", span: tt.span, condition: tt.condition}})
			fg, ok := exportEntryRoots(t, fixture, tt.maxChains)["finding"]
			if !ok {
				t.Fatal("no finding graph")
			}
			if fg.Reachability != tt.wantReachability || fg.UnresolvedReason != tt.wantReason || len(fg.CallChains) != tt.wantChains {
				t.Errorf("reachability %q reason %q chains %d, want %q %q %d (chains %+v)",
					fg.Reachability, fg.UnresolvedReason, len(fg.CallChains),
					tt.wantReachability, tt.wantReason, tt.wantChains, shortChains(fg))
			}
			if tt.maxChains == 0 {
				// The fragment's entry-point index answers the same question:
				// it lists the finding only under a chain the condition keeps.
				fragment := buildGraphFragmentExport(fixture.result)
				indexed := fragmentIndexesFinding(&fragment, "finding")
				if want := tt.wantReachability == graphfrag.ReachabilityReachable; indexed != want {
					t.Errorf("fragment entry points index the finding = %v, want %v", indexed, want)
				}
			}
			switch {
			case tt.wantReachable == nil && fg.Reachable != nil:
				t.Errorf("reachable = %v, want unset", *fg.Reachable)
			case tt.wantReachable != nil && (fg.Reachable == nil || *fg.Reachable != *tt.wantReachable):
				t.Errorf("reachable = %v, want %v", fg.Reachable, *tt.wantReachable)
			}
		})
	}
}

func fragmentIndexesFinding(fragment *graphfrag.GraphFragmentExport, findingID string) bool {
	for i := range fragment.CryptoEntryPoints {
		for _, rf := range fragment.CryptoEntryPoints[i].ReachableFindings {
			if rf.FindingID == findingID {
				return true
			}
		}
	}
	return false
}
