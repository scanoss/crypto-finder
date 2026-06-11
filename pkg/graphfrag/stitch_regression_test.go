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

package graphfrag

import (
	"testing"
)

// TestStitch_ContractFKSupportingCallsSurviveNonRootStitch guards REQ-8.1:
// a supporting call that is referenced by a finding's SupportingCallIDs FK but
// is NOT on any backward BFS chain from the terminal (the terminal has in-degree 0)
// must still appear in the stitch result's SupportingCalls.
//
// This guards the fix in attachAnnotationSupportingCalls (stitch.go:88) introduced
// in commit 83daf55d. If this test goes RED, the bug has regressed.
func TestStitch_ContractFKSupportingCallsSurviveNonRootStitch(t *testing.T) {
	t.Parallel()

	// Scenario: a lib component with a synthesized terminal (Password4J-style).
	// The terminal's CryptoOperation carries a SupportingCallIDs FK pointing to
	// "lifecycle-sup-1". That supporting call is NOT reachable from the root via
	// any backward BFS chain (the crypto terminal has in-degree 0 — nothing calls
	// it from within the fragment closure). traversal alone would therefore drop it,
	// which is the exact bug attachAnnotationSupportingCalls resolves.
	libComponent := ComponentKey{Purl: "pkg:maven/com.password4j/password4j", Version: "1.8.0"}
	appComponent := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}

	const (
		appEntrySig        = "com.acme.(App).main#1"
		libTerminalSig     = "com.password4j.(HashBuilder).withBcrypt#0"
		libLifecycleSig    = "com.password4j.(Password).hash#1"
		lifecycleSupportID = "lifecycle-sup-1"
	)

	fragments := map[ComponentKey]Fragment{
		appComponent: {
			Component: appComponent,
			Module:    "com.acme:app",
			Functions: []Function{
				{Signature: appEntrySig, FunctionName: "com.acme.App.main"},
			},
			ExternalCalls: []ExternalCall{
				// The app calls the lib terminal directly (exact edge).
				{
					Caller:          appEntrySig,
					TargetSignature: libTerminalSig,
					Resolution:      ResolutionExact,
				},
			},
		},
		libComponent: {
			Component: libComponent,
			Module:    "com.password4j:password4j",
			Functions: []Function{
				{Signature: libTerminalSig, FunctionName: "com.password4j.HashBuilder.withBcrypt"},
				{Signature: libLifecycleSig, FunctionName: "com.password4j.Password.hash"},
			},
			// The terminal has a crypto operation with a FK to the lifecycle supporting call.
			CryptoOperations: []CryptoOperation{
				{
					Function:  libTerminalSig,
					FindingID: "bcrypt-finding-1",
					RuleID:    "java.password4j.HashBuilder.withBcrypt",
					Symbol:    "com.password4j.HashBuilder.withBcrypt",
					// SupportingCallIDs carries the FK to the lifecycle supporting call.
					// The lifecycle call is NOT on any backward chain from the terminal
					// (terminal has in-degree 0 in this lib fragment — nothing internal calls it).
					SupportingCallIDs: []string{lifecycleSupportID},
				},
			},
			// The lifecycle supporting call lives in the fragment pool but has no
			// backward-chain link to the terminal — it is a contract/annotation-derived
			// lifecycle call (Password.hash builds the HashBuilder used by withBcrypt).
			SupportingCalls: []SupportingCall{
				{
					Function:     libLifecycleSig,
					SupportingID: lifecycleSupportID,
					Category:     "factory",
				},
			},
		},
	}

	deps := DependencyGraph{
		appComponent: {libComponent},
	}

	// Use the entry-rooted path (the serving path that triggered the original bug).
	res, err := StitchWithOptions(appComponent, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}

	// The chain must be present.
	if len(res.Chains) == 0 {
		t.Fatal("expected at least one chain, got none")
	}

	// The lifecycle supporting call must survive in the result — it was dropped
	// before attachAnnotationSupportingCalls was introduced (commit 83daf55d).
	var found bool
	for _, sc := range res.SupportingCalls {
		if sc.SupportingID == lifecycleSupportID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("supporting call %q not found in stitch result — FK-derived supporting call was dropped; "+
			"this means the fix in attachAnnotationSupportingCalls (commit 83daf55d) has regressed. "+
			"SupportingCalls present: %v", lifecycleSupportID, supportingCallIDs(res.SupportingCalls))
	}
}

// TestStitch_ContractFKSupportingCallsSurviveHistoricalStitch guards the same
// bug on the historical (non-entry-rooted) Stitch path.
func TestStitch_ContractFKSupportingCallsSurviveHistoricalStitch(t *testing.T) {
	t.Parallel()

	libComponent := ComponentKey{Purl: "pkg:maven/com.password4j/password4j", Version: "1.8.0"}
	appComponent := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "2.0.0"}

	const (
		appEntrySig     = "com.acme.(App).run#0"
		libTerminalSig  = "com.password4j.(HashBuilder).withBcrypt#0"
		libLifecycleSig = "com.password4j.(Password).hash#1"
		supportID       = "lifecycle-sup-historical"
	)

	fragments := map[ComponentKey]Fragment{
		appComponent: {
			Component: appComponent,
			Module:    "com.acme:app",
			Functions: []Function{
				{Signature: appEntrySig, FunctionName: "com.acme.App.run"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          appEntrySig,
					TargetSignature: libTerminalSig,
					Resolution:      ResolutionExact,
				},
			},
		},
		libComponent: {
			Component: libComponent,
			Module:    "com.password4j:password4j",
			Functions: []Function{
				{Signature: libTerminalSig, FunctionName: "com.password4j.HashBuilder.withBcrypt"},
				{Signature: libLifecycleSig, FunctionName: "com.password4j.Password.hash"},
			},
			CryptoOperations: []CryptoOperation{
				{
					Function:          libTerminalSig,
					FindingID:         "bcrypt-finding-2",
					RuleID:            "java.password4j.HashBuilder.withBcrypt",
					Symbol:            "com.password4j.HashBuilder.withBcrypt",
					SupportingCallIDs: []string{supportID},
				},
			},
			SupportingCalls: []SupportingCall{
				{
					Function:     libLifecycleSig,
					SupportingID: supportID,
					Category:     "factory",
				},
			},
		},
	}

	deps := DependencyGraph{
		appComponent: {libComponent},
	}

	res, err := Stitch(appComponent, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}

	if len(res.Chains) == 0 {
		t.Fatal("expected at least one chain, got none")
	}

	var found bool
	for _, sc := range res.SupportingCalls {
		if sc.SupportingID == supportID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("supporting call %q not found in historical stitch result — FK-derived supporting call was dropped. "+
			"SupportingCalls present: %v", supportID, supportingCallIDs(res.SupportingCalls))
	}
}

// supportingCallIDs is a test helper that extracts SupportingID values for readable failure messages.
func supportingCallIDs(scs []SupportingCall) []string {
	ids := make([]string, 0, len(scs))
	for i := range scs {
		ids = append(ids, scs[i].SupportingID)
	}
	return ids
}
