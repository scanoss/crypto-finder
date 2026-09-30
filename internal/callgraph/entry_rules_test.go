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

package callgraph

import "testing"

// TestTraceBackCondensed_TestCodeIsNotAnEntryPoint: a JUnit 3 setUp overrides
// a method of TestCase, a type outside the application, which would make it
// a framework entry. A test runner calls it, not the application, so crypto
// written in it stays unreachable when the test sources are in the graph.
func TestTraceBackCondensed_TestCodeIsNotAnEntryPoint(t *testing.T) {
	t.Parallel()
	setUp := FunctionID{Package: "com.app", Type: "LedgerTest", Name: "setUp"}
	crypto := FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance"}
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			setUp.String(): {
				ID: setUp, FilePath: "/repo/src/test/java/com/app/LedgerTest.java", StartLine: 8, EndLine: 12,
				Annotations: []string{"Override"},
				Calls:       []FunctionCall{{Callee: crypto, Line: 10}},
			},
		},
		Callers:          map[string][]string{crypto.String(): {setUp.String()}},
		SourceSupertypes: map[string][]string{"com.app.LedgerTest": {"junit.framework.TestCase"}},
	}

	trace := NewTracer(graph, ".").TraceBackCondensed(setUp, map[string]bool{"com.app": true}, 0, 0)

	if len(trace.Chains) != 0 {
		t.Fatalf("chains = %+v, want none: a test is not an entry point", trace.Chains)
	}
}
