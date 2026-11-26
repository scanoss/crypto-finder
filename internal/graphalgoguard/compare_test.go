// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphalgoguard_test

import (
	"strings"
	"testing"
)

func guardGolden(java, python ecosystemDigest) *graphAlgoGolden {
	return &graphAlgoGolden{Ecosystems: map[string]ecosystemDigest{"java": java, "python": python}}
}

// TestCompareGraphAlgoGoldenPerEcosystem: the guard asks for the id of the
// ecosystem whose graph changed, and only that one. A Python change bumped
// under the Python id passes once recorded, with the Java entry untouched; a
// Python change under an unchanged Python id, or a Java change covered only by
// a Python bump, fails and names the ecosystem.
func TestCompareGraphAlgoGoldenPerEcosystem(t *testing.T) {
	java := ecosystemDigest{GraphAlgoVersion: "graph-algo-37", SHA256: "aaaa", Functions: 6, InternalEdges: 7, ExternalCalls: 10}
	python := ecosystemDigest{GraphAlgoVersion: "graph-algo-py-1", SHA256: "bbbb", Functions: 8, InternalEdges: 5, ExternalCalls: 13}
	golden := guardGolden(java, python)

	pythonChanged := python
	pythonChanged.SHA256, pythonChanged.InternalEdges = "cccc", 9
	problem := compareGraphAlgoGolden(golden, *guardGolden(java, pythonChanged))
	if !strings.Contains(problem, "python (GraphAlgoVersionPython") || strings.Contains(problem, "java (") {
		t.Errorf("Python graph changed under the same Python id; problem should name python only:\n%s", problem)
	}

	pythonBumped := pythonChanged
	pythonBumped.GraphAlgoVersion = "graph-algo-py-2"
	current := *guardGolden(java, pythonBumped)
	if unbumped := unbumpedEcosystems(golden.Ecosystems, current.Ecosystems); len(unbumped) != 0 {
		t.Errorf("Python change with a Python bump reported unbumped: %v", unbumped)
	}
	problem = compareGraphAlgoGolden(golden, current)
	if !strings.Contains(problem, "-update") || strings.Contains(problem, "java:") {
		t.Errorf("bumped Python change should only ask to record the python entry:\n%s", problem)
	}
	if problem := compareGraphAlgoGolden(&current, current); problem != "" {
		t.Errorf("recorded golden still fails: %s", problem)
	}

	javaChanged := java
	javaChanged.SHA256 = "dddd"
	problem = compareGraphAlgoGolden(golden, *guardGolden(javaChanged, pythonBumped))
	if !strings.Contains(problem, "java (GraphAlgoVersion,") {
		t.Errorf("Java graph changed with only a Python bump; problem should name java:\n%s", problem)
	}
}
