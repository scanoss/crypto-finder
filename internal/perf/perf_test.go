// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package perf

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func resetForTest(t *testing.T, value string) {
	t.Helper()
	t.Setenv(EnvPhaseTimings, value)
	setupOnce = sync.Once{}
	out, outFile = nil, nil
	mu.Lock()
	totals = map[string]*aggregate{}
	mu.Unlock()
	t.Cleanup(func() {
		if outFile != nil {
			_ = outFile.Close()
		}
		setupOnce = sync.Once{}
		out, outFile = nil, nil
	})
}

func TestPhaseTimingsWrittenToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timings.txt")
	resetForTest(t, path)

	Time("parse", func() {})
	for range 3 {
		StartQuiet("parse.file").End()
	}
	Note("slow_parse file=%s", "big.go")
	WriteSummary()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"phase_timing name=parse wall_ms=",
		"phase_note slow_parse file=big.go",
		"phase_total name=parse count=1 ",
		"phase_total name=parse.file count=3 ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("timings lack %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "phase_timing name=parse.file") {
		t.Errorf("a quiet span printed its own line:\n%s", text)
	}
}

func TestPhaseTimingsDisabledWritesNothing(t *testing.T) {
	resetForTest(t, "")
	if Enabled() {
		t.Fatal("timings enabled without the environment variable")
	}
	if wall := Start("scan").End(); wall < 0 {
		t.Fatalf("wall = %s", wall)
	}
	WriteSummary()
}

func TestZeroSpanIsNoop(t *testing.T) {
	var span Span
	if got := span.End(); got != 0 {
		t.Fatalf("zero span End() = %s, want 0", got)
	}
}
