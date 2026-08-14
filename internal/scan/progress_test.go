// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestProgressWriterWritesJSONLTerminalDurations(t *testing.T) {
	var output bytes.Buffer
	writer := NewProgressWriter(&output)

	if err := writer.Start("scan", ""); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	if err := writer.Start("rules", "scan"); err != nil {
		t.Fatalf("start rules: %v", err)
	}
	if err := writer.Complete("rules", "scan", nil); err != nil {
		t.Fatalf("complete rules: %v", err)
	}
	if err := writer.Skip("dependencies", "scan", "not_requested"); err != nil {
		t.Fatalf("skip dependencies: %v", err)
	}
	if err := writer.Cancel("scan", "", nil); err != nil {
		t.Fatalf("cancel scan: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("event count = %d, want 5: %s", len(lines), output.String())
	}

	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode event %q: %v", line, err)
		}
		if event["event"] != "scan_progress" || event["schema_version"] != "1" {
			t.Fatalf("envelope = %#v", event)
		}
	}

	var completed map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &completed); err != nil {
		t.Fatal(err)
	}
	if _, ok := completed["duration_ms"].(float64); !ok {
		t.Fatalf("completed event lacks integer duration_ms: %#v", completed)
	}
	if _, ok := completed["details"]; ok {
		t.Fatalf("completed rules event has unexpected details: %#v", completed)
	}
}

func TestProgressWriterWrapsEncodingErrors(t *testing.T) {
	wantErr := errors.New("write failed")
	writer := NewProgressWriter(errorWriter{err: wantErr})

	err := writer.Start("scan", "")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "scan/progress: encode event:") {
		t.Fatalf("Start error = %q, want scan/progress prefix", err)
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}
