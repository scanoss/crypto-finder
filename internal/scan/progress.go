// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	progressEvent         = "scan_progress"
	progressSchemaVersion = "1"
)

// ProgressWriter writes scan lifecycle events as JSON lines.
type ProgressWriter struct {
	output  io.Writer
	started map[string]time.Time
}

// NewProgressWriter creates a writer for structured scan progress events.
func NewProgressWriter(output io.Writer) *ProgressWriter {
	return &ProgressWriter{output: output, started: make(map[string]time.Time)}
}

// Start writes a started event for phase.
func (w *ProgressWriter) Start(phase, parentPhase string) error {
	w.started[phase] = time.Now()
	return w.write(progressEventRecord{Phase: phase, Status: "started", ParentPhase: parentPhase})
}

// Complete writes a completed event for phase.
func (w *ProgressWriter) Complete(phase, parentPhase string, details map[string]any) error {
	return w.terminal(phase, parentPhase, "completed", details)
}

// Fail writes a failed event for phase.
func (w *ProgressWriter) Fail(phase, parentPhase string, details map[string]any) error {
	return w.terminal(phase, parentPhase, "failed", details)
}

// Cancel writes a canceled event for phase.
func (w *ProgressWriter) Cancel(phase, parentPhase string, details map[string]any) error {
	return w.terminal(phase, parentPhase, "canceled", details)
}

// Skip writes a skipped event for phase.
func (w *ProgressWriter) Skip(phase, parentPhase, reason string) error {
	return w.write(progressEventRecord{
		Phase:       phase,
		Status:      "skipped",
		ParentPhase: parentPhase,
		Details:     map[string]any{"reason": reason},
	})
}

func (w *ProgressWriter) terminal(phase, parentPhase, status string, details map[string]any) error {
	started := w.started[phase]
	duration := time.Since(started).Milliseconds()
	if started.IsZero() || duration < 0 {
		duration = 0
	}
	return w.write(progressEventRecord{
		Phase:       phase,
		Status:      status,
		ParentPhase: parentPhase,
		DurationMS:  &duration,
		Details:     details,
	})
}

func (w *ProgressWriter) write(event progressEventRecord) error {
	event.Event = progressEvent
	event.SchemaVersion = progressSchemaVersion
	if err := json.NewEncoder(w.output).Encode(event); err != nil {
		return fmt.Errorf("scan/progress: encode event: %w", err)
	}
	return nil
}

type progressEventRecord struct {
	Event         string         `json:"event"`
	SchemaVersion string         `json:"schema_version"`
	Phase         string         `json:"phase"`
	Status        string         `json:"status"`
	ParentPhase   string         `json:"parent_phase,omitempty"`
	DurationMS    *int64         `json:"duration_ms,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}
