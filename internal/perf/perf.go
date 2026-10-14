// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package perf records opt-in wall-clock, CPU and allocation timings for the
// phases of a scan.
//
// Every span is logged at debug level. Setting SCANOSS_PHASE_TIMINGS to 1 (or
// true / stderr) also prints one "phase_timing" line per printed span to
// stderr; any other non-empty value names a file the lines are appended to.
// WriteSummary adds one aggregated line per phase name at the end of a scan.
//
// cpu_ms is the process CPU time (user+system) spent while the span was open,
// so cpu_ms/wall_ms near 1 marks a single-threaded phase. Spans that overlap
// (parallel per-dependency work) each see the whole process's CPU.
package perf

import (
	"fmt"
	"io"
	"os"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// EnvPhaseTimings is the environment variable that enables phase timing output.
const EnvPhaseTimings = "SCANOSS_PHASE_TIMINGS"

const allocMetric = "/gc/heap/allocs:bytes"

type aggregate struct {
	order int
	count int
	wall  time.Duration
	cpu   time.Duration
	alloc uint64
}

var (
	setupOnce sync.Once
	out       io.Writer
	outFile   *os.File

	mu     sync.Mutex
	totals = map[string]*aggregate{}
)

func setup() {
	value := strings.TrimSpace(os.Getenv(EnvPhaseTimings))
	switch strings.ToLower(value) {
	case "", "0", "false", "off":
	case "1", "true", "on", "stderr":
		out = os.Stderr
	default:
		//nolint:gosec // The path is the caller's own opt-in timings file.
		file, err := os.OpenFile(value, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Warn().Err(err).Str("path", value).Msg("Cannot open phase timings file; writing to stderr")
			out = os.Stderr
			return
		}
		outFile = file
		out = file
	}
}

// Enabled reports whether phase timing lines are written.
func Enabled() bool {
	setupOnce.Do(setup)
	return out != nil
}

// Span is one open phase. The zero value is a no-op.
type Span struct {
	name  string
	quiet bool
	start time.Time
	cpu   time.Duration
	alloc uint64
}

// Start opens a span whose end is printed and aggregated.
func Start(name string) Span {
	return start(name, false)
}

// StartQuiet opens a span that is only aggregated into the summary, for phases
// repeated once per dependency or file.
func StartQuiet(name string) Span {
	return start(name, true)
}

func start(name string, quiet bool) Span {
	return Span{name: name, quiet: quiet, start: time.Now(), cpu: processCPU(), alloc: heapAllocs()}
}

// End closes the span and returns its wall duration.
func (s Span) End() time.Duration {
	if s.name == "" {
		return 0
	}
	wall := time.Since(s.start)
	cpu := processCPU() - s.cpu
	alloc := heapAllocs() - s.alloc

	mu.Lock()
	agg, ok := totals[s.name]
	if !ok {
		agg = &aggregate{order: len(totals)}
		totals[s.name] = agg
	}
	agg.count++
	agg.wall += wall
	agg.cpu += cpu
	agg.alloc += alloc
	mu.Unlock()

	if !s.quiet {
		log.Debug().Str("phase", s.name).Dur("wall", wall).Dur("cpu", cpu).Uint64("alloc_bytes", alloc).Msg("Phase timing")
		if Enabled() {
			write(fmt.Sprintf("phase_timing name=%s wall_ms=%d cpu_ms=%d alloc_mb=%d\n",
				s.name, wall.Milliseconds(), cpu.Milliseconds(), alloc>>20))
		}
	}
	return wall
}

// Time runs fn inside a printed span.
func Time(name string, fn func()) {
	span := Start(name)
	defer span.End()
	fn()
}

// Note writes one free-form "phase_note" line when phase timings are enabled.
func Note(format string, args ...any) {
	if !Enabled() {
		return
	}
	write("phase_note " + fmt.Sprintf(format, args...) + "\n")
}

// WriteSummary writes one aggregated line per phase name, in first-seen order,
// when phase timings are enabled.
func WriteSummary() {
	if !Enabled() {
		return
	}
	mu.Lock()
	names := make([]string, 0, len(totals))
	for name := range totals {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return totals[names[i]].order < totals[names[j]].order })
	var b strings.Builder
	for _, name := range names {
		agg := totals[name]
		fmt.Fprintf(&b, "phase_total name=%s count=%d wall_ms=%d cpu_ms=%d alloc_mb=%d\n",
			name, agg.count, agg.wall.Milliseconds(), agg.cpu.Milliseconds(), agg.alloc>>20)
	}
	mu.Unlock()
	write(b.String())
	if outFile != nil {
		if err := outFile.Sync(); err != nil {
			log.Debug().Err(err).Msg("Failed to sync phase timings file")
		}
	}
}

var writeMu sync.Mutex

func write(line string) {
	writeMu.Lock()
	defer writeMu.Unlock()
	if _, err := io.WriteString(out, line); err != nil {
		log.Debug().Err(err).Msg("Failed to write phase timings")
	}
}

func heapAllocs() uint64 {
	sample := []metrics.Sample{{Name: allocMetric}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}
