// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"errors"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/perf"
)

// Environment fallbacks for the hidden --cpuprofile, --memprofile and --trace
// flags, so a wrapper can profile a scan without changing its command line.
const (
	envCPUProfile = "SCANOSS_CPUPROFILE"
	envMemProfile = "SCANOSS_MEMPROFILE"
	envTrace      = "SCANOSS_TRACE"
)

// scanProfilePaths are the output paths of the opt-in scan profiles. An empty
// path disables that profile.
type scanProfilePaths struct {
	CPU   string
	Mem   string
	Trace string
}

// withEnvDefaults fills each path the flags left empty from its environment
// variable.
func (p scanProfilePaths) withEnvDefaults(lookup func(string) (string, bool)) scanProfilePaths {
	fill := func(path *string, env string) {
		if *path != "" {
			return
		}
		if value, ok := lookup(env); ok {
			*path = value
		}
	}
	fill(&p.CPU, envCPUProfile)
	fill(&p.Mem, envMemProfile)
	fill(&p.Trace, envTrace)
	return p
}

// startScanProfiles creates the profile files before the scan starts, so an
// unwritable path fails before a long scan instead of after it, and starts the
// CPU profile and execution trace. The returned stop ends them, writes the
// heap profile after a GC and the phase timing summary; calls after the first
// do nothing.
func startScanProfiles(paths scanProfilePaths) (stop func() error, err error) {
	cpuFile, err := createProfile(paths.CPU)
	if err != nil {
		return nil, profileFailure(err, "failed to create scan profile")
	}
	memFile, err := createProfile(paths.Mem)
	if err != nil {
		return nil, profileFailure(errors.Join(err, closeProfile(cpuFile)), "failed to create scan profile")
	}
	traceFile, err := createProfile(paths.Trace)
	if err == nil && cpuFile != nil {
		err = pprof.StartCPUProfile(cpuFile)
	}
	if err == nil && traceFile != nil {
		if err = trace.Start(traceFile); err != nil && cpuFile != nil {
			pprof.StopCPUProfile()
		}
	}
	if err != nil {
		return nil, profileFailure(errors.Join(err, closeProfile(cpuFile), closeProfile(memFile), closeProfile(traceFile)), "failed to start scan profile")
	}

	stopped := false
	return func() error {
		if stopped {
			return nil
		}
		stopped = true
		perf.WriteSummary()
		if traceFile != nil {
			trace.Stop()
		}
		if cpuFile != nil {
			pprof.StopCPUProfile()
		}
		var heapErr error
		if memFile != nil {
			runtime.GC()
			heapErr = pprof.WriteHeapProfile(memFile)
		}
		if err := errors.Join(heapErr, closeProfile(cpuFile), closeProfile(memFile), closeProfile(traceFile)); err != nil {
			return profileFailure(err, "failed to write scan profile")
		}
		return nil
	}, nil
}

func createProfile(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	return os.Create(path)
}

func closeProfile(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}

func profileFailure(err error, message string) error {
	return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, message)
}
