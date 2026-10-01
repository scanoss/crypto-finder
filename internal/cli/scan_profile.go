// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"errors"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/scanoss/crypto-finder/internal/failure"
)

// startScanProfiles creates both profile files before the scan starts, so an
// unwritable path fails before a long scan instead of after it, and starts the
// CPU profile. An empty path disables that profile. The returned stop ends the
// CPU profile and writes the heap profile after a GC; calls after the first do
// nothing.
func startScanProfiles(cpuPath, memPath string) (stop func() error, err error) {
	cpuFile, err := createProfile(cpuPath)
	if err != nil {
		return nil, profileFailure(err, "failed to create scan profile")
	}
	memFile, err := createProfile(memPath)
	if err == nil && cpuFile != nil {
		err = pprof.StartCPUProfile(cpuFile)
	}
	if err != nil {
		return nil, profileFailure(errors.Join(err, closeProfile(cpuFile), closeProfile(memFile)), "failed to start scan profile")
	}

	stopped := false
	return func() error {
		if stopped {
			return nil
		}
		stopped = true
		if cpuFile != nil {
			pprof.StopCPUProfile()
		}
		var heapErr error
		if memFile != nil {
			runtime.GC()
			heapErr = pprof.WriteHeapProfile(memFile)
		}
		if err := errors.Join(heapErr, closeProfile(cpuFile), closeProfile(memFile)); err != nil {
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
