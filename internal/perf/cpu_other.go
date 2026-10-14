// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

//go:build !unix

package perf

import "time"

// processCPU is not measured on this platform.
func processCPU() time.Duration { return 0 }
