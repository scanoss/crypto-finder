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

package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// scannerJobsEnv sets --scanner-jobs when the flag is not given.
const scannerJobsEnv = "SCANOSS_SCANNER_JOBS"

// maxScannerJobs bounds the knob well above any core count, so a typo fails
// instead of starting thousands of scanner workers.
const maxScannerJobs = 1024

// resolveScannerJobs returns the OpenGrep job count for the primary scan. An
// explicit --scanner-jobs wins over SCANOSS_SCANNER_JOBS; an empty or unset
// variable keeps the default. Zero keeps OpenGrep's own default.
func resolveScannerJobs(flagSet bool, flagValue int, lookupEnv func(string) (string, bool)) (int32, error) {
	source, value := "--scanner-jobs", flagValue
	if !flagSet {
		raw, ok := lookupEnv(scannerJobsEnv)
		raw = strings.TrimSpace(raw)
		if !ok || raw == "" {
			return 0, nil
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("%s must be a whole number of jobs, got %q", scannerJobsEnv, raw)
		}
		source, value = scannerJobsEnv, parsed
	}
	if value < 0 || value > maxScannerJobs {
		return 0, fmt.Errorf("%s must be between 0 and %d, got %d", source, maxScannerJobs, value)
	}
	return int32(value), nil
}
