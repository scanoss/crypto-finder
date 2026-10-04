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
	"strings"
	"testing"
)

func TestResolveScannerJobs(t *testing.T) {
	t.Parallel()
	env := func(value string, set bool) func(string) (string, bool) {
		return func(name string) (string, bool) {
			if name != scannerJobsEnv {
				t.Errorf("looked up %s, want %s", name, scannerJobsEnv)
			}
			return value, set
		}
	}
	tests := []struct {
		name      string
		flagSet   bool
		flagValue int
		lookup    func(string) (string, bool)
		want      int32
		wantErr   string
	}{
		{name: "unset keeps the scanner default", lookup: env("", false), want: 0},
		{name: "empty variable keeps the scanner default", lookup: env("  ", true), want: 0},
		{name: "variable sets the jobs", lookup: env(" 3 ", true), want: 3},
		{name: "flag wins over the variable", flagSet: true, flagValue: 2, lookup: env("8", true), want: 2},
		{name: "explicit zero flag wins over the variable", flagSet: true, lookup: env("8", true), want: 0},
		{name: "upper bound accepted", flagSet: true, flagValue: maxScannerJobs, lookup: env("", false), want: maxScannerJobs},
		{name: "negative flag", flagSet: true, flagValue: -1, lookup: env("", false), wantErr: "--scanner-jobs must be between 0 and 1024, got -1"},
		{name: "flag above the bound", flagSet: true, flagValue: maxScannerJobs + 1, lookup: env("", false), wantErr: "--scanner-jobs must be between"},
		{name: "negative variable", lookup: env("-2", true), wantErr: scannerJobsEnv + " must be between 0 and 1024, got -2"},
		{name: "non-numeric variable", lookup: env("two", true), wantErr: scannerJobsEnv + ` must be a whole number of jobs, got "two"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveScannerJobs(tt.flagSet, tt.flagValue, tt.lookup)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("resolveScannerJobs = %d, %v; want %d", got, err, tt.want)
			}
		})
	}
}
