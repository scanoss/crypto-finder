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

const (
	// depSkipNotRequested: the scan ran without --scan-dependencies.
	depSkipNotRequested = "not_requested"

	progressStatusCompleted = "completed"
)

// dependencySkipDetails is the details object of a skipped dependencies
// progress event: the reason, and the ecosystem it is about when there is one.
func dependencySkipDetails(reason, ecosystem string) map[string]any {
	details := map[string]any{"reason": reason}
	if ecosystem != "" && reason != depSkipNotRequested {
		details["ecosystem"] = ecosystem
	}
	return details
}
