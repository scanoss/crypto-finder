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

package ruleset

import (
	"encoding/json"
	"fmt"
)

// DecodeUnverified returns the lease inside an envelope without checking its
// signature, for display and for routing a bundle before Parse verifies it.
func DecodeUnverified(envelope []byte) (Lease, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return Lease{}, fmt.Errorf("ruleset: decode lease envelope: %w", err)
	}
	var l Lease
	if err := json.Unmarshal(env.Lease, &l); err != nil {
		return Lease{}, fmt.Errorf("ruleset: decode lease: %w", err)
	}
	return l, nil
}
