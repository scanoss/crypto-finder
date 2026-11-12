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

package apiclient

import "github.com/scanoss/crypto-finder/internal/version"

// UserAgent is the User-Agent of every request to the SCANOSS API:
// "crypto-finder/<version>", the product token the gateway reads the client
// family and version from (a dev build sends "crypto-finder/dev").
func UserAgent() string {
	return "crypto-finder/" + version.Version
}
