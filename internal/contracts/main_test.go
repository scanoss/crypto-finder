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

package contracts_test

import (
	"os"
	"testing"

	kb "github.com/scanoss/crypto-finder/internal/contracts"
)

// The tests in this package assert the content of the embedded KB through
// the engine's loader, so they register it first.
func TestMain(m *testing.M) {
	kb.RegisterAll()
	os.Exit(m.Run())
}
