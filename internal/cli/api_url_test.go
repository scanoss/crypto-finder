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
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
)

func TestCheckAPIURL(t *testing.T) {
	if err := checkAPIURL("https://api.scanoss.com", false); err != nil {
		t.Errorf("https refused: %v", err)
	}
	if err := checkAPIURL("http://scanoss.internal:5443", true); err != nil {
		t.Errorf("allowed http refused: %v", err)
	}
	err := checkAPIURL("http://scanoss.internal:5443", false)
	fe, ok := failure.As(err)
	if !ok {
		t.Fatalf("checkAPIURL error = %v, want a *failure.Error", err)
	}
	if fe.Code != failure.CodeInvalidArguments || fe.Stage != failure.StageConfig {
		t.Errorf("code/stage = %s/%s, want %s/%s", fe.Code, fe.Stage, failure.CodeInvalidArguments, failure.StageConfig)
	}
}
