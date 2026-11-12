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
package engine

import (
	"errors"
	"fmt"
	"testing"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/failure"
)

func TestRulesLoadFailure(t *testing.T) {
	t.Parallel()

	upgrade := fmt.Errorf("failed to get ruleset 'dca@latest': %w", &apiclient.UpgradeRequiredError{StatusCode: 426, Message: "Upgrade crypto-finder."})
	got, ok := failure.As(rulesLoadFailure(upgrade, "failed to load rules"))
	if !ok || got.Code != failure.CodeUpgradeRequired || got.Message != "Upgrade crypto-finder." || got.Details["http_status"] != "426" || got.Error() != "Upgrade crypto-finder." {
		t.Fatalf("upgrade: %+v", got)
	}

	refused := fmt.Errorf("download failed: %w", &apiclient.RefusedError{StatusCode: 403, Message: "key without ruleset access"})
	got, ok = failure.As(rulesLoadFailure(refused, "failed to load rules"))
	want := "failed to load rules: the SCANOSS API refused the ruleset download (HTTP 403): key without ruleset access"
	if !ok || got.Code != failure.CodeRulesLoadFailed || got.Error() != want {
		t.Fatalf("refused: %+v (%q)", got, got.Error())
	}

	got, ok = failure.As(rulesLoadFailure(errors.New("boom"), "failed to load rules"))
	if !ok || got.Code != failure.CodeRulesLoadFailed || got.Error() != "failed to load rules: boom" {
		t.Fatalf("other: %+v", got)
	}
}
