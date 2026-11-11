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
	"strconv"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/failure"
)

// rulesLoadFailure turns a rule loading error into the terminal failure. An
// API answer that this crypto-finder must be upgraded becomes
// upgrade_required with the server's message alone, so the CLI shows that
// message and nothing else. A refused API key (401/403) is rules_load_failed
// naming the status and the server's message; any other error is
// rules_load_failed with the error chain.
func rulesLoadFailure(err error, message string) error {
	var upgrade *apiclient.UpgradeRequiredError
	if errors.As(err, &upgrade) {
		return failure.New(failure.CodeUpgradeRequired, failure.StageRules, upgrade.Message,
			failure.WithDetail("http_status", strconv.Itoa(upgrade.StatusCode)))
	}
	var refused *apiclient.RefusedError
	if errors.As(err, &refused) {
		return failure.New(failure.CodeRulesLoadFailed, failure.StageRules,
			fmt.Sprintf("%s: the SCANOSS API refused the ruleset download (HTTP %d): %s", message, refused.StatusCode, refused.Message),
			failure.WithDetail("http_status", strconv.Itoa(refused.StatusCode)))
	}
	return failure.WrapUnknown(err, failure.CodeRulesLoadFailed, failure.StageRules, message)
}
