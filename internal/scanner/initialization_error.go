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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package scanner

import (
	"context"
	"fmt"

	"github.com/scanoss/crypto-finder/internal/failure"
)

// InitializationContextError classifies a completed initialization context.
func InitializationContextError(ctx context.Context, scannerName string) error {
	err := ctx.Err()
	switch err {
	case nil:
		return nil
	case context.DeadlineExceeded:
		return failure.New(
			failure.CodeScannerTimeout,
			failure.StageScan,
			fmt.Sprintf("%s initialization timed out", scannerName),
			failure.WithRetryable(true),
			failure.WithDetail("scanner", scannerName),
		)
	default:
		return failure.Wrap(
			err,
			failure.CodeScannerCancelled,
			failure.StageScan,
			fmt.Sprintf("%s initialization canceled", scannerName),
			failure.WithDetail("scanner", scannerName),
		)
	}
}
