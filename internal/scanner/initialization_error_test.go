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

//revive:disable:var-naming // scanner is a domain package name and intentionally matches CLI/config terminology.
package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/failure"
)

func TestInitializationContextError(t *testing.T) {
	for _, tt := range []struct {
		name      string
		context   func() (context.Context, context.CancelFunc)
		code      failure.Code
		retryable bool
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			code: failure.CodeScannerCancelled,
		},
		{
			name: "deadline exceeded",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			code:      failure.CodeScannerTimeout,
			retryable: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.context()
			defer cancel()

			structured, ok := failure.As(InitializationContextError(ctx, "test-scanner"))
			if !ok || structured.Code != tt.code {
				t.Fatalf("InitializationContextError() = %v, want %s", structured, tt.code)
			}
			if structured.Retryable != tt.retryable {
				t.Fatalf("InitializationContextError() retryable = %t, want %t", structured.Retryable, tt.retryable)
			}
			if structured.Details["scanner"] != "test-scanner" {
				t.Fatalf("InitializationContextError() scanner detail = %q, want test-scanner", structured.Details["scanner"])
			}
		})
	}
}
