// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

// lenient drops the error of a call whose result the caller keeps as it is: a
// marshal of a value that always encodes.
func lenient[T any](v T, _ error) T {
	return v
}

// discard drops an error that cannot be acted on: a decode of metadata that
// may be absent or malformed, which then stays empty.
func discard(error) {}
