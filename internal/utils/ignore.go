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

//revive:disable:var-naming // utils is a conventional package name for shared utilities
package utils

// Discard drops an error that cannot be acted on: a best-effort cleanup, a
// Close on a file that was only read, a write to a hash. Call it as
// Discard(f.Close()), inside a func literal when deferred.
func Discard(error) {}

// Lenient drops the error of a call whose partial result the caller keeps (the
// zero value for a syntax error, the clamped value for a range error, a short
// list for a failed glob).
func Lenient[T any](v T, _ error) T {
	return v
}

// AsOr is the comma-ok assertion v.(T) with the ok result dropped: the zero
// value of T when v is not a T.
func AsOr[T any](v any) T {
	t, ok := v.(T)
	if !ok {
		var zero T
		return zero
	}
	return t
}
