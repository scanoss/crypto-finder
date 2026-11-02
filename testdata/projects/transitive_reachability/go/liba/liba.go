// Package transliba is a direct dependency with no hashing of its own.
package transliba

import "example.com/translibb"

// Used is the path the application calls.
func Used(data []byte) []byte {
	return translibb.UsedHash(data)
}

// Unused is a path nothing in the application calls.
func Unused(data []byte) []byte {
	return translibb.UnusedHash(data)
}
