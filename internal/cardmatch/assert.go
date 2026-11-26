package cardmatch

import (
	"errors"
	"fmt"
)

// as is the unchecked type assertion v.(T): it panics when v is not a T, as the
// assertion does, so a malformed document fails loudly instead of decoding as
// the zero value.
func as[T any](v any) T {
	t, ok := v.(T)
	if !ok {
		panic(fmt.Sprintf("cardmatch: %T is not %T", v, t))
	}
	return t
}

// asOr is the comma-ok assertion v.(T) with the ok result dropped: the zero
// value of T when v is not a T.
func asOr[T any](v any) T {
	t, ok := v.(T)
	if !ok {
		var zero T
		return zero
	}
	return t
}

// lenient drops the error of a call whose partial result the caller keeps (0
// or "" for a syntax error, the clamped value for a range error).
func lenient[T any](v T, _ error) T {
	return v
}

// isSkipError reports whether err is, or wraps, a skipError.
func isSkipError(err error) bool {
	var s *skipError
	return errors.As(err, &s)
}
