package utils_test

import (
	"math"
	"testing"

	"github.com/scanoss/crypto-finder/internal/utils"
)

func TestFDToInt(t *testing.T) {
	if got, ok := utils.FDToInt(uintptr(42)); !ok || got != 42 {
		t.Fatalf("FDToInt(42) = (%d, %v), want (42, true)", got, ok)
	}

	overflow := uintptr(math.MaxInt) + 1
	if got, ok := utils.FDToInt(overflow); ok || got != 0 {
		t.Fatalf("FDToInt(overflow) = (%d, %v), want (0, false)", got, ok)
	}
}
