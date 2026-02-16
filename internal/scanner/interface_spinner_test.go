package scanner_test

import (
	"flag"
	"testing"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

func TestShouldUseSpinner_InTestsIsFalse(t *testing.T) {
	if scanner.ShouldUseSpinner() {
		t.Fatal("ShouldUseSpinner() should be false in test process")
	}
}

func TestShouldUseSpinner_WithoutTestFlagStillSafe(t *testing.T) {
	orig := flag.CommandLine
	fs := flag.NewFlagSet("unit", flag.ContinueOnError)
	flag.CommandLine = fs
	defer func() {
		flag.CommandLine = orig
	}()

	// In CI/non-interactive test environments this should still be false,
	// but this path exercises the non test.v branch.
	if scanner.ShouldUseSpinner() {
		t.Fatal("ShouldUseSpinner() unexpectedly true in non-interactive environment")
	}
}
