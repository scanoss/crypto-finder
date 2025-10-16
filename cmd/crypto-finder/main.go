// Package main is the entry point for the crypto-finder CLI tool.
// Crypto-finder scans source code repositories for cryptographic algorithm usage
// and outputs results in a standardized JSON format.
package main

import (
	"github.com/scanoss/crypto-finder/internal/cli"
)

func main() {
	cli.Execute()
}
