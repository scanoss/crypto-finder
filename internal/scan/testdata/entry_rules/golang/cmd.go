package main

import (
	"crypto/sha512"

	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:  "export",
	RunE: runExport,
}

func runExport(cmd *cobra.Command, args []string) error {
	_ = sha512.Sum512_224([]byte("export"))
	return nil
}
