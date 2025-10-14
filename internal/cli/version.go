package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Version information (set by build flags)
	// TODO: Update version information to fetch from the actual git tag
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Display version, build, and runtime information for crypto-finder.",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("crypto-finder version %s\n", Version)
	fmt.Printf("  Git commit:  %s\n", GitCommit)
	fmt.Printf("  Build date:  %s\n", BuildDate)
	fmt.Printf("  Go version:  %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
