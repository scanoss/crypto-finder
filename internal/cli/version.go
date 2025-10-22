package cli

import (
	"fmt"
	"runtime"

	"github.com/scanoss/crypto-finder/internal/version"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Display version, build, and runtime information for crypto-finder.",
	Run:   runVersion,
}

func runVersion(_ *cobra.Command, _ []string) {
	fmt.Printf("%s version %s\n", version.ToolName, version.Version)
	fmt.Printf("  Git commit:  %s\n", version.GitCommit)
	fmt.Printf("  Build date:  %s\n", version.BuildDate)
	fmt.Printf("  Go version:  %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
