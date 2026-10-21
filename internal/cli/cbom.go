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

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/utils"
	"github.com/scanoss/crypto-finder/internal/version"
	"github.com/scanoss/crypto-finder/pkg/sbomcbom"
)

var (
	cbomOutput        string
	cbomAPIKey        string
	cbomAPIURL        string
	cbomMaxComponents int
)

var cbomCmd = &cobra.Command{
	Use:   "cbom <sbom-file>",
	Short: "Build a CBOM for an SBOM from SCANOSS's mined findings",
	Long: `Build a CycloneDX 1.7 CBOM for the components an SBOM lists.

Nothing is scanned locally. For every component with a package URL and a
version, cbom asks the SCANOSS API for the findings crypto-finder produced
when SCANOSS mined that component, and converts them exactly as convert does.
Each component that uses cryptography becomes a library in the CBOM whose
dependencies are its cryptographic assets.

The SBOM can be CycloneDX JSON, SPDX JSON or SPDX tag-value; "-" reads stdin.
A summary of every component (crypto, no-crypto, not-mined, unsupported or
failed) goes to stderr.

Examples:
  crypto-finder cbom sbom.cdx.json --output cbom.json
  syft dir:. -o cyclonedx-json | crypto-finder cbom - > cbom.json`,
	Args: cobra.ExactArgs(1),
	RunE: runCBOM,
}

func init() {
	cbomCmd.Flags().StringVarP(&cbomOutput, "output", "o", "", "Output file path (default: stdout)")
	cbomCmd.Flags().StringVar(&cbomAPIKey, "api-key", "", "SCANOSS API key")
	cbomCmd.Flags().StringVar(&cbomAPIURL, "api-url", "", "SCANOSS API base URL")
	cbomCmd.Flags().IntVar(&cbomMaxComponents, "max-components", 2000, "Refuse SBOMs with more distinct components than this")
}

func runCBOM(cmd *cobra.Command, args []string) error {
	data, err := readSBOM(args[0])
	if err != nil {
		return failure.Wrap(err, failure.CodeInvalidArguments, failure.StageInput, "failed to read the SBOM")
	}
	doc, err := sbomcbom.ParseSBOM(data)
	if err != nil {
		return failure.Wrap(err, failure.CodeInvalidArguments, failure.StageInput, "failed to parse the SBOM")
	}

	cfg := config.GetInstance()
	if err := cfg.Initialize(config.InitOptions{APIKey: cbomAPIKey, APIURL: cbomAPIURL}); err != nil {
		return failure.WrapUnknown(err, failure.CodeConfigInitializationFailed, failure.StageConfig, "failed to initialize config")
	}

	res, err := sbomcbom.Generate(cmd.Context(), doc, sbomcbom.Options{
		APIKey:        cfg.GetAPIKey(),
		APIURL:        cfg.GetAPIURL(),
		MaxComponents: cbomMaxComponents,
		ToolVersion:   version.Version,
	})
	switch {
	case errors.Is(err, sbomcbom.ErrTooManyComponents):
		return failure.Wrap(err, failure.CodeInvalidArguments, failure.StageInput, "the SBOM has too many components")
	case errors.Is(err, sbomcbom.ErrAccessDenied):
		return failure.Wrap(err, failure.CodeComponentLookupFailed, failure.StageDependency, "the SCANOSS API refused the API key")
	case err != nil:
		return failure.WrapUnknown(err, failure.CodeUnknown, failure.StageExport, "failed to build the CBOM")
	}

	out, err := json.MarshalIndent(res.BOM, "", "  ")
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to encode the CBOM")
	}
	if err := writeCBOM(out, cbomOutput); err != nil {
		return failure.WrapUnknown(err, failure.CodeOutputWriteFailed, failure.StageOutput, "failed to write the CBOM")
	}
	fmt.Fprint(os.Stderr, cbomSummary(doc, res))
	return nil
}

func readSBOM(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path) // #nosec G304 -- the user names the SBOM to read.
}

func writeCBOM(data []byte, destination string) error {
	data = append(data, '\n')
	if destination == "" || destination == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	return utils.WriteFileAtomic(abs, 0o600, func(file *os.File) error {
		_, err := file.Write(data)
		return err
	})
}

func cbomSummary(doc *sbomcbom.Document, res *sbomcbom.Result) string {
	counts := map[sbomcbom.Status]int{}
	for _, c := range res.Components {
		counts[c.Status]++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s SBOM, %d components with a purl", doc.Format, len(doc.Components))
	if doc.WithoutPURL > 0 {
		fmt.Fprintf(&b, " (%d without one, not looked up)", doc.WithoutPURL)
	}
	fmt.Fprintf(&b, "\n  crypto %d, no crypto %d, not mined %d, unsupported %d, failed %d\n",
		counts[sbomcbom.StatusCrypto], counts[sbomcbom.StatusNoCrypto], counts[sbomcbom.StatusNotMined],
		counts[sbomcbom.StatusUnsupported], counts[sbomcbom.StatusFailed])
	if res.RulesVersion != "" {
		fmt.Fprintf(&b, "  findings mined with rules %s\n", res.RulesVersion)
	}
	for _, c := range res.Components {
		if c.Status == sbomcbom.StatusFailed {
			fmt.Fprintf(&b, "  failed %s: %s\n", c.PURL, c.Problem)
		}
	}
	return b.String()
}
