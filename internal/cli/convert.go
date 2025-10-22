package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/output"
)

var convertOutput string

var convertCmd = &cobra.Command{
	Use:   "convert [input-file]",
	Short: "Convert interim JSON format to CycloneDX CBOM",
	Long: `Convert crypto-finder interim format to CycloneDX 1.6 CBOM format.

The convert command transforms scan results from the interim JSON format to
CycloneDX CBOM (Cryptography Bill of Materials) format. It applies strict
mapping - only cryptographic assets with complete metadata are included in
the CBOM output.

Input Sources:
  - File path: convert results.json
  - Stdin: scan | convert (or convert < results.json)

Output Destinations:
  - Stdout (default): Output goes to stdout
  - File: --output cbom.json

Validation:
  The converter always validates output against CycloneDX 1.6 schema.
  Conversion fails if the generated CBOM is invalid.

Examples:
  # Convert from file to stdout
  crypto-finder convert results.json

  # Convert from file to output file
  crypto-finder convert results.json --output cbom.json

  # Convert from stdin (pipe from scan)
  crypto-finder scan --rules-dir ./rules /path/to/code | crypto-finder convert

  # Convert from stdin redirect
  crypto-finder convert < results.json

  # Convert with verbose validation output
  crypto-finder convert results.json --verbose --output cbom.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConvert,
}

func init() {
	// Add flags
	convertCmd.Flags().StringVarP(&convertOutput, "output", "o", "", "Output file path (default: stdout)")
}

// getInputReader determines the input source and returns a reader.
func getInputReader(args []string) (io.Reader, string, func(), error) {
	if len(args) > 0 {
		// Read from file
		inputSource := args[0]
		file, err := os.Open(inputSource)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to open input file: %w", err)
		}

		closeFunc := func() {
			if err := file.Close(); err != nil {
				log.Warn().Err(err).Str("path", inputSource).Msg("failed to close file")
			}
		}

		log.Info().Str("file", inputSource).Msg("Reading interim format from file")
		return file, inputSource, closeFunc, nil
	}

	// Check if stdin has data
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to stat stdin: %w", err)
	}

	if (stat.Mode() & os.ModeCharDevice) != 0 {
		// Stdin is a terminal (no piped data)
		return nil, "", nil, fmt.Errorf("no input provided: specify a file path or pipe data via stdin\n\nExamples:\n  convert results.json\n  scan | convert\n  convert < results.json")
	}

	// Read from stdin
	log.Info().Msg("Reading interim format from stdin")
	return os.Stdin, "stdin", nil, nil
}

func runConvert(_ *cobra.Command, args []string) error {
	// Determine input source
	reader, inputSource, closeFunc, err := getInputReader(args)
	if err != nil {
		return err
	}
	if closeFunc != nil {
		defer closeFunc()
	}

	// Parse interim JSON
	var report entities.InterimReport
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&report); err != nil {
		return fmt.Errorf("failed to parse interim JSON from %s: %w", inputSource, err)
	}

	log.Info().
		Str("tool", report.Tool.Name).
		Str("version", report.Tool.Version).
		Int("findings", len(report.Findings)).
		Msg("Interim format parsed successfully")

	// Convert to CycloneDX using the writer
	factory := output.NewWriterFactory()
	writer, err := factory.GetWriter("cyclonedx")
	if err != nil {
		return fmt.Errorf("failed to get CycloneDX writer: %w", err)
	}

	// Determine output destination
	outputDest := convertOutput
	if outputDest == "" {
		outputDest = "-" // stdout
	}

	// Perform conversion and write
	if err := writer.Write(&report, outputDest); err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	// Print summary to stderr (so it doesn't interfere with stdout output)
	if outputDest == "-" || outputDest == "" {
		fmt.Fprintf(os.Stderr, "\nConversion complete\n")
		fmt.Fprintf(os.Stderr, "  Output: <stdout>\n")
	} else {
		fmt.Fprintf(os.Stderr, "\nConversion complete\n")
		fmt.Fprintf(os.Stderr, "  Output: %s\n", outputDest)
	}

	return nil
}
