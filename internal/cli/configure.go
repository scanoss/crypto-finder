package cli

import (
	"fmt"

	"github.com/scanoss/crypto-finder/internal/config"

	"github.com/spf13/cobra"
)

var (
	configAPIKey string
	configAPIURL string
)

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure SCANOSS crypto-finder settings",
	Long: `Configure SCANOSS crypto-finder settings.

	Examples:
	  # Configure API key
	  scanoss-cf configure --api-key YOUR_API_KEY

	  # Configure API URL
	  scanoss-cf configure --api-url https://api.scanoss.com

	  # Configure multiple values
	  scanoss-cf configure --api-key YOUR_API_KEY --api-url https://api.scanoss.com`,
	RunE: runConfigure,
}

func init() {
	configureCmd.Flags().StringVar(&configAPIKey, "api-key", "", "SCANOSS API key")
	configureCmd.Flags().StringVar(&configAPIURL, "api-url", "", "SCANOSS API base URL")
}

func runConfigure(_ *cobra.Command, _ []string) error {
	if configAPIKey == "" && configAPIURL == "" {
		return fmt.Errorf("at least one of --api-key or --api-url must be provided")
	}

	cfg := config.GetInstance()
	// Initialize to load existing values from env/config file
	if err := cfg.Initialize("", ""); err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	// Update only the provided values using setters
	if configAPIKey != "" {
		if err := cfg.SetAPIKey(configAPIKey); err != nil {
			return fmt.Errorf("failed to set API key: %w", err)
		}
	}
	if configAPIURL != "" {
		if err := cfg.SetAPIURL(configAPIURL); err != nil {
			return fmt.Errorf("failed to set API URL: %w", err)
		}
	}

	fmt.Println("Configuration updated successfully!")

	if configAPIKey != "" {
		fmt.Println("✓ API key configured")
	}
	if configAPIURL != "" {
		fmt.Printf("✓ API URL set to: %s\n", configAPIURL)
	}

	return nil
}
