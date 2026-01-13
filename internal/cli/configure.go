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
	  crypto-finder configure --api-key YOUR_API_KEY

	  # Configure API URL
	  crypto-finder configure --api-url https://api.scanoss.com

	  # Configure multiple values
	  crypto-finder configure --api-key YOUR_API_KEY --api-url https://api.scanoss.com`,
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
