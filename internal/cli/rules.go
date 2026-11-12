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
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/failure"
)

var rulesImportLease string

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage cached remote rulesets",
}

var rulesImportCmd = &cobra.Command{
	Use:   "import <bundle.tar.gz>",
	Short: "Store a signed offline ruleset bundle in the local cache",
	Long: `Store a signed offline ruleset bundle in the local cache.

The bundle's lease (--lease, by default <bundle>.lease.json) must verify the
bundle. It is stored encrypted with the configured API key under its ruleset
name and version, and used until its lease expires without contacting the
API. Scan with --ruleset-version <version> to use it.`,
	Args: cobra.ExactArgs(1),
	RunE: runRulesImport,
}

var rulesStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "List the cached rulesets and their leases",
	Args:  cobra.NoArgs,
	RunE:  runRulesStatus,
}

func init() {
	rulesImportCmd.Flags().StringVar(&rulesImportLease, "lease", "", "Lease file issued with the bundle (default <bundle>.lease.json)")
	rulesCmd.AddCommand(rulesImportCmd)
	rulesCmd.AddCommand(rulesStatusCmd)
}

func newRulesCacheManager() (*cache.Manager, error) {
	cfg := config.GetInstance()
	if err := cfg.Initialize(config.InitOptions{}); err != nil {
		return nil, failure.WrapUnknown(err, failure.CodeConfigInitializationFailed, failure.StageConfig, "failed to initialize config")
	}
	manager, err := cache.NewManager(api.NewClient(cfg.GetAPIURL(), cfg.GetAPIKey(), api.WithAllowHTTP(cfg.GetAllowHTTP())))
	if err != nil {
		return nil, failure.WrapUnknown(err, failure.CodeCacheInitializationFailed, failure.StageConfig, "failed to create cache manager")
	}
	return manager, nil
}

func runRulesImport(cmd *cobra.Command, args []string) error {
	bundle, err := os.ReadFile(args[0])
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput, fmt.Sprintf("failed to read bundle %q", args[0]))
	}
	leasePath := rulesImportLease
	if leasePath == "" {
		leasePath = args[0] + ".lease.json"
	}
	leaseJSON, err := os.ReadFile(leasePath)
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeInvalidArguments, failure.StageInput, fmt.Sprintf("failed to read lease %q (pass --lease)", leasePath))
	}
	manager, err := newRulesCacheManager()
	if err != nil {
		return err
	}
	lease, err := manager.ImportBundle(bundle, leaseJSON)
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeRulesLoadFailed, failure.StageRules, fmt.Sprintf("failed to import bundle %q", args[0]))
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Imported ruleset %s@%s (lease expires %s)\n",
		lease.Name, lease.Version, lease.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func runRulesStatus(cmd *cobra.Command, _ []string) error {
	manager, err := newRulesCacheManager()
	if err != nil {
		return err
	}
	cached, err := manager.List()
	if err != nil {
		return failure.WrapUnknown(err, failure.CodeCacheInitializationFailed, failure.StageConfig, "failed to list cached rulesets")
	}
	return writeRulesStatus(cmd.OutOrStdout(), cached)
}

func writeRulesStatus(out io.Writer, cached []cache.CachedRuleset) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tVERSION\tMODE\tEXPIRES AT\tKEY ID\tLANGUAGES"); err != nil {
		return err
	}
	for _, r := range cached {
		mode, expires, keyID, languages := "legacy", "-", "-", "-"
		if len(r.Languages) > 0 {
			languages = strings.Join(r.Languages, ",")
		}
		if r.Leased {
			mode = "leased"
			expires = r.ExpiresAt.UTC().Format(time.RFC3339)
			if r.SigningKeyID != "" {
				keyID = r.SigningKeyID
			}
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Version, mode, expires, keyID, languages); err != nil {
			return err
		}
	}
	return w.Flush()
}
