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

// Developer commands of the migration from rule YAML to v3 card files. They
// are hidden and are deleted with the rule compiler.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scanoss/crypto-finder/internal/cardmatch"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/failure"
	cardsscanner "github.com/scanoss/crypto-finder/internal/scanner/cards"
	"github.com/scanoss/crypto-finder/internal/utils"
)

var (
	cardsVerifyRules, cardsVerifyCards, cardsVerifyLang string

	cardsExportRules  string
	cardsExportLang   string
	cardsExportOutput string

	cardsExplainRules, cardsExplainCards, cardsExplainFragment, cardsExplainRule, cardsExplainAt string
)

// cardsExport is the export's document: one record per rule of the rules
// directory, in compile order.
type cardsExport struct {
	Format   string              `json:"format"`
	Language string              `json:"language"`
	Rules    []cardsExportedRule `json:"rules"`
	Counts   cardsExportCounts   `json:"counts"`
}

type cardsExportedRule struct {
	cardmatch.ExportedRule
	Conditioned *engine.RuleConditioned `json:"conditioned,omitempty"`
}

type cardsExportCounts struct {
	Rules, Compiled, Skipped, Lossy, Entries int
}

var cardsExportCmd = &cobra.Command{
	Use:    "cards-export",
	Short:  "Export what the rule compiler makes of each rule (migration to v3 card files)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		lang, err := cardsDevLanguage(cardsExportLang)
		if err != nil {
			return err
		}
		doc, err := exportCards(cardsExportRules, lang.Name)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(doc, "", " ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if cardsExportOutput == "" || cardsExportOutput == "-" {
			_, err = os.Stdout.Write(data)
			return err
		}
		if err := os.WriteFile(cardsExportOutput, data, 0o600); err != nil {
			return err
		}
		c := doc.Counts
		fmt.Fprintf(os.Stderr, "cards-export %s: %d rules, %d compiled (%d with dropped clauses), %d skipped, %d entries\n",
			doc.Language, c.Rules, c.Compiled, c.Lossy, c.Skipped, c.Entries)
		return nil
	},
}

// exportCards compiles the rules under rulesDir and adds each conditioned
// rule's catalog fields.
func exportCards(rulesDir, language string) (*cardsExport, error) {
	compiled, err := cardmatch.ExportRules(rulesDir)
	if err != nil {
		return nil, err
	}
	conditioned := engine.RuleConditionedFields([]string{rulesDir})
	doc := &cardsExport{Format: "cards-export/1", Language: language, Rules: make([]cardsExportedRule, 0, len(compiled))}
	for _, r := range compiled {
		out := cardsExportedRule{ExportedRule: r}
		if fields, ok := conditioned[r.ID]; ok {
			out.Conditioned = &fields
		}
		doc.Rules = append(doc.Rules, out)
		doc.Counts.Rules++
		doc.Counts.Entries += len(r.Sites)
		if r.Status == "compiled" {
			doc.Counts.Compiled++
			if len(r.DroppedClauses) > 0 {
				doc.Counts.Lossy++
			}
		} else {
			doc.Counts.Skipped++
		}
	}
	return doc, nil
}

// cardsDevLanguage resolves a --lang value of the cards dev commands. They
// compile and compare rules with the rule compiler, which exists only for the
// compiled languages: the others are rejected, not silently treated as Java.
func cardsDevLanguage(name string) (cardsscanner.Language, error) {
	lang, ok := cardsscanner.ForName(name)
	if !ok {
		return cardsscanner.Language{}, failure.New(failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("unknown --lang %q (%s)", name, cardsDevLanguageNames()))
	}
	if !lang.Compiled {
		return cardsscanner.Language{}, failure.New(failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("--lang %q is not supported by the cards dev commands yet (%s)", name, cardsDevLanguageNames()))
	}
	return lang, nil
}

// cardsDevLanguageNames lists the --lang values the cards dev commands accept.
func cardsDevLanguageNames() string {
	var names []string
	for _, l := range cardsscanner.Languages() {
		if l.Compiled {
			names = append(names, l.Name)
		}
	}
	return strings.Join(names, ", ")
}

var cardsCmd = &cobra.Command{
	Use:    "cards",
	Short:  "Developer commands of the migration to v3 card files",
	Hidden: true,
}

var cardsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Check v3 card files against the rule YAML and the compiler they replace (A1-A4)",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		var lang cardsscanner.Language
		if cardsVerifyLang != "" {
			var langErr error
			if lang, langErr = cardsDevLanguage(cardsVerifyLang); langErr != nil {
				return langErr
			}
		}
		diffs, err := verifyCards(os.Stdout, cardsVerifyRules, cardsVerifyCards, lang.Ecosystem)
		if err != nil {
			return err
		}
		if diffs > 0 {
			return fmt.Errorf("cards verify: %d differences", diffs)
		}
		return nil
	},
}

// verifyCards runs the identity checks of the v3 card files under cardsDir
// (cards/<lang>) against the rules under rulesDir (semgrep-rules/<lang>),
// writes a report and returns the number of differences.
func verifyCards(w io.Writer, rulesDir, cardsDir, language string) (int, error) {
	matcher, err := cardmatch.VerifyV3(rulesDir, cardsDir)
	if err != nil {
		return 0, err
	}
	data, err := engine.VerifyV3Rules(rulesDir, cardsDir, language)
	if err != nil {
		return 0, err
	}
	infoRules, info, err := cardsscanner.VerifyRuleInfo(rulesDir, cardsDir)
	if err != nil {
		return 0, err
	}
	a4 := append(append([]string{}, info...), filterPrefix(data.Diffs, "A4:")...)
	for _, d := range matcher.Diffs {
		if !strings.Contains(d, "crypto differs") {
			continue
		}
		a4 = append(a4, d)
	}
	a1 := []string{}
	for _, d := range matcher.Diffs {
		if !strings.Contains(d, "crypto differs") {
			a1 = append(a1, d)
		}
	}
	checks := []struct {
		name, what string
		diffs      []string
	}{
		{"A1", fmt.Sprintf("site entries: %d rules with site cards (%d cards), %d index entries loaded; %d hand-carded, %d pending",
			matcher.SiteRules, matcher.Sites, matcher.Entries, matcher.HandRules, matcher.Pending), a1},
		{"A2", fmt.Sprintf("conditioned catalog: %d rules", data.ConditionedRules), filterPrefix(data.Diffs, "A2:")},
		{"A3", fmt.Sprintf("synthesis map: %d api symbols", data.APIs), filterPrefix(data.Diffs, "A3:")},
		{"A4", fmt.Sprintf("rule info: %d rules (check id, message, severity, purl; crypto as the matcher and the engine read it)",
			infoRules), a4},
	}
	total := 0
	for _, c := range checks {
		status := "ok"
		if len(c.diffs) > 0 {
			status = "FAILED"
		}
		utils.Lenient(fmt.Fprintf(w, "%s %s %s: %d differences: %s\n", language, c.name, c.what, len(c.diffs), status))
		for _, d := range c.diffs {
			utils.Lenient(fmt.Fprintf(w, "  %s\n", d))
		}
		total += len(c.diffs)
	}
	return total, nil
}

func filterPrefix(diffs []string, prefix string) []string {
	var out []string
	for _, d := range diffs {
		if strings.HasPrefix(d, prefix) {
			out = append(out, d)
		}
	}
	return out
}

func init() {
	cardsVerifyCmd.Flags().StringVar(&cardsVerifyRules, "rules", "", "Rules directory of one language (semgrep-rules/<lang>)")
	cardsVerifyCmd.Flags().StringVar(&cardsVerifyCards, "cards", "", "v3 cards directory of the same language (cards/<lang>)")
	cardsVerifyCmd.Flags().StringVar(&cardsVerifyLang, "lang", "", "Language ("+cardsDevLanguageNames()+")")
	for _, f := range []string{"rules", "cards", "lang"} {
		utils.Discard(cardsVerifyCmd.MarkFlagRequired(f))
	}
	cardsCmd.AddCommand(cardsVerifyCmd)
	rootCmd.AddCommand(cardsCmd)
}

var cardsExplainCmd = &cobra.Command{
	Use:   "explain",
	Short: "Show which stage of the matcher decides a rule at a source line of an exported graph fragment",
	Long: `For one rule and one line of a graph fragment written by scan --export-graph-fragment, runs the
compiled entries of the rule on each call site of the line and prints, per entry and site, the
stage that rejected it (call, constraints, insides, not_inside, not_calls, taint) or "reported".
A rule with a hand card is flagged: in a scan the card replaces its entries.`,
	Args: cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		file, line, ok := strings.Cut(cardsExplainAt, ":")
		n, err := strconv.Atoi(line)
		if !ok || err != nil || file == "" {
			return fmt.Errorf("--at %q: want <file>:<line>, the file as the fragment names it", cardsExplainAt)
		}
		assets, err := cardmatch.Load("", cardsExplainCards, cardsExplainRules)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(cardsExplainFragment)
		if err != nil {
			return err
		}
		var frag cardmatch.FragmentJSON
		if err := json.Unmarshal(data, &frag); err != nil {
			return fmt.Errorf("%s: %w", cardsExplainFragment, err)
		}
		ex, err := assets.Explain(&frag, cardsExplainRule, file, n)
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(ex, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, string(out))
		return err
	},
}

func init() {
	cardsExplainCmd.Flags().StringVar(&cardsExplainRules, "rules", "", "Rules directory of one language (semgrep-rules/<lang>)")
	cardsExplainCmd.Flags().StringVar(&cardsExplainCards, "cards", "", "Cards directory of the same language (optional)")
	cardsExplainCmd.Flags().StringVar(&cardsExplainFragment, "fragment", "", "Graph fragment JSON (scan --export-graph-fragment)")
	cardsExplainCmd.Flags().StringVar(&cardsExplainRule, "rule", "", "Rule id")
	cardsExplainCmd.Flags().StringVar(&cardsExplainAt, "at", "", "Source line, <file>:<line> as the fragment names the file")
	for _, f := range []string{"rules", "fragment", "rule", "at"} {
		utils.Discard(cardsExplainCmd.MarkFlagRequired(f))
	}
	cardsCmd.AddCommand(cardsExplainCmd)
}

func init() {
	cardsExportCmd.Flags().StringVar(&cardsExportRules, "rules", "", "Rules directory of one language (semgrep-rules/<lang>)")
	cardsExportCmd.Flags().StringVar(&cardsExportLang, "lang", "", "Language of the rules ("+cardsDevLanguageNames()+")")
	cardsExportCmd.Flags().StringVarP(&cardsExportOutput, "output", "o", "", "Output file (default: stdout)")
	utils.Discard(cardsExportCmd.MarkFlagRequired("rules"))
	utils.Discard(cardsExportCmd.MarkFlagRequired("lang"))
	rootCmd.AddCommand(cardsExportCmd)
}
