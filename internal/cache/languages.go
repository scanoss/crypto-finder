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

package cache

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/config"
)

// genericLanguage stands for a rule that names no language.
const genericLanguage = "generic"

// languageSet collects the languages the rules of a ruleset cover: every
// rule's languages, lowercased and trimmed, with "generic" for a rule that
// names none.
type languageSet map[string]struct{}

// addRuleFile adds the languages of the rules in one rule file.
func (s languageSet) addRuleFile(name string, data []byte) error {
	var doc struct {
		Rules []struct {
			Languages []string `yaml:"languages"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("rule file %s: %w", name, err)
	}
	for _, rule := range doc.Rules {
		languages := rule.Languages
		if len(languages) == 0 {
			languages = []string{genericLanguage}
		}
		for _, l := range languages {
			s[strings.ToLower(strings.TrimSpace(l))] = struct{}{}
		}
	}
	return nil
}

// addCardsFile adds the language of a v3 card file, the directory below
// cards/ in its path, when the file holds rules.
func (s languageSet) addCardsFile(name string, data []byte) error {
	var doc struct {
		Rules map[string]yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("card file %s: %w", name, err)
	}
	if language := config.CardsLanguage(name); language != "" && len(doc.Rules) > 0 {
		s[language] = struct{}{}
	}
	return nil
}

// sorted returns the languages in ascending order, nil when there are none.
func (s languageSet) sorted() []string {
	if len(s) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(s))
}

// isRuleFile reports whether name is a rule file or a v3 card file by its
// extension.
func isRuleFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml", cardsFileExt:
		return true
	}
	return false
}

// cardsFileExt is the extension of a v3 card file (rules.CardsFileExt, which
// this package cannot import).
const cardsFileExt = ".cards"

// bundleLanguages returns the languages of the rule and card files in a .tar.gz
// bundle without writing them to disk. It reads the files extractTarball
// would extract.
func bundleLanguages(tarball []byte) ([]string, error) {
	gzr, err := gzip.NewReader(newBytesReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			log.Debug().Err(err).Msg("Failed to close gzip reader")
		}
	}()

	const maxFileSize = 100 * 1024 * 1024 // as in extractTarball
	files := map[string][]byte{}
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read bundle: %w", err)
		}
		name := filepath.Clean(header.Name)
		base := filepath.Base(name)
		if header.Typeflag != tar.TypeReg || strings.HasPrefix(name, "..") ||
			strings.HasPrefix(base, "._") || !isRuleFile(name) ||
			slices.Contains(strings.Split(filepath.ToSlash(name), "/"), config.FilteredRulesDirName) {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileSize))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		files[name] = data // a later entry for the same path replaces it, as on extraction
	}
	set := languageSet{}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		add := set.addRuleFile
		if strings.EqualFold(filepath.Ext(name), cardsFileExt) {
			add = set.addCardsFile
		}
		if err := add(name, files[name]); err != nil {
			return nil, err
		}
	}
	return set.sorted(), nil
}

// recordLanguages returns the languages for a ruleset's metadata. A ruleset
// whose rule files cannot be read is still stored, without languages.
func recordLanguages(name, version string, languages func() ([]string, error)) []string {
	list, err := languages()
	if err != nil {
		log.Warn().Err(err).Str("ruleset", name).Str("version", version).Msg("Failed to read the languages of the ruleset; its metadata will not list them")
		return nil
	}
	return list
}
