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

package rules

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/utils"
)

// CardsFormat is the format key of a v3 card file: a card file that carries
// its rules (id, severity, message, purl, metadata.crypto) in a rules: block
// beside its cards, so a ruleset of card files needs no rule YAML.
const CardsFormat = "scanoss-cards/3"

// CardsFileExt is the extension of a card file.
const CardsFileExt = ".cards"

// IsCardsFile reports whether path names a card file.
func IsCardsFile(path string) bool {
	return strings.EqualFold(filepath.Ext(path), CardsFileExt)
}

// CardFilesUnder returns the card files under dir, sorted, leaving out hidden
// entries and materialized filtered-rules directories. A ruleset whose rules
// are all card files has no rule YAML: its rule files are these.
func CardFilesUnder(dir string) []string {
	var files []string
	utils.Discard(filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries, keep walking
		}
		if path != dir && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if d.Name() == config.FilteredRulesDirName {
				return filepath.SkipDir
			}
			return nil
		}
		if IsCardsFile(path) {
			files = append(files, path)
		}
		return nil
	}))
	sort.Strings(files)
	return files
}

// CardsRule is one entry of a v3 card file's rules: block.
type CardsRule struct {
	ID       string
	Severity string
	Message  string
	PURL     string
	// Crypto is the rule's metadata.crypto, decoded as a rule file's.
	Crypto map[string]any
	// Conditioned is present for a rule with a parameterCondition.
	Conditioned *CardsConditioned
	// Pending says why no card detects the rule yet.
	Pending string
}

// CardsConditioned is what the conditioned-rule catalog reads from a rule:
// the callee keys it is indexed under, and its capture names and binders.
type CardsConditioned struct {
	Symbols        []string `yaml:"symbols"`
	CaptureNames   []string `yaml:"capture_names"`
	CaptureBinders []string `yaml:"capture_binders"`
}

type cardsRuleYAML struct {
	Severity    string            `yaml:"severity"`
	Message     string            `yaml:"message"`
	PURL        string            `yaml:"purl"`
	Crypto      map[string]any    `yaml:"crypto"`
	Conditioned *CardsConditioned `yaml:"conditioned"`
	Pending     string            `yaml:"pending"`
}

// ErrNotV3Cards is returned for a card file without the v3 format key.
var ErrNotV3Cards = errors.New("not a " + CardsFormat + " card file")

type cardsParse struct {
	rules []CardsRule
	err   error
}

// cardsParsed holds every card file parsed in this process, by content. A scan
// reads the same card files in several passes (rule filter, parameter
// condition validation, crypto metadata, entry-point synthesis); parsing YAML
// once per file instead of once per pass is most of a small scan's time.
var cardsParsed sync.Map

// ReadCardsRules returns the rules of a v3 card file in document order. The
// result is shared by every caller that reads the same content: callers must
// not modify it.
func ReadCardsRules(data []byte) ([]CardsRule, error) {
	return readCardsRulesKeyed(sha256.Sum256(data), data)
}

func readCardsRulesKeyed(key [sha256.Size]byte, data []byte) ([]CardsRule, error) {
	if v, ok := cardsParsed.Load(key); ok {
		if p, ok := v.(cardsParse); ok {
			return p.rules, p.err
		}
	}
	if found, ok := memoCardsRules(key); ok {
		cardsParsed.Store(key, cardsParse{rules: found})
		return found, nil
	}
	found, err := readCardsRules(data)
	cardsParsed.Store(key, cardsParse{rules: found, err: err})
	if err == nil {
		storeCardsRules(key, found)
	}
	return found, err
}

func readCardsRules(data []byte) ([]CardsRule, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, ErrNotV3Cards
	}
	root := doc.Content[0]
	var format string
	var rulesNode *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case "format":
			format = root.Content[i+1].Value
		case "rules":
			rulesNode = root.Content[i+1]
		}
	}
	if format != CardsFormat {
		if format == "" {
			return nil, ErrNotV3Cards
		}
		return nil, fmt.Errorf("card format %q, want %q", format, CardsFormat)
	}
	if rulesNode == nil {
		return nil, nil
	}
	if rulesNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("rules: is not a mapping")
	}
	out := make([]CardsRule, 0, len(rulesNode.Content)/2)
	for i := 0; i+1 < len(rulesNode.Content); i += 2 {
		var r cardsRuleYAML
		if err := rulesNode.Content[i+1].Decode(&r); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rulesNode.Content[i].Value, err)
		}
		out = append(out, CardsRule{
			ID: rulesNode.Content[i].Value, Severity: r.Severity, Message: r.Message, PURL: r.PURL,
			Crypto: r.Crypto, Conditioned: r.Conditioned, Pending: r.Pending,
		})
	}
	return out, nil
}

// ReadCardsRulesFile is ReadCardsRules of the file at path.
func ReadCardsRulesFile(path string) ([]CardsRule, error) {
	found, readErr, err := cardsRulesAt(path)
	if readErr != nil {
		return nil, readErr
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return found, nil
}

// cardsFileRead is a card file as this process last read it.
type cardsFileRead struct {
	size    int64
	modTime time.Time
	key     [sha256.Size]byte
}

// cardsFilesRead holds, by path, the card files this process read. Each pass
// over the ruleset reads every card file; a pass after the first reads only
// the files whose size or modification time changed since.
var cardsFilesRead sync.Map

// unchangedCardsFile is the parse of the file at path when this process read
// it already and its size and modification time are still info's.
func unchangedCardsFile(path string, info os.FileInfo) (cardsParse, bool) {
	v, ok := cardsFilesRead.Load(path)
	if !ok {
		return cardsParse{}, false
	}
	seen, ok := v.(cardsFileRead)
	if !ok || seen.size != info.Size() || !seen.modTime.Equal(info.ModTime()) {
		return cardsParse{}, false
	}
	v, ok = cardsParsed.Load(seen.key)
	if !ok {
		return cardsParse{}, false
	}
	p, ok := v.(cardsParse)
	return p, ok
}

// cardsRulesAt is ReadCardsRules of the file at path, with the error reading
// the file apart from the error parsing it.
func cardsRulesAt(path string) (found []CardsRule, readErr, parseErr error) {
	info, statErr := os.Stat(path)
	if statErr == nil {
		if p, ok := unchangedCardsFile(path, info); ok {
			return p.rules, nil, p.err
		}
	}
	data, err := os.ReadFile(path) // #nosec G304 -- a card file of the ruleset the user named.
	if err != nil {
		return nil, err, nil
	}
	key := sha256.Sum256(data)
	if statErr == nil {
		cardsFilesRead.Store(path, cardsFileRead{size: info.Size(), modTime: info.ModTime(), key: key})
	}
	found, err = readCardsRulesKeyed(key, data)
	return found, nil, err
}
