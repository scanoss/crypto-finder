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
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/skip"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
)

// cardsRuleset gives the cards scanner the scan's ruleset directory: the
// --rules-dir directories as given (the local source expands them into rule
// files), or what the rules source loads otherwise, which for a leased
// ruleset is its run directory.
func cardsRuleset(ruleDirs []string, manager *rules.Manager) func() ([]string, error) {
	return func() ([]string, error) {
		if len(ruleDirs) > 0 {
			return ruleDirs, nil
		}
		return manager.Load()
	}
}

// cardsFragmentBuilder gives the cards scanner the call sites of the scanned
// directory. It builds that directory's own call graph of ecosystem (java or
// python), typed by the scan's type-only JARs or packages, the way a scan that exports a graph fragment does,
// and projects it with no findings. The graph is kept in graphs, so the
// export and the dependency phase reuse it instead of building it again.
func cardsFragmentBuilder(graphs *graphStore, target, ecosystem string, javaRuntime func() (javaruntime.Config, error), includeTests bool, compiledArtifact string, skipMatcher skip.SkipMatcher) cards.BuildFragment {
	return func(dir string) (graphfrag.GraphFragmentExport, error) {
		var runtime javaruntime.Config
		if ecosystem == ecosystemJava {
			var err error
			if runtime, err = javaRuntime(); err != nil {
				return graphfrag.GraphFragmentExport{}, err
			}
		}
		artifact := ""
		if dir == target {
			artifact = compiledArtifact
		}
		empty := &entities.InterimReport{}
		result, err := buildStandaloneCallGraphResultForEcosystem(graphs, dir, empty, ecosystem, runtime, includeTests, artifact, skipMatcher, true)
		if err != nil {
			return graphfrag.GraphFragmentExport{}, err
		}
		resolved, err := prepareScanOIDProjection(empty, false)
		if err != nil {
			return graphfrag.GraphFragmentExport{}, err
		}
		return scanutil.BuildGraphFragmentExport(result, resolved), nil
	}
}

// graphStore keeps the typed call graph one scan built for its target, so the
// cards detector and the graph export share a single build: the detector
// builds it before detection (it reads the call sites from it), and the export
// takes it instead of parsing the target a second time. Graphs of other
// directories (a dependency's sources in a dependency scan) are not kept.
//
// It also carries the scan's type-only JARs (--type-jars, and the closure's
// compiled JARs in a dependency scan), the types every graph of the scan is
// built with. A nil store keeps nothing and has no type-only JARs.
type graphStore struct {
	mu       sync.Mutex
	target   string
	typeJARs string
	// typePackages are the scan's Python type-only packages
	// (--type-packages), an OS path list.
	typePackages string
	results      map[string]*engine.DepScanResult
	// javaPlatformWarned records that the scan already warned that its
	// JDK gave no Java platform signatures, so it warns once.
	javaPlatformWarned bool
}

// newGraphStore returns the store of one scan of target, whose graphs are
// typed by typeJARs (an OS path list).
func newGraphStore(target, typeJARs string) *graphStore {
	return &graphStore{target: cleanAbs(target), typeJARs: typeJARs, results: make(map[string]*engine.DepScanResult)}
}

// typeJARList is the scan's type-only JARs as an OS path list.
func (s *graphStore) typeJARList() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.typeJARs
}

// typePackageList is the scan's Python type-only packages as an OS path list.
func (s *graphStore) typePackageList() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.typePackages
}

// addTypeJARs appends jars to the scan's type-only JARs.
func (s *graphStore) addTypeJARs(jars []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := jars
	if strings.TrimSpace(s.typeJARs) != "" {
		list = append([]string{s.typeJARs}, jars...)
	}
	s.typeJARs = strings.Join(list, string(os.PathListSeparator))
}

func cleanAbs(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Clean(dir)
}

// load returns the stored graph of dir, with report attached.
func (s *graphStore) load(dir, ecosystem string, report *entities.InterimReport) (*engine.DepScanResult, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	stored, ok := s.results[ecosystem+"\x00"+cleanAbs(dir)]
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	result := *stored
	result.Report = report
	return &result, true
}

// firstJavaPlatformWarning reports whether the scan has not yet warned that
// Java platform signatures are unavailable, and records that it now has. A
// nil store has no memory, so it always reports true.
func (s *graphStore) firstJavaPlatformWarning() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.javaPlatformWarned {
		return false
	}
	s.javaPlatformWarned = true
	return true
}

// keep stores result when dir is the scan target.
func (s *graphStore) keep(dir, ecosystem string, result *engine.DepScanResult) {
	if s == nil || cleanAbs(dir) != s.target {
		return
	}
	s.mu.Lock()
	s.results[ecosystem+"\x00"+cleanAbs(dir)] = result
	s.mu.Unlock()
}
