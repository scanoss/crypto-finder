// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package offline

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/utils"
)

// Cache is the local content-addressed store of mined dependencies, the
// offline counterpart of the SCANOSS API's results database. A dependency's
// structural graph is stored under its graph key: what the graph is built
// from (the package and version, the sources JAR's content, the content of
// every type-only JAR of its closure) and how (the graph algorithm and the
// fragment schema). Its annotation and findings report are stored under that
// graph and the ruleset's key, so a new ruleset finds the graph and
// re-annotates it without the sources.
//
//	<dir>/<graph key>/graph.json.gz                     structural graph
//	<dir>/<graph key>/meta.json                         what it is (GraphMeta)
//	<dir>/<graph key>/rules-<ruleset key>/annotation.json.gz
//	<dir>/<graph key>/rules-<ruleset key>/findings.json.gz
//
// Entries are written to a temporary file and renamed, so a reader never
// sees a partial one and two runs mining the same dependency do not
// conflict.
type Cache struct {
	dir string
}

// DefaultCacheDir is ~/.scanoss/crypto-finder/cache/mined.
func DefaultCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("offline cache: home directory: %w", err)
	}
	return filepath.Join(home, ".scanoss", "crypto-finder", "cache", "mined"), nil
}

// OpenCache opens (creating) the cache at dir.
func OpenCache(dir string) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("offline cache: %w", err)
	}
	return &Cache{dir: dir}, nil
}

const (
	graphFile      = "graph.json.gz"
	annotationFile = "annotation.json.gz"
	findingsFile   = "findings.json.gz"
)

func (c *Cache) graphPath(graphKey string) string {
	return filepath.Join(c.dir, graphKey, graphFile)
}

func (c *Cache) rulesDir(graphKey, rulesetKey string) string {
	return filepath.Join(c.dir, graphKey, "rules-"+rulesetKey)
}

// Graph returns the cached structural graph of graphKey.
func (c *Cache) Graph(graphKey string) ([]byte, bool) {
	data, err := readGzip(c.graphPath(graphKey))
	return data, err == nil
}

// Annotation returns the cached annotation and findings report of graphKey
// under rulesetKey.
func (c *Cache) Annotation(graphKey, rulesetKey string) (annotation, findings []byte, ok bool) {
	dir := c.rulesDir(graphKey, rulesetKey)
	annotation, err := readGzip(filepath.Join(dir, annotationFile))
	if err != nil {
		return nil, nil, false
	}
	findings, err = readGzip(filepath.Join(dir, findingsFile))
	if err != nil {
		return nil, nil, false
	}
	return annotation, findings, true
}

// GraphMeta says what a cached graph is, for people and tools reading the
// cache; lookups never read it.
type GraphMeta struct {
	Purl     string   `json:"purl"`
	Version  string   `json:"version"`
	Module   string   `json:"module"`
	TypeJARs []string `json:"type_jars,omitempty"`
}

// PutGraph stores a structural graph and what it is.
func (c *Cache) PutGraph(graphKey string, graph []byte, meta GraphMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(c.dir, graphKey, "meta.json"), data); err != nil {
		return err
	}
	return writeGzipAtomic(c.graphPath(graphKey), graph)
}

// PutAnnotation stores an annotation and its findings report. The findings
// report is written last: Annotation reads it as the entry's completion mark.
func (c *Cache) PutAnnotation(graphKey, rulesetKey string, annotation, findings []byte) error {
	dir := c.rulesDir(graphKey, rulesetKey)
	if err := writeGzipAtomic(filepath.Join(dir, annotationFile), annotation); err != nil {
		return err
	}
	return writeGzipAtomic(filepath.Join(dir, findingsFile), findings)
}

func readGzip(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a path inside the cache directory.
	if err != nil {
		return nil, err
	}
	defer func() { utils.Discard(f.Close()) }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func writeGzipAtomic(path string, data []byte) error {
	return writeAtomic(path, func(w io.Writer) error {
		zw := gzip.NewWriter(w)
		_, err := zw.Write(data)
		return errors.Join(err, zw.Close())
	})
}

func writeFileAtomic(path string, data []byte) error {
	return writeAtomic(path, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func writeAtomic(path string, write func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("offline cache: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("offline cache: %w", err)
	}
	defer func() { utils.Discard(os.Remove(tmp.Name())) }()
	werr := write(tmp)
	ferr := tmp.Close()
	if err := errors.Join(werr, ferr); err != nil {
		return fmt.Errorf("offline cache: write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("offline cache: %w", err)
	}
	return nil
}

// GraphKey is the cache key of a dependency's structural graph: what it is
// built from and how. sourcesDigest and typeJARDigests are content digests
// (FileDigest); the type JARs' order is the order they are indexed in.
func GraphKey(purl, version, sourcesDigest string, typeJARDigests []string, graphAlgo, schema string) string {
	h := sha256.New()
	utils.Lenient(fmt.Fprintf(h, "offline-graph-1\npurl=%s\nversion=%s\nsources=%s\nalgo=%s\nschema=%s\n", purl, version, sourcesDigest, graphAlgo, schema))
	for _, d := range typeJARDigests {
		utils.Lenient(fmt.Fprintf(h, "type-jar=%s\n", d))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FileDigest is the SHA-256 of a file's content.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a JAR the resolver named.
	if err != nil {
		return "", err
	}
	defer func() { utils.Discard(f.Close()) }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RulesetKey is the cache key of a ruleset: the content of every file under
// its directories and of each extra file (a card index, say), by path
// relative to its root, plus labels (the ruleset's name and version). The
// per-run copies a ruleset cache keeps beside its versions
// (config.FilteredRulesDirName) are not part of a directory's tree.
func RulesetKey(dirs, files, labels []string) (string, error) { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	h := sha256.New()
	utils.Lenient(fmt.Fprintf(h, "offline-ruleset-1\n"))
	for _, l := range labels {
		utils.Lenient(fmt.Fprintf(h, "label=%s\n", l))
	}
	add := func(name, path string) error {
		data, err := os.ReadFile(path) // #nosec G304 -- a ruleset file.
		if err != nil {
			return err
		}
		utils.Lenient(fmt.Fprintf(h, "file=%s:%d:", name, len(data)))
		_, _ = h.Write(data)
		return nil
	}
	for i, dir := range dirs {
		var paths []string
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && path != dir && d.Name() == config.FilteredRulesDirName {
				return filepath.SkipDir
			}
			if d.Type().IsRegular() {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("offline: hash ruleset %s: %w", dir, err)
		}
		sort.Strings(paths)
		for _, path := range paths {
			rel := utils.Lenient(filepath.Rel(dir, path))
			if err := add(fmt.Sprintf("%d/%s", i, filepath.ToSlash(rel)), path); err != nil {
				return "", err
			}
		}
	}
	for _, f := range files {
		if strings.TrimSpace(f) == "" {
			continue
		}
		if err := add("extra/"+filepath.Base(f), f); err != nil {
			return "", fmt.Errorf("offline: hash %s: %w", f, err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
