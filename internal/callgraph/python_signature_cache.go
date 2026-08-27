// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
)

const (
	pythonSignatureCacheDirName = "python-signatures"
	// pythonSignatureCacheSchemaVersion gates cache-entry compatibility
	// (row 14, python-parser-parity-2): bump this whenever
	// pythonSignature's or CachedPythonSignatureIndex's shape changes so a
	// stale on-disk entry is treated as a miss instead of being
	// misinterpreted.
	pythonSignatureCacheSchemaVersion = 1
)

var pythonSignatureCacheFilenameUnsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// pythonSignature holds one indexed function/method's declared signature
// (row 14, python-parser-parity-2 design.md §4 row 14): the owning
// FunctionID plus the return annotation and, where present, per-parameter
// annotations — both already normalized via pythonNormalizeAnnotation (row
// 13).
type pythonSignature struct {
	ID         FunctionID `json:"id"`
	ParamTypes []string   `json:"param_types,omitempty"`
	ReturnType string     `json:"return_type,omitempty"`
}

// PythonSignatureIndexCache stores per-distribution Python signature
// indexes (row 14, python-parser-parity-2), mirroring BytecodeIndexCache's
// shape for the Java bytecode resolver. Implementations can back this with
// disk, memory, Redis, S3, etc.
type PythonSignatureIndexCache interface {
	Get(ctx context.Context, key string) (*CachedPythonSignatureIndex, bool, error)
	Put(ctx context.Context, key string, value *CachedPythonSignatureIndex) error
}

// CachedPythonSignatureIndex stores the derived signature index for a
// single pip-resolved distribution: every indexed function/method
// signature, keyed by its FullName, plus the class hierarchy discovered in
// the same pass (class FullName -> its declared base-class names, verbatim
// as written in source — Python class bases are bare names, never
// import-qualified by this resolver, matching row 9's OwnerBases
// convention).
type CachedPythonSignatureIndex struct {
	SchemaVersion   int                        `json:"schema_version"`
	DistributionKey string                     `json:"distribution_key"`
	Signatures      map[string]pythonSignature `json:"signatures"`
	Hierarchy       map[string][]string        `json:"hierarchy"`
}

// DiskPythonSignatureIndexCache implements PythonSignatureIndexCache using
// local JSON files, mirroring DiskBytecodeIndexCache's on-disk shape and
// atomic-write discipline (temp file + rename).
type DiskPythonSignatureIndexCache struct {
	dir string
}

// NewDiskPythonSignatureIndexCache creates a signature cache under
// ~/.scanoss/crypto-finder/cache/python-signatures/. The directory itself
// is created LAZILY, on first Put — see NewDiskPythonSignatureIndexCacheWithDir.
func NewDiskPythonSignatureIndexCache() (*DiskPythonSignatureIndexCache, error) {
	cacheDir, err := config.GetCacheDir()
	if err != nil {
		return nil, fmt.Errorf("callgraph: python signature cache: get cache dir: %w", err)
	}
	return NewDiskPythonSignatureIndexCacheWithDir(filepath.Join(cacheDir, pythonSignatureCacheDirName))
}

// NewDiskPythonSignatureIndexCacheWithDir creates a signature cache at a
// custom directory. Useful for testing. The directory is NOT created here
// (G13, PR #310 phase-2 review): every scan wires this cache regardless of
// --scan-dependencies, so eagerly creating the directory at construction
// time left an empty cache directory on disk even for a scan that never
// indexes a single dependency. The directory is created lazily, only when
// Put actually persists a real indexed distribution.
func NewDiskPythonSignatureIndexCacheWithDir(dir string) (*DiskPythonSignatureIndexCache, error) {
	return &DiskPythonSignatureIndexCache{dir: dir}, nil
}

// Get loads a cached signature index entry by key. A missing, corrupted, or
// schema-mismatched file is reported as a plain miss (ok == false, err ==
// nil) — cache corruption degrades to a re-index, never a fatal error. A
// missing cache DIRECTORY (never yet created — see
// NewDiskPythonSignatureIndexCacheWithDir) is indistinguishable from a
// missing entry and also reported as a plain miss.
func (c *DiskPythonSignatureIndexCache) Get(_ context.Context, key string) (*CachedPythonSignatureIndex, bool, error) {
	path := filepath.Join(c.dir, pythonSignatureCacheKeyToFilename(key))
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("callgraph: python signature cache: read cache file: %w", err)
	}

	var entry CachedPythonSignatureIndex
	if err := json.Unmarshal(data, &entry); err != nil {
		// Corrupted entry: best-effort remove so a future Get does not keep
		// re-reading the same unparsable bytes; a removal failure is not
		// itself fatal — it just leaves the corrupted file for next time.
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			log.Debug().Err(removeErr).Str("path", path).Msg("Failed to remove corrupted Python signature cache file")
		}
		return nil, false, nil
	}
	if entry.SchemaVersion != pythonSignatureCacheSchemaVersion {
		return nil, false, nil
	}
	return &entry, true, nil
}

// Put stores a cached signature index entry by key, via a temp-file +
// rename write for crash-safety (mirrors DiskBytecodeIndexCache.Put).
// Creates the cache directory lazily, on this — its first real write (G13,
// PR #310 phase-2 review): NewDiskPythonSignatureIndexCacheWithDir no
// longer creates it eagerly.
func (c *DiskPythonSignatureIndexCache) Put(_ context.Context, key string, value *CachedPythonSignatureIndex) (err error) {
	if mkErr := os.MkdirAll(c.dir, 0o750); mkErr != nil {
		return fmt.Errorf("callgraph: python signature cache: create cache dir: %w", mkErr)
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("callgraph: python signature cache: marshal index: %w", err)
	}

	filename := pythonSignatureCacheKeyToFilename(key)
	path := filepath.Join(c.dir, filename)
	tmpFile, err := os.CreateTemp(c.dir, filename+".tmp-*")
	if err != nil {
		return fmt.Errorf("callgraph: python signature cache: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if tmpPath == "" {
			return
		}
		if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("callgraph: python signature cache: cleanup temp cache file %s: %w", tmpPath, removeErr))
		}
	}()

	if _, writeErr := tmpFile.Write(data); writeErr != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			return fmt.Errorf("callgraph: python signature cache: write cache file: %w", errors.Join(writeErr, closeErr))
		}
		return fmt.Errorf("callgraph: python signature cache: write cache file: %w", writeErr)
	}
	if closeErr := tmpFile.Close(); closeErr != nil {
		return fmt.Errorf("callgraph: python signature cache: close cache file: %w", closeErr)
	}
	// #nosec G703 -- tmpPath is created by os.CreateTemp and path is derived from a sanitized cache filename.
	if renameErr := os.Rename(tmpPath, path); renameErr != nil {
		return fmt.Errorf("callgraph: python signature cache: rename cache file: %w", renameErr)
	}
	tmpPath = ""
	return nil
}

func pythonSignatureCacheKeyToFilename(key string) string {
	return pythonSignatureCacheFilenameUnsafeChars.ReplaceAllString(key, "_") + ".json"
}

// pythonSignatureDistributionKey builds the cache key for a distribution
// (row 14 algorithm step 2, design.md): sanitize(ImportPath) + "@" +
// Version + schema version, so a schema bump naturally invalidates every
// prior entry without a separate migration path.
func pythonSignatureDistributionKey(root PackageDir) string {
	return fmt.Sprintf("%s@%s:v%d", root.ImportPath, root.Version, pythonSignatureCacheSchemaVersion)
}
