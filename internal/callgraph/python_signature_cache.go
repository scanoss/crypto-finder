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

package callgraph

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
	pythonSignatureCacheSchemaVersion = 2
)

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
	SchemaVersion     int                        `json:"schema_version"`
	DistributionKey   string                     `json:"distribution_key"`
	DistributionName  string                     `json:"distribution_name"`
	ImportPath        string                     `json:"import_path"`
	SourceFingerprint string                     `json:"source_fingerprint"`
	Signatures        map[string]pythonSignature `json:"signatures"`
	Hierarchy         map[string][]string        `json:"hierarchy"`
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
	if entry.SchemaVersion != pythonSignatureCacheSchemaVersion || entry.DistributionKey != key {
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
	digest := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x.json", digest)
}

type pythonSignatureDistributionIdentity struct {
	distributionName  string
	importPath        string
	sourceFingerprint string
}

func pythonSignatureIdentity(root PackageDir) pythonSignatureDistributionIdentity {
	distributionName := root.DistributionName
	if distributionName == "" {
		distributionName = root.ImportPath
	}
	return pythonSignatureDistributionIdentity{
		distributionName:  distributionName,
		importPath:        root.ImportPath,
		sourceFingerprint: pythonSignatureSourceFingerprint(root.Dir),
	}
}

// pythonSignatureDistributionKey binds a cached index to the package
// coordinate, the distinct Python import namespace, the version, the selected
// source tree's deterministic content fingerprint, and the cache schema.
func pythonSignatureDistributionKey(root PackageDir) string {
	return pythonSignatureDistributionKeyForIdentity(root, pythonSignatureIdentity(root))
}

func pythonSignatureDistributionKeyForIdentity(root PackageDir, identity pythonSignatureDistributionIdentity) string {
	return fmt.Sprintf("%s@%s:import=%s:source=%s:v%d",
		identity.distributionName,
		root.Version,
		identity.importPath,
		identity.sourceFingerprint,
		pythonSignatureCacheSchemaVersion,
	)
}

// pythonSignatureSourceFingerprint hashes every eligible Python source/stub
// input by normalized relative path and bytes. WalkDir is lexical, so the
// result is deterministic and independent of the distribution's absolute
// installation path. Unreadable or oversized inputs degrade by omission.
func pythonSignatureSourceFingerprint(root string) string {
	digest := sha256.New()
	if err := filepath.WalkDir(root, pythonSignatureFingerprintVisitor(root, digest)); err != nil {
		log.Debug().Err(err).Str("root", root).Msg("Failed to walk Python signature source tree")
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func pythonSignatureFingerprintVisitor(root string, digest hash.Hash) fs.WalkDirFunc {
	return func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return pythonSignatureFingerprintWalkFailure(entry)
		}
		if entry == nil {
			return nil
		}
		if entry.IsDir() {
			return pythonSignatureFingerprintDir(root, path, entry)
		}
		if !pythonSignatureFingerprintEligibleFile(entry) {
			return nil
		}
		data, rel, ok := pythonSignatureFingerprintInput(root, path, entry)
		if !ok {
			return nil
		}
		pythonSignatureFingerprintWrite(digest, rel, data)
		return nil
	}
}

func pythonSignatureFingerprintWalkFailure(entry fs.DirEntry) error {
	if entry != nil && entry.IsDir() {
		return fs.SkipDir
	}
	return nil
}

func pythonSignatureFingerprintDir(root, path string, entry fs.DirEntry) error {
	if path != root && (strings.HasPrefix(entry.Name(), ".") || pythonDependencySkipMatcher.ShouldSkip(filepath.ToSlash(path), true)) {
		return fs.SkipDir
	}
	return nil
}

func pythonSignatureFingerprintEligibleFile(entry fs.DirEntry) bool {
	if entry.Type()&fs.ModeSymlink != 0 {
		return false
	}
	name := entry.Name()
	ext := filepath.Ext(name)
	if ext != pythonSourceExt && ext != pythonStubExt {
		return false
	}
	return !strings.HasPrefix(name, "test_") &&
		!strings.HasSuffix(name, "_test.py") &&
		!strings.HasSuffix(name, "_test.pyi")
}

func pythonSignatureFingerprintInput(root, path string, entry fs.DirEntry) ([]byte, string, bool) {
	info, err := entry.Info()
	if err != nil || info.Size() > maxPythonDependencyFileBytes {
		return nil, "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, "", false
	}
	return data, filepath.ToSlash(rel), true
}

func pythonSignatureFingerprintWrite(digest hash.Hash, rel string, data []byte) {
	prefix := fmt.Sprintf("%s\x00%d\x00", rel, len(data))
	if _, err := digest.Write([]byte(prefix)); err != nil {
		log.Debug().Err(err).Str("path", rel).Msg("Failed to hash Python signature source path")
		return
	}
	if _, err := digest.Write(data); err != nil {
		log.Debug().Err(err).Str("path", rel).Msg("Failed to hash Python signature source bytes")
	}
}
