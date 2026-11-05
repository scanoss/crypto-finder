package dependency

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gofrs/flock"
	"github.com/rs/zerolog/log"
)

const maxExtractedFileSize = 100 << 20 // 100 MiB per file.

// SourceCache manages extraction and caching of source archives (JARs, wheels, etc.).
type SourceCache struct {
	baseDir string
}

func sanitizeSourceCacheKey(key string) string {
	return strings.ReplaceAll(key, ":", "-")
}

// SourceCacheDir is the directory the source cache extracts dependency
// sources into, one directory per coordinate and version:
// ~/.scanoss/crypto-finder/cache/sources.
func SourceCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".scanoss", "crypto-finder", "cache", "sources"), nil
}

// NewSourceCache creates a new source cache in SourceCacheDir.
func NewSourceCache() (*SourceCache, error) {
	baseDir, err := SourceCacheDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		return nil, fmt.Errorf("cannot create source cache dir: %w", err)
	}
	return &SourceCache{baseDir: baseDir}, nil
}

// CachedDir returns the cached directory for a dependency, or "" if not cached.
func (c *SourceCache) CachedDir(key, version string) string {
	dir := filepath.Join(c.baseDir, sanitizeSourceCacheKey(key), version)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir
	}
	return ""
}

// ExtractZip extracts a ZIP/JAR archive to a cache directory, keeping only files
// matching the given extensions (e.g., []string{".java"}). If extensions is empty,
// all files are extracted.
// Returns the extracted directory path, or error.
//
// The directory is reused while it holds what the archive holds; a rebuilt
// archive at the same version (a Maven SNAPSHOT, a module reinstalled with
// mvn install) is extracted again. An extraction runs in a directory of its
// own and is moved into place only when complete, so neither a scan running
// beside it nor one after an interrupted extraction reads a partial entry.
// When the archive cannot be read, an entry already extracted is returned.
func (c *SourceCache) ExtractZip(archivePath, key, version string, extensions []string) (string, error) {
	keyDir := filepath.Join(c.baseDir, sanitizeSourceCacheKey(key))
	destDir := filepath.Join(keyDir, version)
	stampPath := filepath.Join(keyDir, "."+version+".stamp")

	r, err := zip.OpenReader(archivePath)
	if err != nil {
		if isDir(destDir) {
			return destDir, nil
		}
		return "", fmt.Errorf("open archive %s: %w", archivePath, err)
	}
	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Str("archive", archivePath).Msg("Failed to close archive reader")
		}
	}()

	stamp := archiveStamp(r.File, extensions)
	if entryHolds(destDir, stampPath, stamp) {
		return destDir, nil
	}

	if err := os.MkdirAll(keyDir, 0o750); err != nil {
		return "", fmt.Errorf("create extraction dir: %w", err)
	}
	// One extraction of an entry at a time, across processes: the next one
	// finds the entry complete.
	lock := flock.New(filepath.Join(keyDir, "."+version+".lock"))
	if err := lock.Lock(); err != nil {
		return "", fmt.Errorf("lock cached sources %s: %w", destDir, err)
	}
	defer func() {
		if unlockErr := lock.Unlock(); unlockErr != nil {
			log.Debug().Err(unlockErr).Str("path", lock.Path()).Msg("Failed to unlock source cache entry")
		}
	}()
	if entryHolds(destDir, stampPath, stamp) {
		return destDir, nil
	}

	tmpDir, err := os.MkdirTemp(keyDir, "."+version+".partial-*")
	if err != nil {
		return "", fmt.Errorf("create extraction dir: %w", err)
	}
	defer removeBestEffort(tmpDir)

	for _, f := range r.File {
		if !keptEntry(f.Name, extensions) {
			continue
		}

		// #nosec G305 -- validated against zip slip with a canonical prefix check below.
		destPath := filepath.Join(tmpDir, f.Name)

		// Prevent zip slip
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(tmpDir)+string(os.PathSeparator)) {
			continue
		}

		if err := extractZipFile(f, destPath); err != nil {
			// Non-fatal — skip individual files that fail
			continue
		}
	}

	if err := publishEntry(tmpDir, destDir, keyDir, version); err != nil {
		return "", err
	}
	if err := writeStamp(stampPath, stamp, keyDir, version); err != nil {
		return "", err
	}
	return destDir, nil
}

// keptEntry reports whether an archive entry is extracted for extensions.
func keptEntry(name string, extensions []string) bool {
	return len(extensions) == 0 || hasMatchingExtension(name, extensions)
}

// archiveStamp identifies the files an extraction for extensions takes from
// an archive by their names, CRC-32 checksums and sizes, read from the
// archive's directory. A rebuilt archive holding the same sources has the
// same stamp.
func archiveStamp(files []*zip.File, extensions []string) string {
	lines := make([]string, 0, len(files)+1)
	for _, f := range files {
		if keptEntry(f.Name, extensions) {
			lines = append(lines, fmt.Sprintf("%q %08x %d", f.Name, f.CRC32, f.UncompressedSize64))
		}
	}
	sort.Strings(lines)
	lines = append(lines, fmt.Sprintf("extensions %q", extensions))
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// entryHolds reports whether destDir is an entry extracted from an archive
// of the given stamp.
func entryHolds(destDir, stampPath, stamp string) bool {
	current, err := os.ReadFile(stampPath) // #nosec G304 -- a file of the source cache.
	return err == nil && string(current) == stamp && isDir(destDir)
}

// publishEntry moves the complete extraction tmpDir to destDir, replacing
// an entry already there: a stale one, or one an interrupted extraction
// left before extractions were published whole.
func publishEntry(tmpDir, destDir, keyDir, version string) error {
	if err := os.Rename(tmpDir, destDir); err == nil {
		return nil
	}
	oldDir, err := os.MkdirTemp(keyDir, "."+version+".old-*")
	if err != nil {
		return fmt.Errorf("replace cached sources %s: %w", destDir, err)
	}
	defer removeBestEffort(oldDir)
	if err := os.Rename(destDir, filepath.Join(oldDir, "entry")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("replace cached sources %s: %w", destDir, err)
	}
	if err := os.Rename(tmpDir, destDir); err != nil {
		return fmt.Errorf("publish cached sources %s: %w", destDir, err)
	}
	return nil
}

// writeStamp records stamp at stampPath in one rename.
func writeStamp(stampPath, stamp, keyDir, version string) error {
	tmp, err := os.CreateTemp(keyDir, "."+version+".stamp-*")
	if err != nil {
		return fmt.Errorf("write source cache stamp: %w", err)
	}
	_, writeErr := tmp.WriteString(stamp)
	if err := errors.Join(writeErr, tmp.Close()); err != nil {
		removeBestEffort(tmp.Name())
		return fmt.Errorf("write source cache stamp: %w", err)
	}
	if err := os.Rename(tmp.Name(), stampPath); err != nil {
		removeBestEffort(tmp.Name())
		return fmt.Errorf("write source cache stamp: %w", err)
	}
	return nil
}

// removeBestEffort removes path, logging a failure.
func removeBestEffort(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.Debug().Err(err).Str("path", path).Msg("Failed to remove source cache temp path")
	}
}

// hasMatchingExtension checks if a filename ends with any of the given extensions.
func hasMatchingExtension(name string, extensions []string) bool {
	for _, ext := range extensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func extractZipFile(f *zip.File, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}

	out, err := os.Create(destPath)
	if err != nil {
		if closeErr := rc.Close(); closeErr != nil {
			return fmt.Errorf("open zip file failed and close reader failed: %w", closeErr)
		}
		return err
	}

	limit := int64(maxExtractedFileSize) + 1
	written, copyErr := io.CopyN(out, rc, limit)
	closeOutErr := out.Close()
	closeReaderErr := rc.Close()
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		return copyErr
	}
	if written > int64(maxExtractedFileSize) {
		return fmt.Errorf("extracted file exceeds size limit: %s (%d bytes)", f.Name, written)
	}
	if closeOutErr != nil {
		return closeOutErr
	}
	if closeReaderErr != nil {
		return closeReaderErr
	}

	return nil
}
