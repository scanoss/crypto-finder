package dependency

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
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

	planned := plannedFiles(r.File, extensions)
	stamp := archiveStamp(planned, extensions)
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
	// An entry without the archive's stamp that already holds exactly the
	// archive's files (one extracted before entries had stamps) is kept, not
	// replaced under a scan that may be reading it.
	if entryMatches(destDir, planned) {
		if err := writeStamp(stampPath, stamp, keyDir, version); err != nil {
			return "", err
		}
		return destDir, nil
	}

	if err := extractEntry(archivePath, planned, destDir, keyDir, version); err != nil {
		return "", err
	}
	if err := writeStamp(stampPath, stamp, keyDir, version); err != nil {
		return "", err
	}
	return destDir, nil
}

// extractEntry writes the planned files of archivePath to a directory of
// its own and moves it to destDir when complete. A file that cannot be
// written (a full disk) fails the extraction: the entry in place and its
// stamp stay as they were.
func extractEntry(archivePath string, planned []plannedFile, destDir, keyDir, version string) error {
	tmpDir, err := os.MkdirTemp(keyDir, "."+version+".partial-*")
	if err != nil {
		return fmt.Errorf("create extraction dir: %w", err)
	}
	defer removeBestEffort(tmpDir)

	for _, p := range planned {
		if err := extractZipFile(p.file, filepath.Join(tmpDir, p.rel)); err != nil {
			return fmt.Errorf("extract %s from %s: %w", p.file.Name, archivePath, err)
		}
	}
	return publishEntry(tmpDir, destDir, keyDir, version)
}

// plannedFile is an archive file an extraction writes, at rel below the
// entry.
type plannedFile struct {
	file *zip.File
	rel  string
}

// plannedFiles returns the archive files an extraction for extensions
// writes: regular files of a matching name that stay below the entry (no
// zip slip) and are within the size limit.
func plannedFiles(files []*zip.File, extensions []string) []plannedFile {
	var planned []plannedFile
	for _, f := range files {
		rel := filepath.FromSlash(f.Name)
		if f.FileInfo().IsDir() || !filepath.IsLocal(rel) || f.UncompressedSize64 > maxExtractedFileSize {
			continue
		}
		if len(extensions) > 0 && !hasMatchingExtension(f.Name, extensions) {
			continue
		}
		planned = append(planned, plannedFile{file: f, rel: filepath.Clean(rel)})
	}
	return planned
}

// entryMatches reports whether destDir holds exactly the planned files,
// each with the size and CRC-32 the archive records for it.
func entryMatches(destDir string, planned []plannedFile) bool {
	if !isDir(destDir) {
		return false
	}
	count := 0
	walkErr := filepath.WalkDir(destDir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	if walkErr != nil || count != len(planned) {
		return false
	}
	for _, p := range planned {
		data, err := os.ReadFile(filepath.Join(destDir, p.rel)) // #nosec G304 -- a file of the source cache entry.
		if err != nil || uint64(len(data)) != p.file.UncompressedSize64 || crc32.ChecksumIEEE(data) != p.file.CRC32 {
			return false
		}
	}
	return true
}

// archiveStamp identifies the planned files of an extraction for
// extensions by their names, CRC-32 checksums and sizes, read from the
// archive's directory. A rebuilt archive holding the same sources has the
// same stamp.
func archiveStamp(planned []plannedFile, extensions []string) string {
	lines := make([]string, 0, len(planned)+1)
	for _, p := range planned {
		lines = append(lines, fmt.Sprintf("%q %08x %d", p.file.Name, p.file.CRC32, p.file.UncompressedSize64))
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
	// #nosec G703 -- tmp is created by os.CreateTemp in this function and stampPath lies in the source cache.
	if err := os.Rename(tmp.Name(), stampPath); err != nil {
		removeBestEffort(tmp.Name())
		return fmt.Errorf("write source cache stamp: %w", err)
	}
	return nil
}

// removeBestEffort removes path, logging a failure.
func removeBestEffort(path string) {
	// #nosec G703 -- path is a temporary path this file created in the source cache.
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
