package dependency

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

// NewSourceCache creates a new source cache under ~/.crypto-finder/cache/sources/.
func NewSourceCache() (*SourceCache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	baseDir := filepath.Join(home, ".scanoss", "crypto-finder", "cache", "sources")
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
func (c *SourceCache) ExtractZip(archivePath, key, version string, extensions []string) (string, error) {
	destDir := filepath.Join(c.baseDir, sanitizeSourceCacheKey(key), version)

	// If already extracted, return immediately
	if info, err := os.Stat(destDir); err == nil && info.IsDir() {
		return destDir, nil
	}

	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return "", fmt.Errorf("create extraction dir: %w", err)
	}

	r, err := zip.OpenReader(archivePath)
	if err != nil {
		// Clean up empty dir on failure
		if removeErr := os.RemoveAll(destDir); removeErr != nil {
			joinedErr := errors.Join(err, fmt.Errorf("cleanup failed: %w", removeErr))
			return "", fmt.Errorf("open archive %s: %w", archivePath, joinedErr)
		}
		return "", fmt.Errorf("open archive %s: %w", archivePath, err)
	}
	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Str("archive", archivePath).Msg("Failed to close archive reader")
		}
	}()

	for _, f := range r.File {
		// Filter by extension if specified
		if len(extensions) > 0 && !hasMatchingExtension(f.Name, extensions) {
			continue
		}

		// #nosec G305 -- validated against zip slip with a canonical prefix check below.
		destPath := filepath.Join(destDir, f.Name)

		// Prevent zip slip
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if err := extractZipFile(f, destPath); err != nil {
			// Non-fatal — skip individual files that fail
			continue
		}
	}

	return destDir, nil
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
