package language

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-enry/go-enry/v2"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/skip"
)

// EnryDetector implements the Detector interface using GitHub's go-enry library.
// It provides accurate language detection based on file extensions, contents, and
// linguistic analysis.
type EnryDetector struct {
	skipMatcher skip.SkipMatcher
}

// NewEnryDetector creates a new EnryDetector with a custom SkipMatcher.
func NewEnryDetector(matcher skip.SkipMatcher) *EnryDetector {
	return &EnryDetector{
		skipMatcher: matcher,
	}
}

// Detect analyzes the target directory and returns all detected programming languages.
// It recursively scans all files, uses go-enry for detection, and returns unique
// language names in lowercase.
//
//nolint:gocognit // Function handles multiple validation and scanning concerns
func (d *EnryDetector) Detect(targetPath string) ([]string, error) {
	log.Debug().Str("path", targetPath).Msg("starting language detection")

	// Validate target path exists
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access target path: %w", err)
	}

	// If it's a single file, detect its language
	if !info.IsDir() {
		log.Debug().Str("path", targetPath).Msg("target is a single file")
		lang, err := d.detectFile(targetPath)
		if err != nil {
			return nil, err
		}
		if lang != "" {
			log.Info().Str("path", targetPath).Str("language", lang).Msg("detected language for file")
			return []string{strings.ToLower(lang)}, nil
		}
		return []string{}, nil
	}

	// Scan directory recursively
	log.Debug().Str("path", targetPath).Msg("scanning directory recursively")
	languageMap := make(map[string]bool)

	err = filepath.WalkDir(targetPath, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("permission denied or error accessing path")
			return nil
		}

		// Skip directories based on configured patterns
		if info.IsDir() {
			if d.skipMatcher.ShouldSkip(path, true) {
				log.Debug().Str("path", path).Msg("skipping directory (matches skip pattern)")
				return filepath.SkipDir
			}
			return nil
		}

		// Skip if not a regular file
		if !info.Type().IsRegular() {
			return nil
		}

		// Skip files based on configured patterns
		if d.skipMatcher.ShouldSkip(path, false) {
			log.Debug().Str("path", path).Msg("skipping file (matches skip pattern)")
			return nil
		}

		// Detect language for this file
		lang, err := d.detectFile(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to detect language for file")
			return nil
		}

		if lang != "" {
			log.Debug().Str("path", path).Str("language", lang).Msg("detected language")
			languageMap[strings.ToLower(lang)] = true
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	// Convert map to sorted slice
	languages := make([]string, 0, len(languageMap))
	for lang := range languageMap {
		languages = append(languages, lang)
	}

	log.Info().Int("count", len(languages)).Strs("languages", languages).Msg("language detection complete")

	return languages, nil
}

// detectFile detects the programming language of a single file.
func (d *EnryDetector) detectFile(path string) (string, error) {
	// First try detection by filename
	lang := enry.GetLanguage(filepath.Base(path), nil)
	if lang != "" && !enry.IsVendor(path) && !enry.IsDocumentation(path) && !enry.IsConfiguration(path) {
		return lang, nil
	}

	// If filename detection failed, read file content
	content, err := d.readFileSample(path)
	if err != nil {
		return "", err
	}

	// Detect by filename and content
	lang = enry.GetLanguage(filepath.Base(path), content)

	// Filter out non-programming languages
	if lang != "" && enry.GetLanguageType(lang) == enry.Programming {
		if !enry.IsVendor(path) && !enry.IsDocumentation(path) && !enry.IsConfiguration(path) {
			return lang, nil
		}
	}

	return "", nil
}

// readFileSample reads the first 512KB of a file for language detection.
// This is sufficient for go-enry's analysis while avoiding reading large files entirely.
func (d *EnryDetector) readFileSample(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to close file")
		}
	}()

	// Read first 512KB
	const maxSampleSize = 512 * 1024
	buffer := make([]byte, maxSampleSize)

	n, err := file.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return buffer[:n], nil
}
