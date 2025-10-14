package language

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-enry/go-enry/v2"
)

// EnryDetector implements the Detector interface using GitHub's go-enry library.
// It provides accurate language detection based on file extensions, contents, and
// linguistic analysis.
type EnryDetector struct {
	excludeDirs []string
}

// NewEnryDetector creates a new EnryDetector with default excluded directories.
func NewEnryDetector() *EnryDetector {
	return &EnryDetector{
		excludeDirs: DefaultExcludedDirs,
	}
}

// NewEnryDetectorWithExclusions creates a new EnryDetector with custom excluded directories.
func NewEnryDetectorWithExclusions(excludeDirs []string) *EnryDetector {
	return &EnryDetector{
		excludeDirs: excludeDirs,
	}
}

// Detect analyzes the target directory and returns all detected programming languages.
// It recursively scans all files, uses go-enry for detection, and returns unique
// language names in lowercase.
func (d *EnryDetector) Detect(targetPath string) ([]string, error) {
	// Validate target path exists
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access target path: %w", err)
	}

	// If it's a single file, detect its language
	if !info.IsDir() {
		lang, err := d.detectFile(targetPath)
		if err != nil {
			return nil, err
		}
		if lang != "" {
			return []string{strings.ToLower(lang)}, nil
		}
		return []string{}, nil
	}

	// Scan directory recursively
	languageMap := make(map[string]bool)

	err = filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log and continue on permission errors
			return nil
		}

		// Skip excluded directories
		if info.IsDir() {
			if d.shouldExcludeDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip if not a regular file
		if !info.Mode().IsRegular() {
			return nil
		}

		// Detect language for this file
		lang, err := d.detectFile(path)
		if err != nil {
			// Log error but continue processing other files
			return nil
		}

		if lang != "" {
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
	defer file.Close()

	// Read first 512KB (enry doesn't need more)
	const maxSampleSize = 512 * 1024
	buffer := make([]byte, maxSampleSize)

	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return buffer[:n], nil
}

// shouldExcludeDir checks if a directory should be excluded from scanning.
func (d *EnryDetector) shouldExcludeDir(dirName string) bool {
	return slices.Contains(d.excludeDirs, dirName)
}
