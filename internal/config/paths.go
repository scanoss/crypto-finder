package config

import (
	"os"
	"path/filepath"
)

const (
	// RootDirName is the root directory for SCANOSS configuration.
	RootDirName = ".scanoss"

	// AppDirName is the application-specific directory.
	AppDirName = "crypto-finder"

	// ConfigFileName is the configuration file name.
	ConfigFileName = "config.json"

	// CacheDirName is the cache directory name.
	CacheDirName = "cache"

	// RulesetsDirName is the rulesets cache directory name.
	RulesetsDirName = "rulesets"
)

// GetRootDir returns the path to the SCANOSS root directory (~/.scanoss)
// Creates the directory if it doesn't exist.
func GetRootDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	rootDir := filepath.Join(home, RootDirName)
	if err := os.MkdirAll(rootDir, 0o750); err != nil {
		return "", err
	}

	return rootDir, nil
}

// GetAppDir returns the path to the crypto-finder directory (~/.scanoss/crypto-finder)
// Creates the directory if it doesn't exist.
func GetAppDir() (string, error) {
	rootDir, err := GetRootDir()
	if err != nil {
		return "", err
	}

	appDir := filepath.Join(rootDir, AppDirName)
	if err := os.MkdirAll(appDir, 0o750); err != nil {
		return "", err
	}

	return appDir, nil
}

// GetConfigFilePath returns the path to the config file (~/.scanoss/crypto-finder/config.json)
// Does not create the file if it doesn't exist.
func GetConfigFilePath() (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(appDir, ConfigFileName), nil
}

// GetCacheDir returns the path to the cache directory (~/.scanoss/crypto-finder/cache)
// Creates the directory if it doesn't exist.
func GetCacheDir() (string, error) {
	appDir, err := GetAppDir()
	if err != nil {
		return "", err
	}

	cacheDir := filepath.Join(appDir, CacheDirName)
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return "", err
	}

	return cacheDir, nil
}

// GetRulesetsDir returns the path to the rulesets cache directory
// (~/.scanoss/crypto-finder/cache/rulesets)
// Creates the directory if it doesn't exist.
func GetRulesetsDir() (string, error) {
	cacheDir, err := GetCacheDir()
	if err != nil {
		return "", err
	}

	rulesetsDir := filepath.Join(cacheDir, RulesetsDirName)
	if err := os.MkdirAll(rulesetsDir, 0o750); err != nil {
		return "", err
	}

	return rulesetsDir, nil
}
