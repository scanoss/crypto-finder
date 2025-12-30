package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetRootDir(t *testing.T) {
	t.Parallel()

	rootDir, err := GetRootDir()
	if err != nil {
		t.Fatalf("GetRootDir() failed: %v", err)
	}

	if rootDir == "" {
		t.Fatal("Expected non-empty root directory path")
	}

	// Should end with .scanoss
	if !strings.HasSuffix(rootDir, RootDirName) {
		t.Errorf("Expected path to end with '%s', got: %s", RootDirName, rootDir)
	}

	// Directory should exist
	info, err := os.Stat(rootDir)
	if err != nil {
		t.Fatalf("Root directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("Root path is not a directory")
	}
}

func TestGetAppDir(t *testing.T) {
	t.Parallel()

	appDir, err := GetAppDir()
	if err != nil {
		t.Fatalf("GetAppDir() failed: %v", err)
	}

	if appDir == "" {
		t.Fatal("Expected non-empty app directory path")
	}

	// Should end with crypto-finder
	if !strings.HasSuffix(appDir, AppDirName) {
		t.Errorf("Expected path to end with '%s', got: %s", AppDirName, appDir)
	}

	// Should contain .scanoss
	if !strings.Contains(appDir, RootDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", RootDirName, appDir)
	}

	// Directory should exist
	info, err := os.Stat(appDir)
	if err != nil {
		t.Fatalf("App directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("App path is not a directory")
	}
}

func TestGetConfigFilePath(t *testing.T) {
	t.Parallel()

	configPath, err := GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath() failed: %v", err)
	}

	if configPath == "" {
		t.Fatal("Expected non-empty config file path")
	}

	// Should end with config.json
	if !strings.HasSuffix(configPath, ConfigFileName) {
		t.Errorf("Expected path to end with '%s', got: %s", ConfigFileName, configPath)
	}

	// Should contain .scanoss and crypto-finder
	if !strings.Contains(configPath, RootDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", RootDirName, configPath)
	}

	if !strings.Contains(configPath, AppDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", AppDirName, configPath)
	}

	// Parent directory should exist (but file might not)
	parentDir := filepath.Dir(configPath)
	info, err := os.Stat(parentDir)
	if err != nil {
		t.Fatalf("Config file parent directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("Config file parent is not a directory")
	}
}

func TestGetCacheDir(t *testing.T) {
	t.Parallel()

	cacheDir, err := GetCacheDir()
	if err != nil {
		t.Fatalf("GetCacheDir() failed: %v", err)
	}

	if cacheDir == "" {
		t.Fatal("Expected non-empty cache directory path")
	}

	// Should end with cache
	if !strings.HasSuffix(cacheDir, CacheDirName) {
		t.Errorf("Expected path to end with '%s', got: %s", CacheDirName, cacheDir)
	}

	// Should contain .scanoss and crypto-finder
	if !strings.Contains(cacheDir, RootDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", RootDirName, cacheDir)
	}

	if !strings.Contains(cacheDir, AppDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", AppDirName, cacheDir)
	}

	// Directory should exist
	info, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatalf("Cache directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("Cache path is not a directory")
	}
}

func TestGetRulesetsDir(t *testing.T) {
	t.Parallel()

	rulesetsDir, err := GetRulesetsDir()
	if err != nil {
		t.Fatalf("GetRulesetsDir() failed: %v", err)
	}

	if rulesetsDir == "" {
		t.Fatal("Expected non-empty rulesets directory path")
	}

	// Should end with rulesets
	if !strings.HasSuffix(rulesetsDir, RulesetsDirName) {
		t.Errorf("Expected path to end with '%s', got: %s", RulesetsDirName, rulesetsDir)
	}

	// Should contain .scanoss, crypto-finder, and cache
	if !strings.Contains(rulesetsDir, RootDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", RootDirName, rulesetsDir)
	}

	if !strings.Contains(rulesetsDir, AppDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", AppDirName, rulesetsDir)
	}

	if !strings.Contains(rulesetsDir, CacheDirName) {
		t.Errorf("Expected path to contain '%s', got: %s", CacheDirName, rulesetsDir)
	}

	// Directory should exist
	info, err := os.Stat(rulesetsDir)
	if err != nil {
		t.Fatalf("Rulesets directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("Rulesets path is not a directory")
	}
}

func TestPathsConsistency(t *testing.T) {
	t.Parallel()

	// Get all paths
	rootDir, err := GetRootDir()
	if err != nil {
		t.Fatalf("GetRootDir() failed: %v", err)
	}

	appDir, err := GetAppDir()
	if err != nil {
		t.Fatalf("GetAppDir() failed: %v", err)
	}

	cacheDir, err := GetCacheDir()
	if err != nil {
		t.Fatalf("GetCacheDir() failed: %v", err)
	}

	rulesetsDir, err := GetRulesetsDir()
	if err != nil {
		t.Fatalf("GetRulesetsDir() failed: %v", err)
	}

	configPath, err := GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath() failed: %v", err)
	}

	// Verify hierarchy
	// appDir should be under rootDir
	if !strings.HasPrefix(appDir, rootDir) {
		t.Errorf("appDir should be under rootDir: %s not under %s", appDir, rootDir)
	}

	// cacheDir should be under appDir
	if !strings.HasPrefix(cacheDir, appDir) {
		t.Errorf("cacheDir should be under appDir: %s not under %s", cacheDir, appDir)
	}

	// rulesetsDir should be under cacheDir
	if !strings.HasPrefix(rulesetsDir, cacheDir) {
		t.Errorf("rulesetsDir should be under cacheDir: %s not under %s", rulesetsDir, cacheDir)
	}

	// configPath should be under appDir
	if !strings.HasPrefix(configPath, appDir) {
		t.Errorf("configPath should be under appDir: %s not under %s", configPath, appDir)
	}
}
