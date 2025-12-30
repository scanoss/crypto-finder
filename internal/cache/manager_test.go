package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/scanoss/crypto-finder/internal/api"
)

// Mock API client for testing
type mockAPIClient struct {
	downloadRulesetFunc func(ctx context.Context, name, version string) ([]byte, *api.Manifest, error)
}

func (m *mockAPIClient) DownloadRuleset(ctx context.Context, name, version string) ([]byte, *api.Manifest, error) {
	if m.downloadRulesetFunc != nil {
		return m.downloadRulesetFunc(ctx, name, version)
	}
	// Default mock response - minimal valid tarball
	return createMockTarball(), &api.Manifest{
		Name:           name,
		Version:        version,
		ChecksumSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // empty file checksum
		CreatedAt:      time.Now(),
	}, nil
}

// createMockTarball creates a minimal valid gzip+tar archive for testing
func createMockTarball() []byte {
	// Minimal gzip header + empty tar
	return []byte{
		// Gzip header
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		// Empty tar archive (2x 512-byte null blocks)
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	mockClient := &mockAPIClient{}
	manager, err := NewManager(mockClient)

	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	if manager == nil {
		t.Fatal("NewManager() returned nil manager")
	}

	if manager.apiClient == nil {
		t.Error("manager.apiClient is nil")
	}

	if manager.cacheDir == "" {
		t.Error("manager.cacheDir is empty")
	}

	if manager.noCache {
		t.Error("manager.noCache should default to false")
	}
}

func TestManager_SetNoCache(t *testing.T) {
	t.Parallel()

	mockClient := &mockAPIClient{}
	manager, err := NewManager(mockClient)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Test setting noCache to true
	manager.SetNoCache(true)
	if !manager.noCache {
		t.Error("SetNoCache(true) did not set noCache to true")
	}

	// Test setting noCache back to false
	manager.SetNoCache(false)
	if manager.noCache {
		t.Error("SetNoCache(false) did not set noCache to false")
	}
}

func TestManager_GetRulesetPath_CacheHit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	mockClient := &mockAPIClient{}

	// Create manager with temp cache dir
	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Setup: Create valid cache with metadata
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}

	// Create valid metadata (not expired)
	metadata := NewMetadata("dca", "latest", "checksum123", 86400) // 24h TTL
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Execute - should use cache, not download
	downloadCalled := false
	mockClient.downloadRulesetFunc = func(ctx context.Context, name, version string) ([]byte, *api.Manifest, error) {
		downloadCalled = true
		return nil, nil, errors.New("should not be called")
	}

	path, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	if downloadCalled {
		t.Error("DownloadRuleset should not have been called (cache hit expected)")
	}

	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}
}

func TestManager_GetRulesetPath_CacheMiss(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	mockTarball := createMockTarball()
	mockClient := &mockAPIClient{
		downloadRulesetFunc: func(ctx context.Context, name, version string) ([]byte, *api.Manifest, error) {
			return mockTarball, &api.Manifest{
				Name:           name,
				Version:        version,
				ChecksumSHA256: CalculateChecksum(mockTarball),
				CreatedAt:      time.Now(),
			}, nil
		},
	}

	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - cache doesn't exist, should download
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	expectedPath := filepath.Join(tempDir, "dca", "latest")
	if path != expectedPath {
		t.Errorf("Expected path %s, got %s", expectedPath, path)
	}

	// Verify cache was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Cache directory was not created")
	}

	// Verify metadata was created
	metadataPath := filepath.Join(path, metadataFileName)
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		t.Error("Metadata file was not created")
	}
}

func TestManager_GetRulesetPath_NoCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create existing cache
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}

	metadata := NewMetadata("dca", "latest", "oldchecksum", 86400)
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	// Setup mock client to track downloads
	downloadCount := 0
	mockTarball := createMockTarball()
	mockClient := &mockAPIClient{
		downloadRulesetFunc: func(ctx context.Context, name, version string) ([]byte, *api.Manifest, error) {
			downloadCount++
			return mockTarball, &api.Manifest{
				Name:           name,
				Version:        version,
				ChecksumSHA256: CalculateChecksum(mockTarball),
				CreatedAt:      time.Now(),
			}, nil
		},
	}

	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  tempDir,
		noCache:   true, // Enable no-cache mode
	}

	// Execute - should bypass cache and download
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	if downloadCount != 1 {
		t.Errorf("Expected 1 download, got %d", downloadCount)
	}

	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}

	// Verify cache was updated (not using old checksum)
	newMetadata, err := LoadMetadata(metadataPath)
	if err != nil {
		t.Fatalf("Failed to load updated metadata: %v", err)
	}

	if newMetadata.Checksum == "oldchecksum" {
		t.Error("Cache was not updated (checksum unchanged)")
	}
}

func TestManager_GetRulesetPath_ExpiredCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Setup: Create expired cache
	rulesetPath := filepath.Join(tempDir, "dca", "latest")
	if err := os.MkdirAll(rulesetPath, 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}

	// Create metadata with very short TTL (already expired)
	metadata := NewMetadata("dca", "latest", "checksum123", -1) // Negative TTL = already expired
	metadataPath := filepath.Join(rulesetPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		t.Fatalf("Failed to save metadata: %v", err)
	}

	downloadCalled := false
	mockTarball := createMockTarball()
	mockClient := &mockAPIClient{
		downloadRulesetFunc: func(ctx context.Context, name, version string) ([]byte, *api.Manifest, error) {
			downloadCalled = true
			return mockTarball, &api.Manifest{
				Name:           name,
				Version:        version,
				ChecksumSHA256: CalculateChecksum(mockTarball),
				CreatedAt:      time.Now(),
			}, nil
		},
	}

	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - cache is expired, should download
	path, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err != nil {
		t.Fatalf("GetRulesetPath() failed: %v", err)
	}

	if !downloadCalled {
		t.Error("Expected download to be called for expired cache")
	}

	if path != rulesetPath {
		t.Errorf("Expected path %s, got %s", rulesetPath, path)
	}
}

func TestManager_GetRulesetPath_DownloadError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tempDir := t.TempDir()

	mockClient := &mockAPIClient{
		downloadRulesetFunc: func(ctx context.Context, name, version string) ([]byte, *api.Manifest, error) {
			return nil, nil, errors.New("network error")
		},
	}

	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - download should fail
	_, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error but got none")
	}

	if err.Error() != "failed to download ruleset: network error" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestManager_GetRulesetPath_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	tempDir := t.TempDir()

	mockClient := &mockAPIClient{
		downloadRulesetFunc: func(ctx context.Context, name, version string) ([]byte, *api.Manifest, error) {
			return nil, nil, ctx.Err()
		},
	}

	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	// Execute - should fail due to context cancellation
	_, err := manager.GetRulesetPath(ctx, "dca", "latest")

	// Assert
	if err == nil {
		t.Fatal("Expected error due to context cancellation")
	}
}

func TestManager_isCacheValid(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	mockClient := &mockAPIClient{}

	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  tempDir,
		noCache:   false,
	}

	tests := []struct {
		name     string
		setup    func() (rulesetPath, metadataPath string)
		expected bool
	}{
		{
			name: "valid cache with unexpired metadata",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "test1")
				_ = os.MkdirAll(rulesetPath, 0o755)
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				metadata := NewMetadata("test", "1.0", "checksum", 86400)
				_ = metadata.Save(metadataPath)
				return rulesetPath, metadataPath
			},
			expected: true,
		},
		{
			name: "nonexistent ruleset directory",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "nonexistent")
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				return rulesetPath, metadataPath
			},
			expected: false,
		},
		{
			name: "missing metadata file",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "test2")
				_ = os.MkdirAll(rulesetPath, 0o755)
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				return rulesetPath, metadataPath
			},
			expected: false,
		},
		{
			name: "expired cache",
			setup: func() (string, string) {
				rulesetPath := filepath.Join(tempDir, "test3")
				_ = os.MkdirAll(rulesetPath, 0o755)
				metadataPath := filepath.Join(rulesetPath, metadataFileName)
				metadata := NewMetadata("test", "1.0", "checksum", -1) // Already expired
				_ = metadata.Save(metadataPath)
				return rulesetPath, metadataPath
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rulesetPath, metadataPath := tt.setup()
			result := manager.isCacheValid(rulesetPath, metadataPath)

			if result != tt.expected {
				t.Errorf("isCacheValid() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestManager_getTTL(t *testing.T) {
	t.Parallel()

	mockClient := &mockAPIClient{}
	manager := &Manager{
		apiClient: mockClient,
		cacheDir:  "/tmp",
		noCache:   false,
	}

	tests := []struct {
		version string
		ttl     time.Duration
	}{
		{"latest", 24 * time.Hour},
		{"v1.0.0", 7 * 24 * time.Hour},
		{"v2.3.1", 7 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := manager.getTTL(tt.version)
			if result != tt.ttl {
				t.Errorf("getTTL(%s) = %v, expected %v", tt.version, result, tt.ttl)
			}
		})
	}
}
