package callgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/scanoss/crypto-finder/internal/config"
)

const (
	bytecodeCacheDirName       = "bytecode"
	bytecodeCacheSchemaVersion = 3
	legacyBytecodeCacheVersion = 1
)

var (
	bytecodeCacheFilenameUnsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	removeBytecodeCacheFile          = os.Remove
)

// BytecodeIndexCache stores per-artifact bytecode indexes.
// Implementations can back this with disk, memory, Redis, S3, etc.
type BytecodeIndexCache interface {
	Get(ctx context.Context, key string) (*CachedBytecodeIndex, bool, error)
	Put(ctx context.Context, key string, value *CachedBytecodeIndex) error
}

// CachedBytecodeIndex stores the derived bytecode index for a single artifact.
type CachedBytecodeIndex struct {
	SchemaVersion int
	ArtifactKey   string
	MethodsIndex  map[string][]methodSignature
	TypeHierarchy map[string][]string
}

type cachedBytecodeIndexJSON struct {
	SchemaVersion int                                    `json:"schema_version"`
	ArtifactKey   string                                 `json:"artifact_key"`
	MethodsIndex  map[string][]serializedMethodSignature `json:"methods_index"`
	TypeHierarchy map[string][]string                    `json:"type_hierarchy"`
}

type serializedMethodSignature struct {
	ClassName     string              `json:"class_name"`
	MethodName    string              `json:"method_name"`
	ParamTypes    []string            `json:"param_types"`
	ReturnType    string              `json:"return_type"`
	FullClass     string              `json:"full_class"`
	ParamTypeRefs []serializedTypeRef `json:"param_type_refs,omitempty"`
	ReturnTypeRef *serializedTypeRef  `json:"return_type_ref,omitempty"`
}

type serializedTypeRef struct {
	Name              string              `json:"name"`
	GenericParameters []serializedTypeRef `json:"generic_parameters,omitempty"`
}

func encodeSerializedTypeRef(ref TypeRef) *serializedTypeRef {
	if ref.Name == "" && len(ref.GenericParameters) == 0 {
		return nil
	}
	out := &serializedTypeRef{Name: ref.Name}
	if len(ref.GenericParameters) > 0 {
		out.GenericParameters = make([]serializedTypeRef, len(ref.GenericParameters))
		for i, child := range ref.GenericParameters {
			if encoded := encodeSerializedTypeRef(child); encoded != nil {
				out.GenericParameters[i] = *encoded
			}
		}
	}
	return out
}

func encodeSerializedTypeRefs(refs []TypeRef) []serializedTypeRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]serializedTypeRef, len(refs))
	for i, r := range refs {
		if encoded := encodeSerializedTypeRef(r); encoded != nil {
			out[i] = *encoded
		}
	}
	return out
}

func decodeSerializedTypeRef(ref *serializedTypeRef) TypeRef {
	if ref == nil {
		return TypeRef{}
	}
	return TypeRef{
		Name:              ref.Name,
		GenericParameters: decodeSerializedTypeRefs(ref.GenericParameters),
	}
}

func decodeSerializedTypeRefs(refs []serializedTypeRef) []TypeRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]TypeRef, len(refs))
	for i := range refs {
		out[i] = decodeSerializedTypeRef(&refs[i])
	}
	return out
}

// MarshalJSON serializes a cached bytecode index using the stable JSON schema.
func (c CachedBytecodeIndex) MarshalJSON() ([]byte, error) {
	methods := make(map[string][]serializedMethodSignature, len(c.MethodsIndex))
	for key, sigs := range c.MethodsIndex {
		encoded := make([]serializedMethodSignature, len(sigs))
		for i := range sigs {
			sig := &sigs[i]
			encoded[i] = serializedMethodSignature{
				ClassName:     sig.className,
				MethodName:    sig.methodName,
				ParamTypes:    append([]string(nil), sig.paramTypes...),
				ReturnType:    sig.returnType,
				FullClass:     sig.fullClass,
				ParamTypeRefs: encodeSerializedTypeRefs(sig.paramTypeRefs),
				ReturnTypeRef: encodeSerializedTypeRef(sig.returnTypeRef),
			}
		}
		methods[key] = encoded
	}

	payload := cachedBytecodeIndexJSON{
		SchemaVersion: c.SchemaVersion,
		ArtifactKey:   c.ArtifactKey,
		MethodsIndex:  methods,
		TypeHierarchy: c.TypeHierarchy,
	}
	return json.Marshal(payload)
}

// UnmarshalJSON deserializes a cached bytecode index from the stable JSON schema.
func (c *CachedBytecodeIndex) UnmarshalJSON(data []byte) error {
	var payload cachedBytecodeIndexJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	methods := make(map[string][]methodSignature, len(payload.MethodsIndex))
	for key, sigs := range payload.MethodsIndex {
		decoded := make([]methodSignature, len(sigs))
		for i := range sigs {
			sig := &sigs[i]
			decoded[i] = methodSignature{
				className:     sig.ClassName,
				methodName:    sig.MethodName,
				paramTypes:    append([]string(nil), sig.ParamTypes...),
				returnType:    sig.ReturnType,
				fullClass:     sig.FullClass,
				paramTypeRefs: decodeSerializedTypeRefs(sig.ParamTypeRefs),
				returnTypeRef: decodeSerializedTypeRef(sig.ReturnTypeRef),
			}
		}
		methods[key] = decoded
	}

	c.SchemaVersion = payload.SchemaVersion
	c.ArtifactKey = payload.ArtifactKey
	c.MethodsIndex = methods
	c.TypeHierarchy = payload.TypeHierarchy
	return nil
}

// DiskBytecodeIndexCache implements BytecodeIndexCache using local JSON files.
type DiskBytecodeIndexCache struct {
	dir string
}

// NewDiskBytecodeIndexCache creates a bytecode cache under ~/.scanoss/crypto-finder/cache/bytecode/.
func NewDiskBytecodeIndexCache() (*DiskBytecodeIndexCache, error) {
	cacheDir, err := config.GetCacheDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache dir: %w", err)
	}

	dir := filepath.Join(cacheDir, bytecodeCacheDirName)
	return NewDiskBytecodeIndexCacheWithDir(dir)
}

// NewDiskBytecodeIndexCacheWithDir creates a bytecode cache at a custom directory.
// Useful for testing.
func NewDiskBytecodeIndexCacheWithDir(dir string) (*DiskBytecodeIndexCache, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create bytecode cache dir: %w", err)
	}
	return &DiskBytecodeIndexCache{dir: dir}, nil
}

// Get loads a cached bytecode index entry by key.
func (c *DiskBytecodeIndexCache) Get(_ context.Context, key string) (*CachedBytecodeIndex, bool, error) {
	path := filepath.Join(c.dir, bytecodeCacheKeyToFilename(key))
	entry, ok, err := readBytecodeCacheFile(path, bytecodeCacheSchemaVersion)
	if err != nil || ok {
		return entry, ok, err
	}

	legacyKey, ok := legacyBytecodeCacheStorageKey(key)
	if !ok {
		return nil, false, nil
	}

	legacyPath := filepath.Join(c.dir, legacyBytecodeCacheKeyToFilename(legacyKey))
	entry, ok, err = readBytecodeCacheFile(legacyPath, legacyBytecodeCacheVersion)
	if err != nil || !ok {
		return nil, ok, err
	}

	// Lazily promote valid legacy cache entries so future reads hit the current path.
	entry.SchemaVersion = bytecodeCacheSchemaVersion
	if putErr := c.Put(context.Background(), key, entry); putErr != nil {
		_ = putErr
	}

	return entry, true, nil
}

// Put stores a cached bytecode index entry by key.
func (c *DiskBytecodeIndexCache) Put(_ context.Context, key string, value *CachedBytecodeIndex) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal bytecode index: %w", err)
	}

	path := filepath.Join(c.dir, bytecodeCacheKeyToFilename(key))
	tmpFile, err := os.CreateTemp(c.dir, bytecodeCacheKeyToFilename(key)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if tmpPath == "" {
			return
		}
		if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("cleanup temp cache file %s: %w", tmpPath, removeErr))
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			return fmt.Errorf("failed to write cache file: %w", errors.Join(err, closeErr))
		}
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			return fmt.Errorf("failed to sync cache file: %w", errors.Join(err, closeErr))
		}
		return fmt.Errorf("failed to sync cache file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close cache file: %w", err)
	}

	if err := renameBytecodeCacheFile(tmpPath, path); err != nil {
		return err
	}
	tmpPath = ""

	return nil
}

func renameBytecodeCacheFile(tmpPath, path string) error {
	// #nosec G703 -- tmpPath is created by os.CreateTemp and path is derived from a sanitized cache filename.
	err := os.Rename(tmpPath, path)
	if err == nil {
		return nil
	}

	info, statErr := os.Stat(path)
	if statErr != nil || info.IsDir() {
		return fmt.Errorf("failed to rename cache file: %w", err)
	}
	if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("failed to replace existing cache file: %w", errors.Join(err, removeErr))
	}
	// #nosec G703 -- tmpPath is created by os.CreateTemp and path is derived from a sanitized cache filename.
	if retryErr := os.Rename(tmpPath, path); retryErr != nil {
		return fmt.Errorf("failed to rename cache file after replacing existing file: %w", errors.Join(err, retryErr))
	}
	return nil
}

func bytecodeCacheStorageKey(artifactKey string) string {
	if artifactKey == "" {
		return ""
	}
	return fmt.Sprintf("v%d:%s", bytecodeCacheSchemaVersion, artifactKey)
}

func bytecodeCacheKeyToFilename(key string) string {
	safe := bytecodeCacheFilenameUnsafeChars.ReplaceAllString(key, "_")
	return safe + ".json"
}

func legacyBytecodeCacheStorageKey(key string) (string, bool) {
	artifactKey, ok := strings.CutPrefix(key, fmt.Sprintf("v%d:", bytecodeCacheSchemaVersion))
	if !ok || artifactKey == "" {
		return "", false
	}
	return fmt.Sprintf("v%d:%s", legacyBytecodeCacheVersion, artifactKey), true
}

func legacyBytecodeCacheKeyToFilename(key string) string {
	return strings.ReplaceAll(key, "/", "_") + ".json"
}

func readBytecodeCacheFile(path string, expectedSchema int) (*CachedBytecodeIndex, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to read cache file: %w", err)
	}

	var entry CachedBytecodeIndex
	if err := json.Unmarshal(data, &entry); err != nil {
		if removeErr := removeInvalidBytecodeCacheFile(path); removeErr != nil {
			return nil, false, removeErr
		}
		return nil, false, nil
	}

	if entry.SchemaVersion != expectedSchema {
		if removeErr := removeInvalidBytecodeCacheFile(path); removeErr != nil {
			return nil, false, removeErr
		}
		return nil, false, nil
	}

	return &entry, true, nil
}

func removeInvalidBytecodeCacheFile(path string) error {
	if err := removeBytecodeCacheFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove corrupted cache file: %w", err)
	}
	return nil
}
