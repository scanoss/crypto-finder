package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

func joinVirtualPath(rel string) string {
	return filepath.Join(string(filepath.Separator)+"virtual", rel)
}

type fakeBytecodeIndexCache struct {
	mu      sync.Mutex
	entries map[string]*CachedBytecodeIndex
	gets    []string
	puts    []string
}

func newFakeBytecodeIndexCache() *fakeBytecodeIndexCache {
	return &fakeBytecodeIndexCache{
		entries: make(map[string]*CachedBytecodeIndex),
	}
}

func (c *fakeBytecodeIndexCache) Get(_ context.Context, key string) (*CachedBytecodeIndex, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets = append(c.gets, key)
	entry, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	return entry, true, nil
}

func (c *fakeBytecodeIndexCache) Put(_ context.Context, key string, value *CachedBytecodeIndex) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts = append(c.puts, key)
	c.entries[key] = value
	return nil
}

func jwtTestClassInfo() []*classFileInfo {
	return []*classFileInfo{
		{
			className:     "ClaimsMutator",
			fullClassName: "io.jsonwebtoken.ClaimsMutator",
			methods: []methodSignature{{
				className:  "ClaimsMutator",
				methodName: "setId",
				paramTypes: []string{"String"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.ClaimsMutator",
			}},
		},
		{
			className:     "JwtBuilder",
			fullClassName: "io.jsonwebtoken.JwtBuilder",
			interfaces:    []string{"io.jsonwebtoken.ClaimsMutator"},
			methods: []methodSignature{{
				className:  "JwtBuilder",
				methodName: "signWith",
				paramTypes: []string{"SignatureAlgorithm", "byte[]"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.JwtBuilder",
			}},
		},
	}
}

func newJWTCallGraph() (*CallGraph, *FunctionDecl, *FunctionDecl) {
	target := &FunctionDecl{
		ID:         FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith#2"},
		Parameters: []FunctionParameter{{Type: "K"}, {Type: "byte[]"}},
	}
	caller := &FunctionDecl{
		ID: FunctionID{Package: "app", Name: "run#0"},
		Calls: []FunctionCall{{
			Callee:    FunctionID{Package: "app", Type: "JwtBuilder", Name: "signWith#2"},
			Arguments: []string{"algo", "key"},
		}},
	}
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			target.ID.String(): target,
			caller.ID.String(): caller,
		},
		Callers: map[string][]string{},
	}
	return graph, target, caller
}

func disableAmbientJavaHome(t *testing.T) {
	t.Helper()
	t.Setenv("JAVA_HOME", "")
}

func assertJWTGraphResolved(t *testing.T, graph *CallGraph, target, caller *FunctionDecl) {
	t.Helper()

	if got := target.Parameters[0].Type; got != "SignatureAlgorithm" {
		t.Fatalf("target.Parameters[0].Type = %q, want SignatureAlgorithm", got)
	}
	if got := target.ReturnType; got != "JwtBuilder" {
		t.Fatalf("target.ReturnType = %q, want JwtBuilder", got)
	}

	rewritten := caller.Calls[0].Callee
	if rewritten.Package != "io.jsonwebtoken" || rewritten.Type != "JwtBuilder" {
		t.Fatalf("call was not rewritten to bytecode package: %#v", rewritten)
	}

	callers := graph.Callers[target.ID.String()]
	if len(callers) != 1 || callers[0] != caller.ID.String() {
		t.Fatalf("unexpected callers index: %#v", graph.Callers)
	}
	if got := graph.TypeHierarchy["io.jsonwebtoken.JwtBuilder"]; len(got) != 1 || got[0] != "io.jsonwebtoken.ClaimsMutator" {
		t.Fatalf("graph.TypeHierarchy[io.jsonwebtoken.JwtBuilder] = %#v, want [io.jsonwebtoken.ClaimsMutator]", got)
	}
	key := ExternalMethodSignatureKey(FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith#2"})
	signatures := graph.ExternalMethodSignatures[key]
	if len(signatures) != 1 {
		t.Fatalf("graph.ExternalMethodSignatures[%q] = %#v, want one signature", key, signatures)
	}
	if got := signatures[0].ParameterTypes; len(got) != 2 || got[0] != "SignatureAlgorithm" || got[1] != "byte[]" {
		t.Fatalf("external parameter types = %#v, want [SignatureAlgorithm byte[]]", got)
	}
}

func TestBuildMethodIndexFromClassInfos_UsesFullyQualifiedKeys(t *testing.T) {
	index, hierarchy := buildMethodIndexFromClassInfos([]*classFileInfo{
		{
			className:     "Cipher",
			fullClassName: "javax.crypto.Cipher",
			methods: []methodSignature{{
				className:  "Cipher",
				methodName: "getInstance",
				fullClass:  "javax.crypto.Cipher",
			}},
		},
		{
			className:     "Cipher",
			fullClassName: "com.example.Cipher",
			interfaces:    []string{"com.example.AlgorithmFactory"},
			superClass:    "com.example.BaseCipher",
			methods: []methodSignature{{
				className:  "Cipher",
				methodName: "getInstance",
				fullClass:  "com.example.Cipher",
			}},
		},
	})

	if got := len(index["javax.crypto.Cipher.getInstance"]); got != 1 {
		t.Fatalf("index[javax.crypto.Cipher.getInstance] = %d entries, want 1", got)
	}
	if got := len(index["com.example.Cipher.getInstance"]); got != 1 {
		t.Fatalf("index[com.example.Cipher.getInstance] = %d entries, want 1", got)
	}
	if _, exists := index["Cipher.getInstance"]; exists {
		t.Fatalf("simple-name method key should not exist: %#v", index)
	}
	if got := hierarchy["com.example.Cipher"]; len(got) != 2 || got[0] != "com.example.AlgorithmFactory" || got[1] != "com.example.BaseCipher" {
		t.Fatalf("hierarchy[com.example.Cipher] = %#v, want [com.example.AlgorithmFactory com.example.BaseCipher]", got)
	}
}

func TestBuildJavaMethodLookup_UsesQualifiedAndSimpleArityKeys(t *testing.T) {
	index := map[string][]methodSignature{
		"io.jsonwebtoken.JwtBuilder.signWith": {
			{
				className:  "JwtBuilder",
				methodName: "signWith",
				paramTypes: []string{"SignatureAlgorithm", "byte[]"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.JwtBuilder",
			},
		},
		"com.example.JwtBuilder.signWith": {
			{
				className:  "JwtBuilder",
				methodName: "signWith",
				paramTypes: []string{"String", "byte[]"},
				returnType: "JwtBuilder",
				fullClass:  "com.example.JwtBuilder",
			},
		},
	}

	lookup := buildJavaMethodLookup(index)

	exact := lookupJavaMethodSignatures(lookup, "io.jsonwebtoken", "JwtBuilder", "signWith", 2)
	if len(exact) != 1 || exact[0].fullClass != "io.jsonwebtoken.JwtBuilder" {
		t.Fatalf("exact lookup = %#v, want io.jsonwebtoken.JwtBuilder only", exact)
	}

	fallback := lookupJavaMethodSignatures(lookup, "", "JwtBuilder", "signWith", 2)
	if len(fallback) != 2 {
		t.Fatalf("simple fallback lookup = %#v, want 2 entries", fallback)
	}
	if fallback[0].fullClass != "com.example.JwtBuilder" || fallback[1].fullClass != "io.jsonwebtoken.JwtBuilder" {
		t.Fatalf("simple fallback order = %#v, want deterministic lexical order", fallback)
	}
}

func TestBuildJavaMethodLookup_FiltersByArity(t *testing.T) {
	index := map[string][]methodSignature{
		"pkg.Type.helper": {
			{className: "Type", methodName: "helper", paramTypes: nil, fullClass: "pkg.Type"},
			{className: "Type", methodName: "helper", paramTypes: []string{"String"}, fullClass: "pkg.Type"},
		},
	}

	lookup := buildJavaMethodLookup(index)
	zeroArity := lookupJavaMethodSignatures(lookup, "pkg", "Type", "helper", 0)
	if len(zeroArity) != 1 || len(zeroArity[0].paramTypes) != 0 {
		t.Fatalf("zero-arity lookup = %#v, want one zero-arity signature", zeroArity)
	}

	oneArity := lookupJavaMethodSignatures(lookup, "pkg", "Type", "helper", 1)
	if len(oneArity) != 1 || len(oneArity[0].paramTypes) != 1 || oneArity[0].paramTypes[0] != "String" {
		t.Fatalf("one-arity lookup = %#v, want one String signature", oneArity)
	}
}

func TestApplyResolvedJavaCall_AllowsFullClassWithoutPackage(t *testing.T) {
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			".(StandaloneType).helper#0": {
				ID: FunctionID{Type: "StandaloneType", Name: "helper#0"},
			},
			"app.run#0": {
				ID: FunctionID{Package: "app", Name: "run#0"},
			},
		},
		Callers: map[string][]string{},
	}
	fn := graph.Functions["app.run#0"]
	call := &FunctionCall{
		Callee: FunctionID{Package: "app", Type: "StandaloneType", Name: "helper#0"},
	}
	sig := methodSignature{
		className:  "StandaloneType",
		methodName: "helper",
		fullClass:  "StandaloneType",
	}

	if ok := applyResolvedJavaCall(graph, fn, call, sig, map[string][]string{}); !ok {
		t.Fatal("expected applyResolvedJavaCall to resolve method without package")
	}
	if call.Callee.Package != "" || call.Callee.Type != "StandaloneType" || call.Callee.Name != "helper#0" {
		t.Fatalf("call.Callee = %#v, want packageless StandaloneType.helper#0", call.Callee)
	}
	callers := graph.Callers[".(StandaloneType).helper#0"]
	if len(callers) != 1 || callers[0] != "app.run#0" {
		t.Fatalf("unexpected callers index: %#v", graph.Callers)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_UsesExactVersionJar(t *testing.T) {
	disableAmbientJavaHome(t)

	repo := t.TempDir()
	jarV1 := filepath.Join(repo, "io", "jsonwebtoken", "jjwt-api", "1.0.0", "jjwt-api-1.0.0.jar")
	jarV2 := filepath.Join(repo, "io", "jsonwebtoken", "jjwt-api", "2.0.0", "jjwt-api-2.0.0.jar")
	for _, jarPath := range []string{jarV1, jarV2} {
		if err := os.MkdirAll(filepath.Dir(jarPath), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(jarPath), err)
		}
		if err := os.WriteFile(jarPath, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", jarPath, err)
		}
	}

	var seen []string
	resolver := &JavaBytecodeTypeResolver{
		mavenRepoPath: repo,
		extractClassInfo: func(jarPath string) ([]*classFileInfo, error) {
			seen = append(seen, jarPath)
			return []*classFileInfo{{
				className:     "JwtBuilder",
				fullClassName: "io.jsonwebtoken.JwtBuilder",
				methods: []methodSignature{{
					className:  "JwtBuilder",
					methodName: "signWith",
					paramTypes: []string{"SignatureAlgorithm", "byte[]"},
					returnType: "JwtBuilder",
					fullClass:  "io.jsonwebtoken.JwtBuilder",
				}},
			}}, nil
		},
	}

	if err := resolver.ResolveTypes(&CallGraph{}, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "2.0.0",
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	if len(seen) != 1 {
		t.Fatalf("extractClassInfo calls = %d, want 1", len(seen))
	}
	if seen[0] != jarV2 {
		t.Fatalf("jarPath = %q, want %q", seen[0], jarV2)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_DeduplicatesJARs(t *testing.T) {
	disableAmbientJavaHome(t)

	var calls atomic.Int32
	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string {
			if root.ImportPath == "app" {
				return ""
			}
			return "/tmp/shared.jar"
		},
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			calls.Add(1)
			return []*classFileInfo{{
				className:     "JwtBuilder",
				fullClassName: "io.jsonwebtoken.JwtBuilder",
			}}, nil
		},
	}

	err := resolver.ResolveTypes(&CallGraph{}, []PackageDir{
		{Dir: "/repo", ImportPath: "app"},
		{ImportPath: "io.jsonwebtoken:jjwt-api", Version: "1.0.0"},
		{ImportPath: "io.jsonwebtoken:jjwt-api", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	if calls.Load() != 1 {
		t.Fatalf("extractClassInfo calls = %d, want 1", calls.Load())
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_UsesResolverSuppliedCompiledArtifactPath(t *testing.T) {
	disableAmbientJavaHome(t)

	compiledJar := filepath.Join(t.TempDir(), "lib.jar")
	if err := os.WriteFile(compiledJar, []byte("jar"), 0o600); err != nil {
		t.Fatalf("write compiled jar: %v", err)
	}

	var seen []string
	resolver := &JavaBytecodeTypeResolver{
		extractClassInfo: func(path string) ([]*classFileInfo, error) {
			seen = append(seen, path)
			return []*classFileInfo{{
				className:     "JwtBuilder",
				fullClassName: "io.jsonwebtoken.JwtBuilder",
			}}, nil
		},
	}

	if err := resolver.ResolveTypes(&CallGraph{}, []PackageDir{{
		ImportPath:           "org.example:lib",
		Version:              "1.2.3",
		CompiledArtifactPath: compiledJar,
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	if len(seen) != 1 || seen[0] != compiledJar {
		t.Fatalf("expected resolver to use supplied compiled artifact path, got %#v", seen)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_ProcessesJARsConcurrently(t *testing.T) {
	disableAmbientJavaHome(t)

	workers := min(max(runtime.NumCPU()/2, 1), maxJavaJARWorkers)
	if workers < 2 {
		t.Skip("environment does not provide enough CPUs to exercise resolver concurrency")
	}

	roots := []PackageDir{
		{ImportPath: "g:a", Version: "1"},
		{ImportPath: "g:b", Version: "1"},
		{ImportPath: "g:c", Version: "1"},
		{ImportPath: "g:d", Version: "1"},
	}

	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	started := make(chan struct{}, len(roots))
	release := make(chan struct{})

	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string {
			return joinVirtualPath(strings.ReplaceAll(root.ImportPath, ":", "-") + ".jar")
		},
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			current := inFlight.Add(1)
			for {
				prev := maxInFlight.Load()
				if current <= prev || maxInFlight.CompareAndSwap(prev, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			inFlight.Add(-1)
			return []*classFileInfo{{
				className:     "JwtBuilder",
				fullClassName: "io.jsonwebtoken.JwtBuilder",
			}}, nil
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- resolver.ResolveTypes(&CallGraph{}, roots)
	}()

	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for concurrent JAR work to start")
		}
	}
	close(release)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ResolveTypes: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ResolveTypes to finish")
	}

	if maxInFlight.Load() < 2 {
		t.Fatalf("maxInFlight = %d, want at least 2", maxInFlight.Load())
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_PreservesBehaviorWithPartialFailures(t *testing.T) {
	disableAmbientJavaHome(t)

	graph, target, caller := newJWTCallGraph()

	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string {
			return root.Version
		},
		extractClassInfo: func(jarPath string) ([]*classFileInfo, error) {
			if jarPath == "bad" {
				return nil, os.ErrInvalid
			}
			return jwtTestClassInfo(), nil
		},
	}

	err := resolver.ResolveTypes(graph, []PackageDir{
		{ImportPath: "io.jsonwebtoken:jjwt-impl", Version: "bad"},
		{ImportPath: "io.jsonwebtoken:jjwt-api", Version: "good"},
	})
	if err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	assertJWTGraphResolved(t, graph, target, caller)
}

func TestJavaBytecodeTypeResolver_ResolveTypes_PropagatesTransitiveInheritance(t *testing.T) {
	disableAmbientJavaHome(t)

	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			"app.LeafBuilder.setId#1": {
				ID:         FunctionID{Package: "app", Type: "LeafBuilder", Name: "setId#1"},
				Parameters: []FunctionParameter{{Type: "T"}},
			},
		},
		Callers: map[string][]string{},
	}

	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string {
			return root.Version
		},
		extractClassInfo: func(_ string) ([]*classFileInfo, error) {
			return []*classFileInfo{
				{
					className:     "BaseMutator",
					fullClassName: "io.jsonwebtoken.BaseMutator",
					methods: []methodSignature{{
						className:  "BaseMutator",
						methodName: "setId",
						paramTypes: []string{"String"},
						returnType: "BaseMutator",
						fullClass:  "io.jsonwebtoken.BaseMutator",
					}},
				},
				{
					className:     "MidMutator",
					fullClassName: "io.jsonwebtoken.MidMutator",
					interfaces:    []string{"io.jsonwebtoken.BaseMutator"},
				},
				{
					className:     "LeafBuilder",
					fullClassName: "io.jsonwebtoken.LeafBuilder",
					interfaces:    []string{"io.jsonwebtoken.MidMutator"},
				},
			}, nil
		},
	}

	if err := resolver.ResolveTypes(graph, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "good",
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	fn := graph.Functions["app.LeafBuilder.setId#1"]
	if got := fn.Parameters[0].Type; got != "String" {
		t.Fatalf("transitive inherited method type = %q, want String", got)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_PropagatesSuperclassInheritance(t *testing.T) {
	disableAmbientJavaHome(t)

	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			"app.ChildBuilder.setId#1": {
				ID:         FunctionID{Package: "app", Type: "ChildBuilder", Name: "setId#1"},
				Parameters: []FunctionParameter{{Type: "T"}},
			},
		},
		Callers: map[string][]string{},
	}

	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string {
			return root.Version
		},
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			return []*classFileInfo{
				{
					className:     "BaseBuilder",
					fullClassName: "io.jsonwebtoken.BaseBuilder",
					methods: []methodSignature{{
						className:  "BaseBuilder",
						methodName: "setId",
						paramTypes: []string{"String"},
						returnType: "BaseBuilder",
						fullClass:  "io.jsonwebtoken.BaseBuilder",
					}},
				},
				{
					className:     "ChildBuilder",
					fullClassName: "io.jsonwebtoken.ChildBuilder",
					superClass:    "io.jsonwebtoken.BaseBuilder",
				},
			}, nil
		},
	}

	if err := resolver.ResolveTypes(graph, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "good",
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	fn := graph.Functions["app.ChildBuilder.setId#1"]
	if got := fn.Parameters[0].Type; got != "String" {
		t.Fatalf("superclass inherited method type = %q, want String", got)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_CacheMissThenHit(t *testing.T) {
	disableAmbientJavaHome(t)

	cache := newFakeBytecodeIndexCache()
	var extractCalls atomic.Int32
	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(PackageDir) string { return "/virtual/jjwt-api.jar" },
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			extractCalls.Add(1)
			return jwtTestClassInfo(), nil
		},
		bytecodeCache: cache,
	}

	graph1, target1, caller1 := newJWTCallGraph()
	if err := resolver.ResolveTypes(graph1, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "1.0.0",
	}}); err != nil {
		t.Fatalf("ResolveTypes first run: %v", err)
	}
	assertJWTGraphResolved(t, graph1, target1, caller1)

	cacheKey := bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@1.0.0")
	if extractCalls.Load() != 1 {
		t.Fatalf("extractClassInfo calls after first run = %d, want 1", extractCalls.Load())
	}
	if len(cache.puts) != 1 || cache.puts[0] != cacheKey {
		t.Fatalf("cache puts = %#v, want [%q]", cache.puts, cacheKey)
	}

	graph2, target2, caller2 := newJWTCallGraph()
	if err := resolver.ResolveTypes(graph2, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "1.0.0",
	}}); err != nil {
		t.Fatalf("ResolveTypes second run: %v", err)
	}
	assertJWTGraphResolved(t, graph2, target2, caller2)

	if extractCalls.Load() != 1 {
		t.Fatalf("extractClassInfo calls after second run = %d, want 1", extractCalls.Load())
	}
	if len(cache.gets) < 2 || cache.gets[1] != cacheKey {
		t.Fatalf("cache gets = %#v, want second get for %q", cache.gets, cacheKey)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_CacheHitAvoidsExtraction(t *testing.T) {
	disableAmbientJavaHome(t)

	cache := newFakeBytecodeIndexCache()
	cacheKey := bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@1.0.0")
	cache.entries[cacheKey] = &CachedBytecodeIndex{
		SchemaVersion: bytecodeCacheSchemaVersion,
		ArtifactKey:   "io.jsonwebtoken:jjwt-api@1.0.0",
		MethodsIndex: map[string][]methodSignature{
			"io.jsonwebtoken.ClaimsMutator.setId": {{
				className:  "ClaimsMutator",
				methodName: "setId",
				paramTypes: []string{"String"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.ClaimsMutator",
			}},
			"io.jsonwebtoken.JwtBuilder.signWith": {{
				className:  "JwtBuilder",
				methodName: "signWith",
				paramTypes: []string{"SignatureAlgorithm", "byte[]"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.JwtBuilder",
			}},
		},
		TypeHierarchy: map[string][]string{
			"io.jsonwebtoken.JwtBuilder": {"io.jsonwebtoken.ClaimsMutator"},
		},
	}

	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(PackageDir) string { return "/virtual/jjwt-api.jar" },
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			t.Fatal("extractClassInfo should not be called on cache hit")
			return nil, nil
		},
		bytecodeCache: cache,
	}

	graph, target, caller := newJWTCallGraph()
	if err := resolver.ResolveTypes(graph, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "1.0.0",
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	assertJWTGraphResolved(t, graph, target, caller)
	if len(cache.puts) != 0 {
		t.Fatalf("cache puts = %#v, want none on hit", cache.puts)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_StaleCacheFallsBackToParsing(t *testing.T) {
	disableAmbientJavaHome(t)

	cache := newFakeBytecodeIndexCache()
	cacheKey := bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@1.0.0")
	cache.entries[cacheKey] = &CachedBytecodeIndex{
		SchemaVersion: bytecodeCacheSchemaVersion - 1,
		ArtifactKey:   "io.jsonwebtoken:jjwt-api@1.0.0",
		MethodsIndex:  map[string][]methodSignature{},
		TypeHierarchy: map[string][]string{},
	}

	var extractCalls atomic.Int32
	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(PackageDir) string { return "/virtual/jjwt-api.jar" },
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			extractCalls.Add(1)
			return jwtTestClassInfo(), nil
		},
		bytecodeCache: cache,
	}

	graph, target, caller := newJWTCallGraph()
	if err := resolver.ResolveTypes(graph, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "1.0.0",
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	assertJWTGraphResolved(t, graph, target, caller)
	if extractCalls.Load() != 1 {
		t.Fatalf("extractClassInfo calls = %d, want 1", extractCalls.Load())
	}
	if len(cache.puts) != 1 || cache.puts[0] != cacheKey {
		t.Fatalf("cache puts = %#v, want refresh for %q", cache.puts, cacheKey)
	}
}

func TestRewriteJavaCallFromIndex_ZeroAritySkipsMismatchedSignature(t *testing.T) {
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			"pkg.(Type).helper#0": {
				ID: FunctionID{Package: "pkg", Type: "Type", Name: "helper#0"},
			},
			"app.run#0": {
				ID: FunctionID{Package: "app", Name: "run#0"},
			},
		},
		Callers: map[string][]string{},
	}
	fn := graph.Functions["app.run#0"]
	call := &FunctionCall{
		Callee: FunctionID{Package: "pkg", Type: "UnresolvedType", Name: "helper#0"},
	}

	index := map[string][]methodSignature{
		"pkg.UnresolvedType.helper": {
			{className: "OtherType", methodName: "helper", fullClass: "pkg.OtherType", paramTypes: []string{"String"}},
			{className: "Type", methodName: "helper", fullClass: "pkg.Type", paramTypes: nil},
		},
	}

	lookup := buildJavaMethodLookup(index)

	if ok := rewriteJavaCallFromIndex(graph, fn, call, lookup, map[string][]string{}); !ok {
		t.Fatal("expected rewriteJavaCallFromIndex to resolve zero-arity overload")
	}
	if call.Callee.Package != "pkg" || call.Callee.Type != "Type" || call.Callee.Name != "helper#0" {
		t.Fatalf("call.Callee = %#v, want pkg.Type.helper#0", call.Callee)
	}
	if callers := graph.Callers["pkg.(Type).helper#0"]; len(callers) != 1 || callers[0] != "app.run#0" {
		t.Fatalf("unexpected callers index: %#v", graph.Callers)
	}
}

func BenchmarkLookupJavaMethodSignatures_SimpleFallback(b *testing.B) {
	index := make(map[string][]methodSignature, 20000)
	for i := 0; i < 20000; i++ {
		fullClass := fmt.Sprintf("pkg%d.Builder", i)
		index[fullClass+".signWith"] = []methodSignature{{
			className:  "Builder",
			methodName: "signWith",
			paramTypes: []string{"String", "byte[]"},
			returnType: "Builder",
			fullClass:  fullClass,
		}}
	}

	lookup := buildJavaMethodLookup(index)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sigs := lookupJavaMethodSignatures(lookup, "", "Builder", "signWith", 2)
		if len(sigs) != 20000 {
			b.Fatalf("lookup returned %d signatures, want 20000", len(sigs))
		}
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_CorruptedCacheFallsBackToParsing(t *testing.T) {
	disableAmbientJavaHome(t)

	dir := t.TempDir()
	cache, err := NewDiskBytecodeIndexCacheWithDir(dir)
	if err != nil {
		t.Fatalf("NewDiskBytecodeIndexCacheWithDir: %v", err)
	}

	cacheKey := bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@1.0.0")
	cachePath := filepath.Join(dir, bytecodeCacheKeyToFilename(cacheKey))
	if err := os.WriteFile(cachePath, []byte("{not-json"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var extractCalls atomic.Int32
	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(PackageDir) string { return "/virtual/jjwt-api.jar" },
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			extractCalls.Add(1)
			return jwtTestClassInfo(), nil
		},
		bytecodeCache: cache,
	}

	graph, target, caller := newJWTCallGraph()
	if err := resolver.ResolveTypes(graph, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "1.0.0",
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	assertJWTGraphResolved(t, graph, target, caller)
	if extractCalls.Load() != 1 {
		t.Fatalf("extractClassInfo calls = %d, want 1", extractCalls.Load())
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_MixesCachedAndParsedJARs(t *testing.T) {
	disableAmbientJavaHome(t)

	cache := newFakeBytecodeIndexCache()
	cache.entries[bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-api@1.0.0")] = &CachedBytecodeIndex{
		SchemaVersion: bytecodeCacheSchemaVersion,
		ArtifactKey:   "io.jsonwebtoken:jjwt-api@1.0.0",
		MethodsIndex: map[string][]methodSignature{
			"io.jsonwebtoken.JwtBuilder.signWith": {{
				className:  "JwtBuilder",
				methodName: "signWith",
				paramTypes: []string{"SignatureAlgorithm", "byte[]"},
				returnType: "JwtBuilder",
				fullClass:  "io.jsonwebtoken.JwtBuilder",
			}},
		},
		TypeHierarchy: map[string][]string{
			"io.jsonwebtoken.JwtBuilder": {"io.jsonwebtoken.ClaimsMutator"},
		},
	}

	var extractCalls atomic.Int32
	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string {
			return joinVirtualPath(strings.ReplaceAll(root.ImportPath, ":", "-") + "-" + root.Version + ".jar")
		},
		extractClassInfo: func(jarPath string) ([]*classFileInfo, error) {
			extractCalls.Add(1)
			switch {
			case strings.Contains(jarPath, "jjwt-api"):
				t.Fatalf("extractClassInfo should not parse cached jar %q", jarPath)
				return nil, nil
			case strings.Contains(jarPath, "jjwt-impl"):
				return []*classFileInfo{{
					className:     "MacProvider",
					fullClassName: "io.jsonwebtoken.impl.MacProvider",
					methods: []methodSignature{{
						className:  "MacProvider",
						methodName: "generateKey",
						paramTypes: []string{"SignatureAlgorithm"},
						returnType: "SecretKey",
						fullClass:  "io.jsonwebtoken.impl.MacProvider",
					}},
				}}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		bytecodeCache: cache,
	}

	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			"io.jsonwebtoken.JwtBuilder.signWith#2": {
				ID:         FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith#2"},
				Parameters: []FunctionParameter{{Type: "K"}, {Type: "byte[]"}},
			},
			"io.jsonwebtoken.impl.MacProvider.generateKey#1": {
				ID:         FunctionID{Package: "io.jsonwebtoken.impl", Type: "MacProvider", Name: "generateKey#1"},
				Parameters: []FunctionParameter{{Type: "T"}},
			},
		},
		Callers: map[string][]string{},
	}

	if err := resolver.ResolveTypes(graph, []PackageDir{
		{ImportPath: "io.jsonwebtoken:jjwt-api", Version: "1.0.0"},
		{ImportPath: "io.jsonwebtoken:jjwt-impl", Version: "1.0.0"},
	}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	if extractCalls.Load() != 1 {
		t.Fatalf("extractClassInfo calls = %d, want 1", extractCalls.Load())
	}
	if got := graph.Functions["io.jsonwebtoken.JwtBuilder.signWith#2"].Parameters[0].Type; got != "SignatureAlgorithm" {
		t.Fatalf("cached declaration was not enriched, got %q", got)
	}
	if got := graph.Functions["io.jsonwebtoken.impl.MacProvider.generateKey#1"].Parameters[0].Type; got != "SignatureAlgorithm" {
		t.Fatalf("parsed declaration was not enriched, got %q", got)
	}
	if len(cache.puts) != 1 || cache.puts[0] != bytecodeCacheStorageKey("io.jsonwebtoken:jjwt-impl@1.0.0") {
		t.Fatalf("cache puts = %#v, want impl jar only", cache.puts)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_IndexesPlatformSignaturesWithoutJARs(t *testing.T) {
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			"example.app.(Digests).sha256#1": {
				ID: FunctionID{Package: "example.app", Type: "Digests", Name: "sha256#1"},
				Calls: []FunctionCall{{
					Callee:    FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"},
					Arguments: []string{`"SHA-256"`},
				}},
			},
		},
		Callers: map[string][]string{},
	}

	resolver := &JavaBytecodeTypeResolver{
		resolvePlatformSource: func() (*javaPlatformIndexSource, error) {
			return &javaPlatformIndexSource{
				RuntimeVersion:  "17.0.12",
				SignatureSource: "jmods",
				ArchivePaths:    []string{"/virtual/java.base.jmod"},
				ArtifactKey:     "jdk-platform@17.0.12:jmods",
			}, nil
		},
		extractClassInfo: func(path string) ([]*classFileInfo, error) {
			if path != "/virtual/java.base.jmod" {
				t.Fatalf("unexpected archive path %q", path)
			}
			return []*classFileInfo{{
				className:     "MessageDigest",
				fullClassName: "java.security.MessageDigest",
				methods: []methodSignature{{
					className:  "MessageDigest",
					methodName: "getInstance",
					paramTypes: []string{"java.lang.String"},
					returnType: "java.security.MessageDigest",
					fullClass:  "java.security.MessageDigest",
				}},
			}}, nil
		},
	}

	if err := resolver.ResolveTypes(graph, nil); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	key := ExternalMethodSignatureKey(FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"})
	signatures := graph.ExternalMethodSignatures[key]
	if len(signatures) != 1 {
		t.Fatalf("graph.ExternalMethodSignatures[%q] = %#v, want one signature", key, signatures)
	}
	if got := signatures[0].ParameterTypes; len(got) != 1 || got[0] != "java.lang.String" {
		t.Fatalf("platform parameter types = %#v, want [java.lang.String]", got)
	}
	if graph.JavaPlatformSignatures == nil {
		t.Fatal("expected JavaPlatformSignatures metadata")
	}
	if !graph.JavaPlatformSignatures.SignaturesUsed {
		t.Fatalf("expected platform signatures to be used, got %#v", graph.JavaPlatformSignatures)
	}
	if graph.JavaPlatformSignatures.RequestedMajor != javaruntime.AutoMajor {
		t.Fatalf("RequestedMajor = %q, want auto", graph.JavaPlatformSignatures.RequestedMajor)
	}
	if graph.JavaPlatformSignatures.RuntimeVersion != "17.0.12" || graph.JavaPlatformSignatures.SignatureSource != "jmods" {
		t.Fatalf("unexpected platform signature metadata: %#v", graph.JavaPlatformSignatures)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_SoftFallbackWhenPlatformUnavailable(t *testing.T) {
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{},
		Callers:   map[string][]string{},
	}

	resolver := &JavaBytecodeTypeResolver{
		resolvePlatformSource: func() (*javaPlatformIndexSource, error) {
			return &javaPlatformIndexSource{
				SignatureSource:   "unavailable",
				UnavailableReason: "java_home_not_set",
			}, nil
		},
	}

	if err := resolver.ResolveTypes(graph, nil); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	if graph.JavaPlatformSignatures == nil {
		t.Fatal("expected JavaPlatformSignatures metadata")
	}
	if graph.JavaPlatformSignatures.SignaturesUsed {
		t.Fatalf("expected soft fallback metadata, got %#v", graph.JavaPlatformSignatures)
	}
	if graph.JavaPlatformSignatures.UnavailableReason != "java_home_not_set" {
		t.Fatalf("UnavailableReason = %q, want java_home_not_set", graph.JavaPlatformSignatures.UnavailableReason)
	}
	if graph.JavaPlatformSignatures.RequestedMajor != javaruntime.AutoMajor {
		t.Fatalf("RequestedMajor = %q, want auto", graph.JavaPlatformSignatures.RequestedMajor)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_FailsForInvalidExplicitJDKHome(t *testing.T) {
	jdkHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(jdkHome, "release"), []byte("JAVA_VERSION=\"17.0.12\"\n"), 0o600); err != nil {
		t.Fatalf("write release: %v", err)
	}

	runtimeConfig, err := javaruntime.NewConfig("21", map[string]string{"21": jdkHome})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{},
		Callers:   map[string][]string{},
	}
	resolver := NewJavaBytecodeTypeResolver(runtimeConfig)

	err = resolver.ResolveTypes(graph, nil)
	if err == nil {
		t.Fatal("expected explicit JDK mismatch to fail")
	}
	if graph.JavaPlatformSignatures == nil {
		t.Fatal("expected JavaPlatformSignatures metadata")
	}
	if graph.JavaPlatformSignatures.RequestedMajor != "21" {
		t.Fatalf("RequestedMajor = %q, want 21", graph.JavaPlatformSignatures.RequestedMajor)
	}
	if graph.JavaPlatformSignatures.UnavailableReason != "invalid_configured_java_home" {
		t.Fatalf("UnavailableReason = %q, want invalid_configured_java_home", graph.JavaPlatformSignatures.UnavailableReason)
	}
}

func TestJavaBytecodeTypeResolver_ResolveTypes_DeduplicatesPlatformAndJarSignatures(t *testing.T) {
	graph, target, caller := newJWTCallGraph()

	resolver := &JavaBytecodeTypeResolver{
		resolveJARPath: func(PackageDir) string { return "/virtual/jjwt-api.jar" },
		resolvePlatformSource: func() (*javaPlatformIndexSource, error) {
			return &javaPlatformIndexSource{
				RuntimeVersion:  "17.0.12",
				SignatureSource: "jmods",
				ArchivePaths:    []string{"/virtual/java.base.jmod"},
				ArtifactKey:     "jdk-platform@17.0.12:jmods",
			}, nil
		},
		extractClassInfo: func(path string) ([]*classFileInfo, error) {
			switch path {
			case "/virtual/jjwt-api.jar", "/virtual/java.base.jmod":
				return jwtTestClassInfo(), nil
			default:
				return nil, os.ErrNotExist
			}
		},
	}

	if err := resolver.ResolveTypes(graph, []PackageDir{{
		ImportPath: "io.jsonwebtoken:jjwt-api",
		Version:    "1.0.0",
	}}); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}

	assertJWTGraphResolved(t, graph, target, caller)
}
