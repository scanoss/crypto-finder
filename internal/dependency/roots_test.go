package dependency

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// mkdirs creates every named directory relative to root, for fixtures whose
// point is a directory that holds no file.
func mkdirs(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, rel := range dirs {
		if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func rootRels(discovery RootDiscovery) []string {
	rels := make([]string, 0, len(discovery.Roots))
	for _, root := range discovery.Roots {
		rels = append(rels, root.Rel)
	}
	return rels
}

func testBounds() rootDiscoveryBounds {
	return rootDiscoveryBounds{
		maxRoots:   maxResolutionRoots,
		maxDepth:   maxRootDiscoveryDepth,
		maxEntries: maxRootDiscoveryWalk,
	}
}

func TestHasRootManifest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		files     map[string]string
		dirs      []string
		ecosystem string
		want      bool
	}{
		{name: "go.mod is a go root", files: map[string]string{"go.mod": "module x\n"}, ecosystem: "go", want: true},
		{name: "a directory named go.mod is not", dirs: []string{"go.mod"}, ecosystem: "go", want: false},
		{name: "pom.xml is a java root", files: map[string]string{"pom.xml": "<project/>"}, ecosystem: ecosystemJava, want: true},
		{name: "build.gradle.kts is a java root", files: map[string]string{"build.gradle.kts": ""}, ecosystem: ecosystemJava, want: true},
		{name: "settings.gradle is a java root", files: map[string]string{"settings.gradle": ""}, ecosystem: ecosystemJava, want: true},
		{name: "Cargo.toml is a rust root", files: map[string]string{"Cargo.toml": ""}, ecosystem: "rust", want: true},
		{
			name:      "node needs the lockfile too",
			files:     map[string]string{npmManifest: `{"name":"x"}`},
			ecosystem: ecosystemNode,
			want:      false,
		},
		{
			name:      "node with both files is a root",
			files:     map[string]string{npmManifest: `{"name":"x"}`, npmLockfile: `{"lockfileVersion":3}`},
			ecosystem: ecosystemNode,
			want:      true,
		},
		{
			name:      "python is never manifest-rooted",
			files:     map[string]string{"pyproject.toml": "", "requirements.txt": ""},
			ecosystem: "python",
			want:      false,
		},
		{name: "an unknown ecosystem is never rooted", files: map[string]string{"pom.xml": "<project/>"}, ecosystem: "cobol", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			files := tt.files
			if files == nil {
				files = map[string]string{"placeholder.txt": ""}
			}
			root := writeTree(t, files)
			mkdirs(t, root, tt.dirs...)
			if got := HasRootManifest(root, tt.ecosystem); got != tt.want {
				t.Errorf("HasRootManifest(%s) = %v, want %v", tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestResolutionRoots_GateClosedWhenRootHasManifest(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"pom.xml":              "<project/>",
		"services/a/pom.xml":   "<project/>",
		"services/b/pom.xml":   "<project/>",
		"src/main/java/A.java": "class A {}",
	})

	got := ResolutionRoots(root, ecosystemJava, nil)
	if got.Searched {
		t.Error("Searched = true, want false: a root that resolves today must not be walked")
	}
	if got.Roots != nil {
		t.Errorf("Roots = %v, want nil", rootRels(got))
	}
}

func TestResolutionRoots_GateClosedForPython(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"services/a/pyproject.toml":   "",
		"services/a/app.py":           "import hashlib",
		"services/b/requirements.txt": "cryptography==42.0.0",
	})

	got := ResolutionRoots(root, "python", nil)
	if got.Searched || got.Roots != nil {
		t.Errorf("ResolutionRoots(python) = %+v, want the closed gate: PipResolver resolves from the interpreter", got)
	}
}

func TestResolutionRoots_GateClosedForAFileTarget(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{"services/a/pom.xml": "<project/>", "note.txt": ""})

	got := ResolutionRoots(filepath.Join(root, "note.txt"), ecosystemJava, nil)
	if got.Searched || got.Roots != nil {
		t.Errorf("ResolutionRoots(file) = %+v, want the closed gate", got)
	}
}

func TestResolutionRoots_FindsRootsBelowAManifestlessRoot(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"services/ledger/pom.xml":                      "<project/>",
		"services/ledger/src/main/java/app/Use.java":   "class Use {}",
		"services/gateway/build.gradle":                "",
		"services/gateway/src/main/java/app/Edge.java": "class Edge {}",
		"README.md": "",
	})

	got := ResolutionRoots(root, ecosystemJava, nil)
	if !got.Searched {
		t.Fatal("Searched = false, want true")
	}
	want := []string{"services/gateway", "services/ledger"}
	if rels := rootRels(got); !reflect.DeepEqual(rels, want) {
		t.Fatalf("Roots = %v, want %v", rels, want)
	}
	if got.Found != 2 || got.Truncated || got.Abandoned {
		t.Errorf("Found/Truncated/Abandoned = %d/%v/%v, want 2/false/false", got.Found, got.Truncated, got.Abandoned)
	}

	// One walk feeds both build tools. JavaResolver.Resolve calls
	// DetectJavaBuildTool per invocation, so the mix needs no Java-specific code.
	wantTool := map[string]string{"services/gateway": javaBuildToolGradle, "services/ledger": javaBuildToolMaven}
	for _, discovered := range got.Roots {
		tool, err := DetectJavaBuildTool(discovered.Dir)
		if err != nil {
			t.Fatalf("DetectJavaBuildTool(%s): %v", discovered.Rel, err)
		}
		if tool != wantTool[discovered.Rel] {
			t.Errorf("DetectJavaBuildTool(%s) = %q, want %q", discovered.Rel, tool, wantTool[discovered.Rel])
		}
	}
}

func TestResolutionRoots_DoesNotDescendIntoARoot(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"a/pom.xml":     "<project/>",
		"a/sub/pom.xml": "<project/>",
	})

	got := ResolutionRoots(root, ecosystemJava, nil)
	if rels := rootRels(got); !reflect.DeepEqual(rels, []string{"a"}) {
		t.Errorf("Roots = %v, want [a]: the root's own resolver owns its declared sub-modules", rels)
	}
}

func TestResolutionRoots_PrunesWhatTheScanSkips(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"node_modules/x/pom.xml":        "<project/>",
		"target/gen/pom.xml":            "<project/>",
		"build/out/pom.xml":             "<project/>",
		".hidden/pom.xml":               "<project/>",
		"src/test/resources/fx/pom.xml": "<project/>",
		"testdata/projects/a/pom.xml":   "<project/>",
		"fixtures/b/pom.xml":            "<project/>",
	})

	got := ResolutionRoots(root, ecosystemJava, nil)
	if !got.Searched {
		t.Fatal("Searched = false, want true")
	}
	if len(got.Roots) != 0 {
		t.Errorf("Roots = %v, want none: every manifest here is behind a skipped directory", rootRels(got))
	}
}

// The matcher is asked about a directory's own name. Passing its absolute path
// would make a scan root that merely sits below a skipped name prune its whole
// tree, because a gitignore pattern matches any segment.
func TestResolutionRoots_SkippedNameInTheScanRootAncestryDoesNotPrune(t *testing.T) {
	t.Parallel()

	tmp := writeTree(t, map[string]string{"build/workspace/services/ledger/pom.xml": "<project/>"})
	root := filepath.Join(tmp, "build", "workspace")

	got := ResolutionRoots(root, ecosystemJava, nil)
	if rels := rootRels(got); !reflect.DeepEqual(rels, []string{"services/ledger"}) {
		t.Errorf("Roots = %v, want [services/ledger]", rels)
	}
}

func TestResolutionRoots_NodePackageJSONWithoutLockfileIsNotARoot(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"src/package.json": `{"type":"module"}`,
		"src/index.js":     "export const x = 1",
	})

	got := ResolutionRoots(root, ecosystemNode, nil)
	if len(got.Roots) != 0 {
		t.Errorf("Roots = %v, want none: NpmResolver needs a lockfile and src/ is ordinary layout", rootRels(got))
	}
}

// The cap is pinned on both sides. A manifest one level below it must be
// unreachable with nothing above it to stop the descent first, which is the
// only arrangement that reaches the depth branch at all.
func TestResolutionRoots_DepthCapStopsBelowTheCap(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{"a/b/c/d/e/pom.xml": "<project/>"})

	bounds := testBounds()
	bounds.maxDepth = 4
	got := resolutionRoots(root, ecosystemJava, nil, bounds)
	if !got.Searched {
		t.Fatal("Searched = false, want true")
	}
	if rels := rootRels(got); len(rels) != 0 {
		t.Errorf("Roots = %v, want none: a/b/c/d/e sits at depth 5", rels)
	}
}

func TestResolutionRoots_DepthCapFindsAManifestAtTheCap(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{"a/b/c/d/pom.xml": "<project/>"})

	bounds := testBounds()
	bounds.maxDepth = 4
	got := resolutionRoots(root, ecosystemJava, nil, bounds)
	if rels := rootRels(got); !reflect.DeepEqual(rels, []string{"a/b/c/d"}) {
		t.Errorf("Roots = %v, want [a/b/c/d]: depth 4 is the last depth that qualifies", rels)
	}
}

func TestResolutionRoots_RootCapTruncatesShallowestFirst(t *testing.T) {
	t.Parallel()

	files := map[string]string{}
	for i := 1; i <= 9; i++ {
		files["deep/m"+strconv.Itoa(i)+"/pom.xml"] = "<project/>"
	}
	for i := 1; i <= 8; i++ {
		files["s"+strconv.Itoa(i)+"/pom.xml"] = "<project/>"
	}
	root := writeTree(t, files)

	bounds := testBounds()
	bounds.maxRoots = 3
	got := resolutionRoots(root, ecosystemJava, nil, bounds)

	if got.Found != 17 || !got.Truncated {
		t.Fatalf("Found/Truncated = %d/%v, want 17/true", got.Found, got.Truncated)
	}
	want := []string{"s1", "s2", "s3"}
	if rels := rootRels(got); !reflect.DeepEqual(rels, want) {
		t.Errorf("Roots = %v, want %v: shallowest first, then lexical", rels, want)
	}
}

func TestResolutionRoots_EntryCapAbandons(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{"a/pom.xml": "<project/>", "b/pom.xml": "<project/>"})

	bounds := testBounds()
	bounds.maxEntries = 1
	got := resolutionRoots(root, ecosystemJava, nil, bounds)

	if !got.Abandoned {
		t.Error("Abandoned = false, want true")
	}
	if len(got.Roots) != 0 {
		t.Errorf("Roots = %v, want none", rootRels(got))
	}
}

func TestResolutionRoots_UnreadableDirIsCountedAndSiblingsSurvive(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root reads a 0o000 directory, so the error path cannot be provoked")
	}
	root := writeTree(t, map[string]string{
		"noread/inner/pom.xml": "<project/>",
		"ok/pom.xml":           "<project/>",
	})
	blocked := filepath.Join(root, "noread")
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	got := resolutionRoots(root, ecosystemJava, nil, testBounds())
	if got.Unreadable != 1 {
		t.Errorf("Unreadable = %d, want 1", got.Unreadable)
	}
	if rels := rootRels(got); !reflect.DeepEqual(rels, []string{"ok"}) {
		t.Errorf("Roots = %v, want [ok]: a partial answer is more coverage than none", rels)
	}
}

// The Go toolchain finds its own manifest upward: GoResolver sets only cmd.Dir
// and `go list -m -json all` walks the ancestors. A directory inside a module
// therefore resolves today, and opening the gate there would resolve a nested
// tooling module instead and lose the parent's whole dependency list.
func TestResolutionRoots_GateClosedForAGoDirInsideAModule(t *testing.T) {
	t.Parallel()

	tmp := writeTree(t, map[string]string{
		"go.mod":               "module example.com/parent\n",
		"sub/s.go":             "package sub",
		"sub/tools/gen/go.mod": "module example.com/parent/sub/tools/gen\n",
	})

	got := ResolutionRoots(filepath.Join(tmp, "sub"), "go", nil)
	if got.Searched || got.Roots != nil {
		t.Errorf("ResolutionRoots = %+v, want the closed gate: go resolves example.com/parent from sub/", got)
	}
}

func TestResolutionRoots_GateClosedForAGoWorkspaceRoot(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"go.work":  "go 1.25\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod": "module example.com/a\n",
		"b/go.mod": "module example.com/b\n",
	})

	got := ResolutionRoots(root, "go", nil)
	if got.Searched || got.Roots != nil {
		t.Errorf("ResolutionRoots = %+v, want the closed gate: go.work resolves the whole workspace", got)
	}
}

func TestResolutionRoots_FindsGoRootsWithNoModuleAbove(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"services/a/go.mod": "module example.com/a\n",
		"services/b/go.mod": "module example.com/b\n",
	})

	got := ResolutionRoots(root, "go", nil)
	want := []string{"services/a", "services/b"}
	if rels := rootRels(got); !reflect.DeepEqual(rels, want) {
		t.Errorf("Roots = %v, want %v: nothing above a temp dir is a Go module", rels, want)
	}
}

// filepath.WalkDir hands entries straight from ReadDir and never follows a
// symlink, so a deploy layout like current -> releases/2026-09 would otherwise
// walk a single non-directory entry and discover nothing.
func TestResolutionRoots_ASymlinkedScanRootIsDereferenced(t *testing.T) {
	t.Parallel()

	tmp := writeTree(t, map[string]string{"releases/2026-09/services/ledger/pom.xml": "<project/>"})
	link := filepath.Join(tmp, "current")
	if err := os.Symlink(filepath.Join(tmp, "releases", "2026-09"), link); err != nil {
		t.Skipf("os.Symlink is unavailable on this platform: %v", err)
	}

	got := ResolutionRoots(link, ecosystemJava, nil)
	if rels := rootRels(got); !reflect.DeepEqual(rels, []string{"services/ledger"}) {
		t.Errorf("Roots = %v, want [services/ledger]", rels)
	}
}

// Resolving a root runs mvn, gradle, cargo or go inside it, so a directory the
// user excluded must never become one.
func TestResolutionRoots_UserSkipPatternsPruneByRelativePath(t *testing.T) {
	t.Parallel()

	root := writeTree(t, map[string]string{
		"third_party/legacy/pom.xml": "<project/>",
		"services/ledger/pom.xml":    "<project/>",
	})

	got := ResolutionRoots(root, ecosystemJava, []string{"third_party/**"})
	if rels := rootRels(got); !reflect.DeepEqual(rels, []string{"services/ledger"}) {
		t.Errorf("Roots = %v, want [services/ledger]: third_party/** excluded the other root", rels)
	}
}

// User patterns are matched against the path relative to the scan root, which
// never holds the scan root's own ancestry, so a pattern naming an ancestor
// segment cannot prune the whole tree.
func TestResolutionRoots_UserSkipPatternInTheScanRootAncestryDoesNotPrune(t *testing.T) {
	t.Parallel()

	tmp := writeTree(t, map[string]string{"third_party/workspace/services/ledger/pom.xml": "<project/>"})
	root := filepath.Join(tmp, "third_party", "workspace")

	got := ResolutionRoots(root, ecosystemJava, []string{"third_party/**"})
	if rels := rootRels(got); !reflect.DeepEqual(rels, []string{"services/ledger"}) {
		t.Errorf("Roots = %v, want [services/ledger]", rels)
	}
}

func TestMergeRootResolutions_LeavesTheScanRootUnnamedAndOneMemberPerRoot(t *testing.T) {
	t.Parallel()

	merged := MergeRootResolutions([]RootResolution{
		{
			Root:   discoveredRoot{Dir: "/work/monorepo/services/ledger", Rel: "services/ledger", Depth: 2},
			Result: &ResolveResult{RootModule: "com.acme.ledger"},
		},
		{
			Root:   discoveredRoot{Dir: "/work/monorepo/services/gateway", Rel: "services/gateway", Depth: 2},
			Result: &ResolveResult{RootModule: ""},
		},
	})

	if merged.RootModule != "" {
		t.Errorf("RootModule = %q, want empty: the scan root declares no module and its directory name is not one", merged.RootModule)
	}
	want := []WorkspaceMember{
		{Name: "com.acme.ledger", Dir: "/work/monorepo/services/ledger"},
		{Name: "gateway", Dir: "/work/monorepo/services/gateway"},
	}
	if !reflect.DeepEqual(merged.WorkspaceMembers, want) {
		t.Errorf("WorkspaceMembers = %+v, want %+v", merged.WorkspaceMembers, want)
	}
}

func TestMergeRootResolutions_ChildMembersReplaceTheChild(t *testing.T) {
	t.Parallel()

	merged := MergeRootResolutions([]RootResolution{{
		Root: discoveredRoot{Dir: "/work/monorepo/services/ledger", Rel: "services/ledger", Depth: 2},
		Result: &ResolveResult{
			RootModule: "com.acme",
			WorkspaceMembers: []WorkspaceMember{
				{Name: "com.acme:api", Dir: "/work/monorepo/services/ledger/api"},
				{Name: "com.acme:core", Dir: "/work/monorepo/services/ledger/core"},
			},
		},
	}})

	want := []WorkspaceMember{
		{Name: "com.acme:api", Dir: "/work/monorepo/services/ledger/api"},
		{Name: "com.acme:core", Dir: "/work/monorepo/services/ledger/core"},
	}
	if !reflect.DeepEqual(merged.WorkspaceMembers, want) {
		t.Errorf("WorkspaceMembers = %+v, want %+v: an aggregator listed beside its own modules parses one directory twice", merged.WorkspaceMembers, want)
	}
}

func TestMergeRootResolutions_DependenciesAreConcatenatedNotDeduped(t *testing.T) {
	t.Parallel()

	shared := Dependency{Module: "org.apache.commons:commons-lang3", Version: "3.12.0", Dir: "/cache/lang3"}
	merged := MergeRootResolutions([]RootResolution{
		{Root: discoveredRoot{Dir: "/work/monorepo/a"}, Result: &ResolveResult{RootModule: "a", Dependencies: []Dependency{shared}}},
		{Root: discoveredRoot{Dir: "/work/monorepo/b"}, Result: &ResolveResult{RootModule: "b", Dependencies: []Dependency{shared}}},
	})

	// engine.canonicalDependencies owns deduplication by module@version, and it
	// already prefers the copy that has a Dir. Repeating that rule here would
	// duplicate the decision in two packages.
	if len(merged.Dependencies) != 2 {
		t.Errorf("len(Dependencies) = %d, want 2", len(merged.Dependencies))
	}
}

func TestMergeRootResolutions_GraphsAreUnionedDedupedAndSorted(t *testing.T) {
	t.Parallel()

	merged := MergeRootResolutions([]RootResolution{
		{
			Root: discoveredRoot{Dir: "/work/monorepo/a"},
			Result: &ResolveResult{
				RootModule:     "a",
				Graph:          map[string][]string{"root": {"zlib", "bouncy"}},
				VersionedGraph: map[string][]Ref{"root": {{Module: "zlib", Version: "1.0"}}},
			},
		},
		{
			Root: discoveredRoot{Dir: "/work/monorepo/b"},
			Result: &ResolveResult{
				RootModule:     "b",
				Graph:          map[string][]string{"root": {"bouncy", "argon"}},
				VersionedGraph: map[string][]Ref{"root": {{Module: "zlib", Version: "1.0"}, {Module: "argon", Version: "2.0"}}},
			},
		},
	})

	wantGraph := map[string][]string{"root": {"argon", "bouncy", "zlib"}}
	if !reflect.DeepEqual(merged.Graph, wantGraph) {
		t.Errorf("Graph = %v, want %v", merged.Graph, wantGraph)
	}
	wantVersioned := map[string][]Ref{"root": {{Module: "argon", Version: "2.0"}, {Module: "zlib", Version: "1.0"}}}
	if !reflect.DeepEqual(merged.VersionedGraph, wantVersioned) {
		t.Errorf("VersionedGraph = %v, want %v", merged.VersionedGraph, wantVersioned)
	}
}

func TestMergeRootResolutions_NoResolutionsLeavesTheScanRootUnnamed(t *testing.T) {
	t.Parallel()

	merged := MergeRootResolutions(nil)
	if merged.RootModule != "" {
		t.Errorf("RootModule = %q, want empty: the scan root declares no module and its directory name is not one", merged.RootModule)
	}
	if merged.Graph == nil || merged.VersionedGraph == nil {
		t.Error("Graph and VersionedGraph must be non-nil maps")
	}
}
