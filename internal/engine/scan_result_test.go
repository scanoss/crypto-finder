package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
)

func TestEnsureFindingSources(t *testing.T) {
	report := &entities.InterimReport{
		Findings: []entities.Finding{
			{
				FilePath:            "direct.go",
				CryptographicAssets: []entities.CryptographicAsset{{Source: ""}},
			},
			{
				FilePath:            "dep.go",
				CryptographicAssets: []entities.CryptographicAsset{{Source: "dependency"}},
			},
		},
	}

	EnsureFindingSources(report)

	if got := report.Findings[0].CryptographicAssets[0].Source; got != "direct" {
		t.Fatalf("direct source = %q, want direct", got)
	}
	if got := report.Findings[1].CryptographicAssets[0].Source; got != "dependency" {
		t.Fatalf("dependency source = %q, want dependency", got)
	}
}

func TestEnrichDirectFindingPURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		filePath  string
		ecosystem string
		rulePURL  string
		resolved  *dependency.ResolveResult
		want      string
	}{
		{
			name:     "direct dependency",
			filePath: "main.go",
			resolved: &dependency.ResolveResult{
				RootModule: "example.com/app",
				VersionedGraph: map[string][]dependency.Ref{
					"example.com/app": {{Module: "github.com/acme/lib", Version: "v1.2.3"}},
				},
			},
			want: "pkg:golang/github.com/acme/lib@v1.2.3",
		},
		{
			name:      "maven group root resolves artifact graph",
			filePath:  "Main.java",
			ecosystem: "java",
			rulePURL:  "pkg:maven/org.example/lib",
			resolved: &dependency.ResolveResult{
				RootModule: "com.acme",
				VersionedGraph: map[string][]dependency.Ref{
					"com.acme:app@1.0.0":    {{Module: "org.example:lib", Version: "2.0.0"}},
					"org.example:lib@2.0.0": {{Module: "org.example:transitive", Version: "3.0.0"}},
				},
			},
			want: "pkg:maven/org.example/lib@2.0.0",
		},
		{
			name:     "transitive dependency stays versionless",
			filePath: "main.go",
			resolved: &dependency.ResolveResult{
				RootModule: "example.com/app",
				VersionedGraph: map[string][]dependency.Ref{
					"example.com/app": {{Module: "github.com/acme/wrapper", Version: "v1.0.0"}},
				},
			},
			want: "pkg:golang/github.com/acme/lib",
		},
		{
			name:     "ambiguous versions stay versionless",
			filePath: "main.go",
			resolved: &dependency.ResolveResult{
				RootModule: "example.com/app",
				VersionedGraph: map[string][]dependency.Ref{
					"example.com/app": {
						{Module: "github.com/acme/lib", Version: "v1.2.3"},
						{Module: "github.com/acme/lib", Version: "v1.2.4"},
					},
				},
			},
			want: "pkg:golang/github.com/acme/lib",
		},
		{
			name:     "workspace member uses its direct graph",
			filePath: "service/main.go",
			resolved: &dependency.ResolveResult{
				RootModule:       "example.com/root",
				WorkspaceMembers: []dependency.WorkspaceMember{{Name: "service", Dir: "/workspace/service"}},
				VersionedGraph: map[string][]dependency.Ref{
					"service": {{Module: "github.com/acme/lib", Version: "v2.0.0"}},
				},
			},
			want: "pkg:golang/github.com/acme/lib@v2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rulePURL := tt.rulePURL
			if rulePURL == "" {
				rulePURL = "pkg:golang/github.com/acme/lib"
			}
			report := &entities.InterimReport{Findings: []entities.Finding{{
				FilePath: tt.filePath,
				CryptographicAssets: []entities.CryptographicAsset{{
					PURL: rulePURL,
				}},
			}}}
			target := "/workspace"
			// The workspace case intentionally exercises owningModule; single-project
			// cases ignore target and use RootModule directly.
			ecosystem := tt.ecosystem
			if ecosystem == "" {
				ecosystem = "go"
			}
			enrichDirectFindingPURLs(report, target, tt.resolved, ecosystem)
			if got := report.Findings[0].CryptographicAssets[0].PURL; got != tt.want {
				t.Fatalf("PURL = %q, want %q", got, tt.want)
			}
		})
	}
}

// writeRepoTree materializes a fixture repository: every key is a path
// relative to the root, every value its contents.
func writeRepoTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// recordingResolver answers per directory and remembers the order it was asked.
type recordingResolver struct {
	ecosystem string
	calls     []string
	answer    func(dir string) (*dependency.ResolveResult, error)
}

func (r *recordingResolver) Resolve(_ context.Context, targetDir string) (*dependency.ResolveResult, error) {
	r.calls = append(r.calls, targetDir)
	return r.answer(targetDir)
}

func (r *recordingResolver) Ecosystem() string { return r.ecosystem }

// CanResolve answers true because only the CLI gate consults it; resolveScanRoot,
// which these tests exercise, selects roots without asking the resolver.
func (r *recordingResolver) CanResolve(string) bool { return true }

func TestResolveScanRoot_RootManifestResolvesAtTarget(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"go.mod":            "module example.com/root\n",
		"services/a/go.mod": "module example.com/a\n",
		"services/a/a.go":   "package a",
	})
	resolver := &recordingResolver{ecosystem: "go", answer: func(_ string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "example.com/root"}, nil
	}}
	resolved, dirs, err := resolveScanRoot(context.Background(), resolver, root, nil)
	if err != nil {
		t.Fatalf("resolveScanRoot: %v", err)
	}
	if !reflect.DeepEqual(resolver.calls, []string{root}) {
		t.Fatalf("Resolve calls = %v, want exactly the scan root %q", resolver.calls, root)
	}
	if !reflect.DeepEqual(dirs, []string{root}) {
		t.Errorf("resolved dirs = %v, want the scan root %q", dirs, root)
	}
	if resolved.RootModule != "example.com/root" {
		t.Errorf("RootModule = %q, want the resolver's own answer untouched", resolved.RootModule)
	}
}

func TestResolveScanRoot_DiscoveredRootsAreResolvedAndMerged(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"services/gateway/pom.xml": "<project/>",
		"services/ledger/pom.xml":  "<project/>",
	})
	resolver := &recordingResolver{ecosystem: "java", answer: func(dir string) (*dependency.ResolveResult, error) {
		name := filepath.Base(dir)
		return &dependency.ResolveResult{
			RootModule:   "com.acme." + name,
			Dependencies: []dependency.Dependency{{Module: "com.acme:" + name + "-dep", Version: "1.0", Dir: dir}},
		}, nil
	}}
	resolved, dirs, err := resolveScanRoot(context.Background(), resolver, root, nil)
	if err != nil {
		t.Fatalf("resolveScanRoot: %v", err)
	}

	wantCalls := []string{filepath.Join(root, "services", "gateway"), filepath.Join(root, "services", "ledger")}
	if !reflect.DeepEqual(resolver.calls, wantCalls) {
		t.Fatalf("Resolve calls = %v, want %v", resolver.calls, wantCalls)
	}
	if !reflect.DeepEqual(dirs, wantCalls) {
		t.Errorf("resolved dirs = %v, want each module root %v", dirs, wantCalls)
	}
	if resolved.RootModule != "" {
		t.Errorf("RootModule = %q, want empty: the scan root declares no module and its directory name is not one", resolved.RootModule)
	}
	wantMembers := []dependency.WorkspaceMember{
		{Name: "com.acme.gateway", Dir: wantCalls[0]},
		{Name: "com.acme.ledger", Dir: wantCalls[1]},
	}
	if !reflect.DeepEqual(resolved.WorkspaceMembers, wantMembers) {
		t.Errorf("WorkspaceMembers = %+v, want %+v", resolved.WorkspaceMembers, wantMembers)
	}
	if len(resolved.Dependencies) != 2 {
		t.Errorf("len(Dependencies) = %d, want 2", len(resolved.Dependencies))
	}
}

func TestResolveScanRoot_FailingRootNamesIt(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"services/gateway/pom.xml": "<project/>",
		"services/ledger/pom.xml":  "<project/>",
	})
	resolver := &recordingResolver{ecosystem: "java", answer: func(dir string) (*dependency.ResolveResult, error) {
		if filepath.Base(dir) == "ledger" {
			return nil, failure.New(failure.CodeJavaBuildToolAmbiguous, failure.StageDependency, "both manifests present")
		}
		return &dependency.ResolveResult{RootModule: "com.acme.gateway"}, nil
	}}
	_, _, err := resolveScanRoot(context.Background(), resolver, root, nil)
	if err == nil {
		t.Fatal("resolveScanRoot: expected an error")
	}
	if !strings.Contains(err.Error(), "services/ledger") {
		t.Errorf("error = %q, want it to name the failing root services/ledger", err.Error())
	}
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("failure.As: %v is not a structured failure", err)
	}
	if structured.Code != failure.CodeJavaBuildToolAmbiguous {
		t.Errorf("Code = %q, want the root's own code %q", structured.Code, failure.CodeJavaBuildToolAmbiguous)
	}
}

func TestResolveScanRoot_NothingBelowKeepsTheResolverError(t *testing.T) {
	root := writeRepoTree(t, map[string]string{"src/main/java/app/Use.java": "package app; class Use {}"})
	_, _, err := resolveScanRoot(context.Background(), dependency.NewJavaResolver(), root, nil)
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("failure.As: %v is not a structured failure", err)
	}
	if structured.Code != failure.CodeDependencyBuildToolUnknown {
		t.Errorf("Code = %q, want the unchanged %q", structured.Code, failure.CodeDependencyBuildToolUnknown)
	}
	if structured.Details["target_dir"] != root {
		t.Errorf("target_dir = %v, want the scan root %q", structured.Details["target_dir"], root)
	}
}

// KNOWN LIMITATION, pinned rather than fixed. MavenResolver.parseRootModule
// returns the groupId alone, so two merged roots sharing <groupId>com.acme</groupId>
// become two members with the same name. owningModule then answers "com.acme",
// versionedDirectDependencyRefs and graphDirectDependencyRefs miss because the
// versioned keys are com.acme:<artifactId>@<version>, and mavenRootAliasRefs
// sees two incoming-free candidates and returns nil by design. Every direct
// finding keeps its versionless rule PURL.
//
// The root cause is issue #520, "Maven root-module identifier omits artifactId,
// only returns groupId"; issue #533 is where it surfaces, because merging is
// what puts two same-group roots in one result. When #520 lands this test
// changes with it.
func TestEnrichDirectFindingPURLs_MergedMavenRootsSharingAGroupIDStayVersionless(t *testing.T) {
	resolved := &dependency.ResolveResult{
		RootModule: "monorepo",
		WorkspaceMembers: []dependency.WorkspaceMember{
			{Name: "com.acme", Dir: "/workspace/services/gateway"},
			{Name: "com.acme", Dir: "/workspace/services/ledger"},
		},
		VersionedGraph: map[string][]dependency.Ref{
			"com.acme:gateway@1.0.0": {{Module: "org.example:lib", Version: "2.0.0"}},
			"com.acme:ledger@1.0.0":  {{Module: "org.example:lib", Version: "2.0.0"}},
		},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "services/ledger/src/main/java/app/Use.java",
		CryptographicAssets: []entities.CryptographicAsset{{PURL: "pkg:maven/org.example/lib"}},
	}}}

	enrichDirectFindingPURLs(report, "/workspace", resolved, "java")

	if got := report.Findings[0].CryptographicAssets[0].PURL; got != "pkg:maven/org.example/lib" {
		t.Fatalf("PURL = %q, want the versionless rule PURL: see issue #520", got)
	}
}
