package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func joinTestPath(root, rel string) string {
	parts := append([]string{root}, strings.Split(rel, "/")...)
	return filepath.Join(parts...)
}

func TestParseDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "standard", input: "90m", want: 90 * time.Minute},
		{name: "days", input: "1.5d", want: 36 * time.Hour},
		{name: "fractional-days", input: "0.1d", want: 144 * time.Minute},
		{name: "weeks", input: "2w", want: 14 * 24 * time.Hour},
		{name: "fractional-weeks", input: "0.5w", want: 84 * time.Hour},
		{name: "invalid", input: "not-a-duration", wantErr: true},
		{name: "invalid-days", input: "xd", wantErr: true},
		{name: "invalid-double-days", input: "1dd", wantErr: true},
		{name: "invalid-garbage", input: "1.5garbage", wantErr: true},
		{name: "invalid-inf", input: "inf", wantErr: true},
		{name: "invalid-nan", input: "nan", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseDuration(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectEcosystem(t *testing.T) {
	t.Parallel()

	writeFile := func(t *testing.T, dir, name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	t.Run("go-priority", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod")
		writeFile(t, dir, "pyproject.toml")
		if got := DetectEcosystem(dir); got != "go" {
			t.Fatalf("DetectEcosystem() = %q, want go", got)
		}
	})

	t.Run("java", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "pom.xml")
		if got := DetectEcosystem(dir); got != "java" {
			t.Fatalf("DetectEcosystem() = %q, want java", got)
		}
	})

	t.Run("java-gradle-build", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "build.gradle")
		if got := DetectEcosystem(dir); got != "java" {
			t.Fatalf("DetectEcosystem() = %q, want java", got)
		}
	})

	t.Run("java-gradle-kts-build", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "build.gradle.kts")
		if got := DetectEcosystem(dir); got != "java" {
			t.Fatalf("DetectEcosystem() = %q, want java", got)
		}
	})

	t.Run("java-gradle-settings", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "settings.gradle")
		if got := DetectEcosystem(dir); got != "java" {
			t.Fatalf("DetectEcosystem() = %q, want java", got)
		}
	})

	t.Run("java-mixed-manifests-still-classifies-java", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "pom.xml")
		writeFile(t, dir, "build.gradle")
		if got := DetectEcosystem(dir); got != "java" {
			t.Fatalf("DetectEcosystem() = %q, want java", got)
		}
	})

	t.Run("rust", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		if got := DetectEcosystem(dir); got != "rust" {
			t.Fatalf("DetectEcosystem() = %q, want rust", got)
		}
	})

	t.Run("python", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "requirements.txt")
		if got := DetectEcosystem(dir); got != "python" {
			t.Fatalf("DetectEcosystem() = %q, want python", got)
		}
	})

	writePyproject := func(t *testing.T, dir, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(body), 0o600); err != nil {
			t.Fatalf("write pyproject.toml: %v", err)
		}
	}

	// Polyglot: Python packaging that embeds Rust via PyO3/setuptools-rust/maturin.
	// These cases mirror pyca/cryptography, pydantic-core, orjson, polars, etc.

	t.Run("polyglot-python-rust-with-project-table", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		writePyproject(t, dir, `
[project]
name = "my-pkg"
version = "0.1.0"
`)
		if got := DetectEcosystem(dir); got != "python" {
			t.Fatalf("DetectEcosystem() = %q, want python (pyproject declares [project])", got)
		}
	})

	t.Run("polyglot-python-rust-with-setuptools-rust-backend", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		writePyproject(t, dir, `
[build-system]
requires = ["setuptools >= 77.0", "setuptools-rust>=1.7.0"]
build-backend = "setuptools.build_meta"
`)
		if got := DetectEcosystem(dir); got != "python" {
			t.Fatalf("DetectEcosystem() = %q, want python (setuptools-rust in requires)", got)
		}
	})

	t.Run("polyglot-python-rust-with-maturin-tool-section", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		writePyproject(t, dir, `
[tool.maturin]
module-name = "my_pkg._native"
`)
		if got := DetectEcosystem(dir); got != "python" {
			t.Fatalf("DetectEcosystem() = %q, want python ([tool.maturin] present)", got)
		}
	})

	t.Run("polyglot-python-rust-with-hatchling-backend", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		writePyproject(t, dir, `
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
`)
		if got := DetectEcosystem(dir); got != "python" {
			t.Fatalf("DetectEcosystem() = %q, want python (hatchling in requires)", got)
		}
	})

	t.Run("polyglot-rust-with-pyproject-dev-tooling-only", func(t *testing.T) {
		// pyproject.toml used only for dev tooling (linter config, black/ruff settings)
		// with no Python package markers → Rust wins (Cargo.toml is authoritative).
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		writePyproject(t, dir, `
[tool.black]
line-length = 100

[tool.ruff]
target-version = "py311"
`)
		if got := DetectEcosystem(dir); got != "rust" {
			t.Fatalf("DetectEcosystem() = %q, want rust (pyproject has no Python package markers)", got)
		}
	})

	t.Run("polyglot-rust-with-empty-pyproject", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		writePyproject(t, dir, "")
		if got := DetectEcosystem(dir); got != "rust" {
			t.Fatalf("DetectEcosystem() = %q, want rust (empty pyproject)", got)
		}
	})

	t.Run("polyglot-rust-with-malformed-pyproject", func(t *testing.T) {
		// Malformed TOML must not panic; fall back to existing precedence (Rust wins).
		dir := t.TempDir()
		writeFile(t, dir, "Cargo.toml")
		writePyproject(t, dir, "this is : not = valid [toml")
		if got := DetectEcosystem(dir); got != "rust" {
			t.Fatalf("DetectEcosystem() = %q, want rust (malformed pyproject falls back)", got)
		}
	})

	t.Run("go-beats-python-pyproject", func(t *testing.T) {
		// Regression: go.mod at root remains authoritative even if pyproject declares a Python package.
		dir := t.TempDir()
		writeFile(t, dir, "go.mod")
		writePyproject(t, dir, `
[project]
name = "dev-tooling"
`)
		if got := DetectEcosystem(dir); got != "go" {
			t.Fatalf("DetectEcosystem() = %q, want go", got)
		}
	})

	t.Run("java-beats-python-pyproject", func(t *testing.T) {
		// Regression: Java manifest wins over pyproject for now (Python↔Java polyglot out of scope).
		dir := t.TempDir()
		writeFile(t, dir, "pom.xml")
		writePyproject(t, dir, `
[project]
name = "dev-tooling"
`)
		if got := DetectEcosystem(dir); got != "java" {
			t.Fatalf("DetectEcosystem() = %q, want java", got)
		}
	})

	t.Run("none", func(t *testing.T) {
		dir := t.TempDir()
		if got := DetectEcosystem(dir); got != "" {
			t.Fatalf("DetectEcosystem() = %q, want empty", got)
		}
	})
}

func TestExportCallGraph(t *testing.T) {
	t.Parallel()

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"app.main": {
				ID:        callgraph.FunctionID{Package: "app", Name: "main"},
				FilePath:  "main.go",
				StartLine: 1,
				EndLine:   10,
				Calls: []callgraph.FunctionCall{{
					Callee:   callgraph.FunctionID{Package: "crypto/aes", Name: "NewCipher"},
					FilePath: "main.go",
					Line:     5,
				}},
			},
			"crypto/aes.NewCipher": {
				ID:        callgraph.FunctionID{Package: "crypto/aes", Name: "NewCipher"},
				FilePath:  "aes.go",
				StartLine: 3,
				EndLine:   20,
			},
		},
		Callers: map[string][]string{"crypto/aes.NewCipher": {"app.main"}},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "main.go",
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 5,
				EndLine:   5,
				Match:     "aes.NewCipher(key)",
				Rules:     []entities.RuleInfo{{ID: "go.crypto.aes.newcipher", Message: "AES usage", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "aes.NewCipher", "algorithmName": "AES"},
				FindingID: "ab12cd34",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:  graph,
		Report:     report,
		RootModule: "example.com/app",
		Ecosystem:  "go",
	}

	t.Run("json", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "cg.json")
		if err := ExportCallGraph(out, "json", result); err != nil {
			t.Fatalf("ExportCallGraph(json): %v", err)
		}

		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("export produced empty file")
		}

		var payload callGraphExportV2
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatalf("invalid json output: %v", err)
		}
		if payload.SchemaVersion != "6.5" {
			t.Fatalf("schema_version = %q, want 6.5", payload.SchemaVersion)
		}
		if len(payload.FindingGraphs) != 1 {
			t.Fatalf("finding_graphs count = %d, want 1", len(payload.FindingGraphs))
		}
		fg := payload.FindingGraphs[0]
		if fg.FindingID != "ab12cd34" {
			t.Fatalf("finding_id = %q, want ab12cd34", fg.FindingID)
		}
		if fg.MatchedOperation == nil {
			t.Fatal("expected matched_operation")
		}
		if fg.MatchedOperation.Kind != "call" {
			t.Fatalf("matched_operation.kind = %q, want call", fg.MatchedOperation.Kind)
		}
		if fg.MatchedOperation.Symbol != "crypto/aes.NewCipher" {
			t.Fatalf("matched_operation.symbol = %q, want crypto/aes.NewCipher", fg.MatchedOperation.Symbol)
		}
		if fg.MatchedOperation.Expression != "aes.NewCipher(key)" {
			t.Fatalf("matched_operation.expression = %q, want aes.NewCipher(key)", fg.MatchedOperation.Expression)
		}
		if fg.MatchedOperation.Line != 5 {
			t.Fatalf("matched_operation.line = %d, want 5", fg.MatchedOperation.Line)
		}
		if len(fg.CallChains) != 1 || len(fg.CallChains[0]) != 1 {
			t.Fatalf("expected one self-chain, got %#v", fg.CallChains)
		}
		node := fg.CallChains[0][0]
		if node.FunctionName != "app.main" {
			t.Fatalf("function_name = %q, want app.main", node.FunctionName)
		}
		if node.FilePath != "main.go" {
			t.Fatalf("file_path = %q, want main.go", node.FilePath)
		}
		if node.StartLine != 1 {
			t.Fatalf("start_line = %d, want 1", node.StartLine)
		}
		if node.EntryCall != nil {
			t.Fatalf("self-chain should not include entry_call, got %#v", node.EntryCall)
		}
		if node.CryptoCall == nil || node.CryptoCall.FunctionName != "crypto/aes.NewCipher" || len(node.CryptoCall.Parameters) != 0 {
			t.Fatalf("expected no-arg crypto_call on last node, got %#v", node.CryptoCall)
		}
		if strings.Contains(string(data), "\"containing_function\"") || strings.Contains(string(data), "\"backward_paths\"") {
			t.Fatalf("legacy finding graph fields still present in export: %s", data)
		}
	})

	t.Run("unsupported-format", func(t *testing.T) {
		err := ExportCallGraph(filepath.Join(t.TempDir(), "x.out"), "yaml", result)
		if err == nil || !strings.Contains(err.Error(), "unsupported call graph format") {
			t.Fatalf("expected unsupported format error, got: %v", err)
		}
	})

	t.Run("write-error", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "missing", "cg.json")
		err := ExportCallGraph(out, "json", result)
		if err == nil || !strings.Contains(err.Error(), "failed to write call graph") {
			t.Fatalf("expected write error, got: %v", err)
		}
	})

	t.Run("nil-report", func(t *testing.T) {
		nilReportResult := &engine.DepScanResult{
			CallGraph:  graph,
			Report:     nil,
			RootModule: "example.com/app",
			Ecosystem:  "go",
		}
		err := ExportCallGraph(filepath.Join(t.TempDir(), "cg.json"), "json", nilReportResult)
		if err == nil || !strings.Contains(err.Error(), "result.Report is nil") {
			t.Fatalf("expected nil report error, got: %v", err)
		}
	})
}

func TestBuildCallChains_EvictsCacheAfterLastUse(t *testing.T) {
	t.Parallel()

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"me.zhengjie.Entry.run#0": {
				ID:        callgraph.FunctionID{Package: "me.zhengjie", Type: "Entry", Name: "run#0"},
				FilePath:  "src/main/java/me/zhengjie/Entry.java",
				StartLine: 1,
				EndLine:   20,
				Calls: []callgraph.FunctionCall{{
					Callee:   callgraph.FunctionID{Package: "me.zhengjie", Type: "CryptoService", Name: "encrypt#1"},
					FilePath: "src/main/java/me/zhengjie/Entry.java",
					Line:     10,
				}},
			},
			"me.zhengjie.CryptoService.encrypt#1": {
				ID:        callgraph.FunctionID{Package: "me.zhengjie", Type: "CryptoService", Name: "encrypt#1"},
				FilePath:  "src/main/java/me/zhengjie/CryptoService.java",
				StartLine: 30,
				EndLine:   60,
			},
		},
		Callers: map[string][]string{
			"me.zhengjie.CryptoService.encrypt#1": {"me.zhengjie.Entry.run#0"},
		},
	}

	report := &entities.InterimReport{
		Findings: []entities.Finding{{
			FilePath: "src/main/java/me/zhengjie/CryptoService.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 40, EndLine: 40, FindingID: "f1"},
				{StartLine: 45, EndLine: 45, FindingID: "f2"},
			},
		}},
	}

	result := &engine.DepScanResult{
		ProjectRoot: "/tmp/eladmin",
		CallGraph:   graph,
		Report:      report,
		RootModule:  "me.zhengjie",
		Ecosystem:   "java",
	}

	ctx := newExportBuildContext(result)
	cacheKey := "me.zhengjie.(CryptoService).encrypt#1"
	if got := ctx.callChainRemainingUses[cacheKey]; got != 2 {
		t.Fatalf("callChainRemainingUses[%q] = %d, want 2", cacheKey, got)
	}

	containingFn := ctx.findContainingFunctionByFinding("src/main/java/me/zhengjie/CryptoService.java", 40)
	if containingFn == nil {
		t.Fatal("expected containing function")
	}

	first := buildCallChains(ctx, containingFn, nil)
	if len(first) != 1 {
		t.Fatalf("first buildCallChains len = %d, want 1", len(first))
	}
	if got := ctx.callChainRemainingUses[cacheKey]; got != 1 {
		t.Fatalf("remaining uses after first call = %d, want 1", got)
	}
	if _, ok := ctx.callChainCache[cacheKey]; !ok {
		t.Fatal("expected cached base chains after first call")
	}

	second := buildCallChains(ctx, containingFn, nil)
	if len(second) != 1 {
		t.Fatalf("second buildCallChains len = %d, want 1", len(second))
	}
	if _, ok := ctx.callChainRemainingUses[cacheKey]; ok {
		t.Fatal("expected remaining uses to be cleared after final call")
	}
	if _, ok := ctx.callChainCache[cacheKey]; ok {
		t.Fatal("expected cache entry to be evicted after final call")
	}
}

func TestExportCallGraph_NonCallMatchedOperationOmitsCryptoCall(t *testing.T) {
	t.Parallel()

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"example.security.Builder.apply": {
				ID:        callgraph.FunctionID{Package: "example.security", Type: "Builder", Name: "apply"},
				FilePath:  "security/Builder.java",
				StartLine: 10,
				EndLine:   20,
				Calls: []callgraph.FunctionCall{
					{
						Callee:   callgraph.FunctionID{Package: "java.util", Type: "List", Name: "get#1"},
						FilePath: "security/Builder.java",
						Line:     12,
						Arguments: []string{
							"0",
						},
					},
					{
						Callee:   callgraph.FunctionID{Package: "io.jsonwebtoken.lang", Type: "Assert", Name: "notNull#2"},
						FilePath: "security/Builder.java",
						Line:     12,
						Arguments: []string{
							"chain.get(0)",
							"\"The first X509Certificate cannot be null.\"",
						},
					},
				},
			},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "security/Builder.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 12,
				EndLine:   12,
				// Match is a bare type reference (no parentheses) so that
				// inferMatchedOperationKind classifies this as "type_usage"
				// from source text alone (api-free, per position-based-anchoring spec).
				Match:     "X509Certificate",
				Rules:     []entities.RuleInfo{{ID: "java.jca.certificate.x509.usage", Message: "X509 usage", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "X509Certificate"},
				FindingID: "typeusage1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:  graph,
		Report:     report,
		RootModule: "example.security",
		Ecosystem:  "java",
	}

	out := filepath.Join(t.TempDir(), "cg.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if len(payload.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs count = %d, want 1", len(payload.FindingGraphs))
	}

	fg := payload.FindingGraphs[0]
	if fg.UnresolvedReason != "" {
		t.Fatalf("unresolved_reason = %q, want empty", fg.UnresolvedReason)
	}
	if fg.MatchedOperation == nil {
		t.Fatal("expected matched_operation")
	}
	if fg.MatchedOperation.Kind != "type_usage" {
		t.Fatalf("matched_operation.kind = %q, want type_usage", fg.MatchedOperation.Kind)
	}
	if fg.MatchedOperation.Symbol != "X509Certificate" {
		t.Fatalf("matched_operation.symbol = %q, want X509Certificate", fg.MatchedOperation.Symbol)
	}
	if len(fg.CallChains) != 1 || len(fg.CallChains[0]) != 1 {
		t.Fatalf("expected one self-chain, got %#v", fg.CallChains)
	}
	if fg.CallChains[0][0].CryptoCall != nil {
		t.Fatalf("expected no crypto_call for type usage match, got %#v", fg.CallChains[0][0].CryptoCall)
	}
}

func TestExportCallGraph_DependencyPathsAndUnresolvedFallback(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	depRoot := filepath.Join(t.TempDir(), "dep")

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"org.example.(Digest).compute#1": {
				ID:        callgraph.FunctionID{Package: "org.example", Type: "Digest", Name: "compute#1"},
				FilePath:  joinTestPath(depRoot, "org/example/Digest.java"),
				StartLine: 40,
				EndLine:   60,
				Calls: []callgraph.FunctionCall{{
					Callee:          callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"},
					FilePath:        joinTestPath(depRoot, "org/example/Digest.java"),
					Line:            45,
					Arguments:       []string{"\"SHA-512\""},
					ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "\"SHA-512\""}}},
				}},
			},
			"java.security.(MessageDigest).getInstance#1": {
				ID:        callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"},
				FilePath:  joinTestPath(projectRoot, "jdk/MessageDigest.java"),
				StartLine: 1,
				EndLine:   10,
				Parameters: []callgraph.FunctionParameter{
					{Type: "String"},
				},
			},
		},
		Callers: map[string][]string{
			"java.security.(MessageDigest).getInstance#1": {"org.example.(Digest).compute#1"},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{
			{
				FilePath: "org/example/Digest.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 45,
					EndLine:   45,
					Match:     "MessageDigest.getInstance(\"SHA-512\")",
					Rules:     []entities.RuleInfo{{ID: "java.hash.sha512", Message: "SHA-512", Severity: "INFO"}},
					Status:    "pending",
					Metadata:  map[string]string{"api": "MessageDigest.getInstance"},
					FindingID: "dep12345",
					Source:    "dependency",
					DependencyInfo: &entities.DependencyInfo{
						Module:  "org.example:dep",
						Version: "1.0.0",
					},
				}},
			},
			{
				FilePath: "org/example/Fields.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 12,
					EndLine:   12,
					Match:     "new IvParameterSpec(iv)",
					Rules:     []entities.RuleInfo{{ID: "java.iv", Message: "IV", Severity: "INFO"}},
					Status:    "pending",
					Metadata:  map[string]string{"api": "IvParameterSpec"},
					FindingID: "dep67890",
					Source:    "dependency",
					DependencyInfo: &entities.DependencyInfo{
						Module:  "org.example:dep",
						Version: "1.0.0",
					},
				}},
			},
		},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.com/app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
		Dependencies: []dependency.Dependency{{
			Module:  "org.example:dep",
			Version: "1.0.0",
			Dir:     depRoot,
		}},
	}

	out := filepath.Join(t.TempDir(), "cg.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if strings.Contains(string(data), "forward_paths") || strings.Contains(string(data), "\"sinks\"") || strings.Contains(string(data), "no_forward_start_node") {
		t.Fatalf("legacy forward-tracing fields still present in export: %s", data)
	}

	var payload callGraphExportV2
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if len(payload.FindingGraphs) != 2 {
		t.Fatalf("finding_graphs count = %d, want 2", len(payload.FindingGraphs))
	}

	var depFG, unresolvedFG callGraphExportFinding
	for _, fg := range payload.FindingGraphs {
		switch fg.FindingID {
		case "dep12345":
			depFG = fg
		case "dep67890":
			unresolvedFG = fg
		}
	}

	if len(depFG.CallChains) != 1 || len(depFG.CallChains[0]) != 1 {
		t.Fatalf("expected dependency self-chain, got %#v", depFG.CallChains)
	}
	depNode := depFG.CallChains[0][0]
	if depNode.FunctionName != "org.example.Digest.compute" {
		t.Fatalf("function_name = %q", depNode.FunctionName)
	}
	if depNode.FilePath != "org/example/Digest.java" {
		t.Fatalf("file_path = %q", depNode.FilePath)
	}
	if depNode.StartLine != 40 {
		t.Fatalf("start_line = %d", depNode.StartLine)
	}
	if depNode.DependencyInfo == nil || depNode.DependencyInfo.Module != "org.example:dep" {
		t.Fatalf("expected dependency context on call chain node, got %#v", depNode.DependencyInfo)
	}
	if depNode.EntryCall != nil {
		t.Fatalf("dependency self-chain should not include entry_call, got %#v", depNode.EntryCall)
	}
	if depNode.CryptoCall == nil || len(depNode.CryptoCall.Parameters) != 1 {
		t.Fatalf("expected one crypto_call parameter, got %#v", depNode.CryptoCall)
	}
	param := depNode.CryptoCall.Parameters[0]
	if param.ParameterIndex != 0 {
		t.Fatalf("parameter_index = %d, want 0", param.ParameterIndex)
	}
	if param.Type != "String" {
		t.Fatalf("type = %q, want String", param.Type)
	}
	if param.ArgumentExpression != "\"SHA-512\"" {
		t.Fatalf("argument_expression = %q, want literal", param.ArgumentExpression)
	}
	if param.ResolvedValue != "\"SHA-512\"" {
		t.Fatalf("resolved_value = %q, want literal", param.ResolvedValue)
	}
	if param.VariableName != "" {
		t.Fatalf("variable_name = %q, want empty for literal argument", param.VariableName)
	}
	if len(param.SourceNodes) != 1 || param.SourceNodes[0].ParameterIndex != nil {
		t.Fatalf("expected non-PARAMETER source node to omit parameter_index, got %#v", param.SourceNodes)
	}

	if unresolvedFG.UnresolvedReason != "no_containing_function" {
		t.Fatalf("unresolved_reason = %q, want no_containing_function", unresolvedFG.UnresolvedReason)
	}
	if unresolvedFG.FindingLocation == nil {
		t.Fatal("expected finding_location for unresolved finding")
	}
	if unresolvedFG.FindingLocation.FilePath != "org/example/Fields.java" {
		t.Fatalf("finding_location.file_path = %q", unresolvedFG.FindingLocation.FilePath)
	}
	if unresolvedFG.FindingLocation.DependencyInfo == nil || unresolvedFG.FindingLocation.DependencyInfo.Version != "1.0.0" {
		t.Fatalf("expected dependency context on finding_location, got %#v", unresolvedFG.FindingLocation.DependencyInfo)
	}
}

func TestExportCallGraph_UsesExternalSignatureFallbackForParameterTypes(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	calleeID := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"example.app.(Digests).sha256#1": {
				ID:        callgraph.FunctionID{Package: "example.app", Type: "Digests", Name: "sha256#1"},
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/Digests.java"),
				StartLine: 20,
				EndLine:   30,
				Calls: []callgraph.FunctionCall{{
					Callee:          calleeID,
					FilePath:        joinTestPath(projectRoot, "src/main/java/example/app/Digests.java"),
					Line:            24,
					Arguments:       []string{"\"SHA-256\""},
					ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "\"SHA-256\""}}},
				}},
			},
		},
		JavaPlatformSignatures: &callgraph.JavaPlatformSignatureMetadata{
			RequestedMajor:  "17",
			RuntimeVersion:  "17.0.12",
			SignaturesUsed:  true,
			SignatureSource: "jmods",
		},
		ExternalMethodSignatures: map[string][]callgraph.ExternalMethodSignature{
			callgraph.ExternalMethodSignatureKey(calleeID): {{
				ParameterTypes: []string{"java.lang.String"},
				ReturnType:     "java.security.MessageDigest",
			}},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "src/main/java/example/app/Digests.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 24,
				EndLine:   24,
				Match:     "MessageDigest.getInstance(\"SHA-256\")",
				Rules:     []entities.RuleInfo{{ID: "java.hash.sha256", Message: "SHA-256", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "MessageDigest.getInstance"},
				FindingID: "external-sig-1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-external-signatures.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if payload.ScanMetadata.JavaRuntimeVersion != "17.0.12" {
		t.Fatalf("java_runtime_version = %q, want 17.0.12", payload.ScanMetadata.JavaRuntimeVersion)
	}
	if payload.ScanMetadata.JavaRequestedJDKMajor != "17" {
		t.Fatalf("java_requested_jdk_major = %q, want 17", payload.ScanMetadata.JavaRequestedJDKMajor)
	}
	if payload.ScanMetadata.JavaPlatformSignaturesUsed == nil || !*payload.ScanMetadata.JavaPlatformSignaturesUsed {
		t.Fatalf("expected java_platform_signatures_used=true, got %#v", payload.ScanMetadata.JavaPlatformSignaturesUsed)
	}
	if payload.ScanMetadata.JavaPlatformSignatureSource != "jmods" {
		t.Fatalf("java_platform_signature_source = %q, want jmods", payload.ScanMetadata.JavaPlatformSignatureSource)
	}

	params := payload.FindingGraphs[0].CallChains[0][0].CryptoCall.Parameters
	if len(params) != 1 {
		t.Fatalf("expected one crypto_call parameter, got %#v", params)
	}
	if params[0].ParameterIndex != 0 {
		t.Fatalf("parameter_index = %d, want 0", params[0].ParameterIndex)
	}
	if params[0].Type != "java.lang.String" {
		t.Fatalf("type = %q, want java.lang.String", params[0].Type)
	}
	cryptoCall := payload.FindingGraphs[0].CallChains[0][0].CryptoCall
	if cryptoCall == nil {
		t.Fatal("expected crypto_call metadata")
	}
	if cryptoCall.ReturnType != "java.security.MessageDigest" {
		t.Fatalf("return_type = %q, want java.security.MessageDigest", cryptoCall.ReturnType)
	}
	if len(cryptoCall.ParameterTypes) != 1 || cryptoCall.ParameterTypes[0] != "java.lang.String" {
		t.Fatalf("parameter_types = %#v, want [java.lang.String]", cryptoCall.ParameterTypes)
	}
	if cryptoCall.CanonicalSignature != "java.security.MessageDigest.getInstance(java.lang.String): java.security.MessageDigest" {
		t.Fatalf("canonical_signature = %q, want java.security.MessageDigest.getInstance(java.lang.String): java.security.MessageDigest", cryptoCall.CanonicalSignature)
	}
}

func TestExportCallGraph_UnresolvedExternalCallLeavesTypeEmpty(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"example.app.main#0": {
				ID:        callgraph.FunctionID{Package: "example.app", Name: "main#0"},
				FilePath:  joinTestPath(projectRoot, "main.go"),
				StartLine: 1,
				EndLine:   10,
				Calls: []callgraph.FunctionCall{{
					Callee:    callgraph.FunctionID{Package: "thirdparty", Name: "Hash#1"},
					FilePath:  joinTestPath(projectRoot, "main.go"),
					Line:      5,
					Arguments: []string{"data"},
				}},
			},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "main.go",
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 5,
				EndLine:   5,
				Match:     "thirdparty.Hash(data)",
				Rules:     []entities.RuleInfo{{ID: "go.hash.thirdparty", Message: "third-party hash", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "thirdparty.Hash"},
				FindingID: "best-effort-1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "go",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-best-effort.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	params := payload.FindingGraphs[0].CallChains[0][0].CryptoCall.Parameters
	if len(params) != 1 {
		t.Fatalf("expected one crypto_call parameter, got %#v", params)
	}
	if params[0].ParameterIndex != 0 {
		t.Fatalf("parameter_index = %d, want 0", params[0].ParameterIndex)
	}
	if params[0].Type != "" {
		t.Fatalf("type = %q, want empty", params[0].Type)
	}
	if params[0].VariableName != "data" {
		t.Fatalf("variable_name = %q, want data", params[0].VariableName)
	}
}

func TestExportCallGraph_JavaScanMetadataRecordsUnavailablePlatformSignatures(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"example.app.(Digests).sha256#1": {
				ID:        callgraph.FunctionID{Package: "example.app", Type: "Digests", Name: "sha256#1"},
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/Digests.java"),
				StartLine: 20,
				EndLine:   24,
				Calls: []callgraph.FunctionCall{{
					Callee:    callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"},
					FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/Digests.java"),
					Line:      24,
					Arguments: []string{`"SHA-256"`},
				}},
			},
		},
		JavaPlatformSignatures: &callgraph.JavaPlatformSignatureMetadata{
			RequestedMajor:    "21",
			SignaturesUsed:    false,
			SignatureSource:   "unavailable",
			UnavailableReason: "java_home_not_set",
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "src/main/java/example/app/Digests.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 24,
				EndLine:   24,
				Match:     "MessageDigest.getInstance(\"SHA-256\")",
				Rules:     []entities.RuleInfo{{ID: "java.hash.sha256", Message: "SHA-256", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "MessageDigest.getInstance"},
				FindingID: "java-meta-1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-java-metadata.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	if payload.ScanMetadata.JavaPlatformSignaturesUsed == nil || *payload.ScanMetadata.JavaPlatformSignaturesUsed {
		t.Fatalf("expected java_platform_signatures_used=false, got %#v", payload.ScanMetadata.JavaPlatformSignaturesUsed)
	}
	if payload.ScanMetadata.JavaRequestedJDKMajor != "21" {
		t.Fatalf("java_requested_jdk_major = %q, want 21", payload.ScanMetadata.JavaRequestedJDKMajor)
	}
	if payload.ScanMetadata.JavaPlatformSignatureSource != "unavailable" {
		t.Fatalf("java_platform_signature_source = %q, want unavailable", payload.ScanMetadata.JavaPlatformSignatureSource)
	}
	if payload.ScanMetadata.JavaPlatformSignatureUnavailableReason != "java_home_not_set" {
		t.Fatalf("java_platform_signature_unavailable_reason = %q, want java_home_not_set", payload.ScanMetadata.JavaPlatformSignatureUnavailableReason)
	}
	params := payload.FindingGraphs[0].CallChains[0][0].CryptoCall.Parameters
	if len(params) != 1 {
		t.Fatalf("expected one crypto_call parameter, got %#v", params)
	}
	if params[0].Type != "" {
		t.Fatalf("type = %q, want empty without platform signatures", params[0].Type)
	}
}

func TestExportCallGraph_OverloadedDependencyPathAndResolvedValues(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	depRoot := filepath.Join(t.TempDir(), "dep")

	userEntryID := callgraph.FunctionID{Package: "example.app", Type: "TokenController", Name: "issue#0"}
	userRepoID := callgraph.FunctionID{Package: "example.app", Type: "JWTCsrfTokenRepository", Name: "generateToken#1"}
	depAPIID := callgraph.FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith#2$SignatureAlgorithm,byte"}
	depImplID := callgraph.FunctionID{Package: "io.jsonwebtoken.impl", Type: "DefaultJwtBuilder", Name: "signWith#2$SignatureAlgorithm,byte"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			userEntryID.String(): {
				ID:        userEntryID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/TokenController.java"),
				StartLine: 10,
				EndLine:   20,
				Calls: []callgraph.FunctionCall{{
					Callee:   userRepoID,
					FilePath: joinTestPath(projectRoot, "src/main/java/example/app/TokenController.java"),
					Line:     14,
				}},
			},
			userRepoID.String(): {
				ID:        userRepoID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/JWTCsrfTokenRepository.java"),
				StartLine: 30,
				EndLine:   46,
				Calls: []callgraph.FunctionCall{{
					Callee:          depAPIID,
					FilePath:        joinTestPath(projectRoot, "src/main/java/example/app/JWTCsrfTokenRepository.java"),
					Line:            37,
					Arguments:       []string{"SignatureAlgorithm.HS256", "secret"},
					ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Name: "SignatureAlgorithm.HS256", Value: "SignatureAlgorithm.HS256"}}, {{Type: "FIELD", Name: "secret", DeclaredType: "byte[]"}}},
				}},
			},
			depAPIID.String(): {
				ID:         depAPIID,
				FilePath:   joinTestPath(depRoot, "io/jsonwebtoken/JwtBuilder.java"),
				StartLine:  100,
				EndLine:    110,
				OwnerType:  "interface",
				OwnerName:  "JwtBuilder",
				ReturnType: "JwtBuilder",
				Parameters: []callgraph.FunctionParameter{{Type: "SignatureAlgorithm"}, {Type: "byte[]"}},
			},
			depImplID.String(): {
				ID:         depImplID,
				FilePath:   joinTestPath(depRoot, "io/jsonwebtoken/impl/DefaultJwtBuilder.java"),
				StartLine:  261,
				EndLine:    267,
				OwnerType:  "class",
				OwnerName:  "DefaultJwtBuilder",
				ReturnType: "JwtBuilder",
				Parameters: []callgraph.FunctionParameter{{Type: "SignatureAlgorithm"}, {Type: "byte[]"}},
				Calls: []callgraph.FunctionCall{{
					Callee:          callgraph.FunctionID{Package: "javax.crypto.spec", Type: "SecretKeySpec", Name: "<init>"},
					FilePath:        joinTestPath(depRoot, "io/jsonwebtoken/impl/DefaultJwtBuilder.java"),
					Line:            266,
					Arguments:       []string{"secretKeyBytes", "alg.getJcaName()"},
					ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "secretKeyBytes", DeclaredType: "byte[]", ParameterIndex: 1}}, {{Type: "VALUE", Value: "\"HmacSHA256\""}}},
				}},
			},
			"javax.crypto.spec.(SecretKeySpec).<init>": {
				ID:         callgraph.FunctionID{Package: "javax.crypto.spec", Type: "SecretKeySpec", Name: "<init>"},
				FilePath:   joinTestPath(projectRoot, "jdk/SecretKeySpec.java"),
				StartLine:  1,
				EndLine:    10,
				Parameters: []callgraph.FunctionParameter{{Type: "byte[]"}, {Type: "String"}},
			},
		},
		Callers: map[string][]string{
			userRepoID.String(): {userEntryID.String()},
			depAPIID.String():   {userRepoID.String()},
			depImplID.String():  {userRepoID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "io/jsonwebtoken/impl/DefaultJwtBuilder.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 266,
				EndLine:   266,
				Match:     "new SecretKeySpec(secretKeyBytes, alg.getJcaName())",
				Rules:     []entities.RuleInfo{{ID: "java.secret-key", Message: "SecretKeySpec", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "SecretKeySpec"},
				FindingID: "dep-overload-1",
				Source:    "dependency",
				DependencyInfo: &entities.DependencyInfo{
					Module:  "io.jsonwebtoken:jjwt-impl",
					Version: "0.12.3",
				},
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
		Dependencies: []dependency.Dependency{{
			Module:  "io.jsonwebtoken:jjwt-impl",
			Version: "0.12.3",
			Dir:     depRoot,
		}},
	}

	out := filepath.Join(t.TempDir(), "cg-overload.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if strings.Contains(string(data), "forward_paths") || strings.Contains(string(data), "\"sinks\"") || strings.Contains(string(data), "no_forward_start_node") {
		t.Fatalf("legacy forward-tracing fields still present in export: %s", data)
	}

	var payload callGraphExportV2
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if len(payload.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs count = %d, want 1", len(payload.FindingGraphs))
	}

	fg := payload.FindingGraphs[0]
	if len(fg.CallChains) != 1 || len(fg.CallChains[0]) != 2 {
		t.Fatalf("expected one nearest-user-to-dependency call chain of length 2, got %#v", fg.CallChains)
	}
	chain := fg.CallChains[0]
	if chain[0].FunctionName != "example.app.JWTCsrfTokenRepository.generateToken" || chain[1].FunctionName != "io.jsonwebtoken.impl.DefaultJwtBuilder.signWith" {
		t.Fatalf("unexpected call chain: %#v", chain)
	}
	if chain[1].CanonicalSignature != "io.jsonwebtoken.impl.DefaultJwtBuilder.signWith(SignatureAlgorithm, byte[]): JwtBuilder" {
		t.Fatalf("unexpected chain canonical signature: %q", chain[1].CanonicalSignature)
	}
	if chain[1].ReturnType != "JwtBuilder" {
		t.Fatalf("unexpected chain return_type: %q", chain[1].ReturnType)
	}
	if len(chain[1].ParameterTypes) != 2 || chain[1].ParameterTypes[0] != "SignatureAlgorithm" || chain[1].ParameterTypes[1] != "byte[]" {
		t.Fatalf("unexpected chain parameter_types: %#v", chain[1].ParameterTypes)
	}
	if chain[0].StartLine != 30 || chain[1].StartLine != 261 {
		t.Fatalf("unexpected chain start lines: %#v", chain)
	}
	if chain[0].EntryCall != nil {
		t.Fatalf("first chain node should not have entry_call, got %#v", chain[0].EntryCall)
	}
	dependencyHop := chain[1].EntryCall
	if dependencyHop == nil || dependencyHop.Line != 37 || dependencyHop.FilePath != "src/main/java/example/app/JWTCsrfTokenRepository.java" {
		t.Fatalf("unexpected dependency entry_call: %#v", dependencyHop)
	}
	if dependencyHop.FunctionName != "io.jsonwebtoken.JwtBuilder.signWith" {
		t.Fatalf("expected interface call name on dependency hop, got %#v", dependencyHop)
	}
	if dependencyHop.CanonicalSignature != "io.jsonwebtoken.JwtBuilder.signWith(SignatureAlgorithm, byte[]): JwtBuilder" {
		t.Fatalf("unexpected dependency hop canonical signature: %q", dependencyHop.CanonicalSignature)
	}
	if dependencyHop.ReturnType != "JwtBuilder" {
		t.Fatalf("unexpected dependency hop return_type: %q", dependencyHop.ReturnType)
	}
	if len(dependencyHop.ParameterTypes) != 2 || dependencyHop.ParameterTypes[0] != "SignatureAlgorithm" || dependencyHop.ParameterTypes[1] != "byte[]" {
		t.Fatalf("unexpected dependency hop parameter_types: %#v", dependencyHop.ParameterTypes)
	}
	if len(dependencyHop.Parameters) != 2 {
		t.Fatalf("expected hop parameters for dependency call, got %#v", dependencyHop.Parameters)
	}
	if dependencyHop.Parameters[0].ArgumentExpression != "SignatureAlgorithm.HS256" {
		t.Fatalf("unexpected first hop argument expression: %#v", dependencyHop.Parameters[0])
	}
	if dependencyHop.Parameters[0].ParameterIndex != 0 || dependencyHop.Parameters[1].ParameterIndex != 1 {
		t.Fatalf("unexpected parameter indexes on dependency hop: %#v", dependencyHop.Parameters)
	}
	if dependencyHop.Parameters[0].ResolvedValue != "SignatureAlgorithm.HS256" {
		t.Fatalf("unexpected first hop resolved value: %#v", dependencyHop.Parameters[0])
	}
	if dependencyHop.Parameters[1].VariableName != "secret" || dependencyHop.Parameters[1].ArgumentExpression != "secret" {
		t.Fatalf("unexpected second hop variable parameter: %#v", dependencyHop.Parameters[1])
	}
	if len(dependencyHop.Parameters[1].SourceNodes) != 1 || dependencyHop.Parameters[1].SourceNodes[0].Type != "FIELD" {
		t.Fatalf("expected source provenance on dependency hop param, got %#v", dependencyHop.Parameters[1].SourceNodes)
	}
	if chain[1].DependencyInfo == nil || chain[1].DependencyInfo.Module != "io.jsonwebtoken:jjwt-impl" {
		t.Fatalf("expected dependency context on last node, got %#v", chain[1].DependencyInfo)
	}
	if chain[1].CryptoCall == nil || len(chain[1].CryptoCall.Parameters) != 2 {
		t.Fatalf("unexpected crypto_call parameters: %#v", chain[1].CryptoCall)
	}
	if len(chain[1].CryptoCall.ParameterTypes) != 2 || chain[1].CryptoCall.ParameterTypes[0] != "byte[]" || chain[1].CryptoCall.ParameterTypes[1] != "String" {
		t.Fatalf("unexpected crypto_call parameter_types: %#v", chain[1].CryptoCall.ParameterTypes)
	}
	if chain[1].CryptoCall.CanonicalSignature != "javax.crypto.spec.SecretKeySpec.<init>(byte[], String): SecretKeySpec" {
		t.Fatalf("unexpected crypto_call canonical signature: %q", chain[1].CryptoCall.CanonicalSignature)
	}
	if chain[1].CryptoCall.ReturnType != "SecretKeySpec" {
		t.Fatalf("unexpected crypto_call return_type: %q", chain[1].CryptoCall.ReturnType)
	}
	if chain[1].CryptoCall.Parameters[0].ParameterIndex != 0 || chain[1].CryptoCall.Parameters[1].ParameterIndex != 1 {
		t.Fatalf("unexpected crypto_call parameter indexes: %#v", chain[1].CryptoCall.Parameters)
	}
	if chain[1].CryptoCall.Parameters[0].ResolvedValue != "" {
		t.Fatalf("did not expect algorithm value to propagate onto unrelated dependency-local parameter, got %#v", chain[1].CryptoCall.Parameters[0])
	}
	if chain[1].CryptoCall.Parameters[1].ResolvedValue != "\"HmacSHA256\"" {
		t.Fatalf("resolved_value = %q, want HmacSHA256 literal", chain[1].CryptoCall.Parameters[1].ResolvedValue)
	}
	if fg.UnresolvedReason != "" {
		t.Fatalf("unexpected unresolved_reason: %q", fg.UnresolvedReason)
	}
}

func TestExportCallGraph_PropagatesProvenanceAcrossDirectChain(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	controllerID := callgraph.FunctionID{Package: "example.app", Type: "SecretsController", Name: "traceToken#1"}
	serviceID := callgraph.FunctionID{Package: "example.app", Type: "SecretService", Name: "issueTraceToken#2"}
	repoID := callgraph.FunctionID{Package: "example.app", Type: "JWTCsrfTokenRepository", Name: "generateToken#2"}
	signWithID := callgraph.FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith#2$SignatureAlgorithm,byte"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			controllerID.String(): {
				ID:        controllerID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/SecretsController.java"),
				StartLine: 34,
				EndLine:   36,
				Calls: []callgraph.FunctionCall{{
					Callee:   serviceID,
					FilePath: joinTestPath(projectRoot, "src/main/java/example/app/SecretsController.java"),
					Line:     35,
					Arguments: []string{
						"SignatureAlgorithm.HS256",
						"request",
					},
					ArgumentSources: [][]callgraph.SourceNode{
						{{Type: "VALUE", Name: "SignatureAlgorithm.HS256", Value: "SignatureAlgorithm.HS256"}},
						{{Type: "PARAMETER", Name: "request", DeclaredType: "HttpServletRequest", Location: &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, "src/main/java/example/app/SecretsController.java"), Line: 34}}},
					},
				}},
			},
			serviceID.String(): {
				ID:        serviceID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/SecretService.java"),
				StartLine: 72,
				EndLine:   76,
				Calls: []callgraph.FunctionCall{{
					Callee:   repoID,
					FilePath: joinTestPath(projectRoot, "src/main/java/example/app/SecretService.java"),
					Line:     75,
					Arguments: []string{
						"algorithm",
						"request",
					},
					ArgumentSources: [][]callgraph.SourceNode{
						{{Type: "PARAMETER", Name: "algorithm", DeclaredType: "SignatureAlgorithm", Location: &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, "src/main/java/example/app/SecretService.java"), Line: 72}}},
						{{Type: "PARAMETER", Name: "request", DeclaredType: "HttpServletRequest", ParameterIndex: 1, Location: &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, "src/main/java/example/app/SecretService.java"), Line: 72}}},
					},
				}},
			},
			repoID.String(): {
				ID:        repoID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/JWTCsrfTokenRepository.java"),
				StartLine: 35,
				EndLine:   47,
				Calls: []callgraph.FunctionCall{{
					Callee:   signWithID,
					FilePath: joinTestPath(projectRoot, "src/main/java/example/app/JWTCsrfTokenRepository.java"),
					Line:     41,
					Arguments: []string{
						"algorithm",
						"secret",
					},
					ArgumentSources: [][]callgraph.SourceNode{
						{{Type: "PARAMETER", Name: "algorithm", DeclaredType: "SignatureAlgorithm", Location: &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, "src/main/java/example/app/JWTCsrfTokenRepository.java"), Line: 35}}},
						{{
							Type:         "FIELD",
							Name:         "secret",
							DeclaredType: "byte[]",
							Location:     &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, "src/main/java/example/app/JWTCsrfTokenRepository.java"), Line: 27},
							SourceNodes: []callgraph.SourceNode{{
								Type:           "PARAMETER",
								Name:           "secret",
								DeclaredType:   "byte[]",
								ParameterIndex: 0,
								Location:       &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, "src/main/java/example/app/JWTCsrfTokenRepository.java"), Line: 27},
							}},
						}},
					},
				}},
				Parameters: []callgraph.FunctionParameter{
					{Type: "SignatureAlgorithm"},
					{Type: "HttpServletRequest"},
				},
			},
			signWithID.String(): {
				ID:        signWithID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/io/jsonwebtoken/JwtBuilder.java"),
				StartLine: 100,
				EndLine:   110,
				Parameters: []callgraph.FunctionParameter{
					{Type: "io.jsonwebtoken.SignatureAlgorithm"},
					{Type: "byte[]"},
				},
			},
		},
		Callers: map[string][]string{
			serviceID.String():  {controllerID.String()},
			repoID.String():     {serviceID.String()},
			signWithID.String(): {repoID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "src/main/java/example/app/JWTCsrfTokenRepository.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 41,
				EndLine:   41,
				Match:     "builder.signWith(algorithm, secret)",
				Rules:     []entities.RuleInfo{{ID: "java.jjwt.signwith.variable", Message: "signWith variable", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "JwtBuilder.signWith"},
				FindingID: "direct-prop-1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
		Dependencies: []dependency.Dependency{
			{Module: "io.jsonwebtoken", Version: "0.12.3", Dir: projectRoot},
		},
	}

	out := filepath.Join(t.TempDir(), "cg-direct-prop.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if len(payload.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs count = %d, want 1", len(payload.FindingGraphs))
	}

	chain := payload.FindingGraphs[0].CallChains[0]
	if len(chain) != 2 {
		t.Fatalf("expected 2-node direct chain from nearest user boundary, got %#v", chain)
	}
	if chain[1].StartLine != 35 {
		t.Fatalf("unexpected repo start_line: %#v", chain[1])
	}
	if chain[1].EntryCall == nil || len(chain[1].EntryCall.Parameters) != 2 {
		t.Fatalf("expected entry_call on repo node, got %#v", chain[1].EntryCall)
	}
	entryParam := chain[1].EntryCall.Parameters[0]
	if entryParam.ParameterIndex != 0 || chain[1].EntryCall.Parameters[1].ParameterIndex != 1 {
		t.Fatalf("unexpected entry_call parameter indexes: %#v", chain[1].EntryCall.Parameters)
	}
	if entryParam.ResolvedValue != "" {
		t.Fatalf("did not expect resolved value once the controller hop is outside the exported chain, got %#v", entryParam)
	}
	if len(entryParam.SourceNodes) != 1 || entryParam.SourceNodes[0].Type != "PARAMETER" {
		t.Fatalf("expected local parameter source node, got %#v", entryParam.SourceNodes)
	}
	if entryParam.SourceNodes[0].ParameterIndex == nil || *entryParam.SourceNodes[0].ParameterIndex != 0 {
		t.Fatalf("expected local parameter source node to keep parameter_index=0, got %#v", entryParam.SourceNodes[0])
	}
	if entryParam.SourceNodes[0].Location == nil ||
		entryParam.SourceNodes[0].Location.FilePath != "src/main/java/example/app/SecretService.java" ||
		entryParam.SourceNodes[0].Location.Line != 72 {
		t.Fatalf("expected local parameter location to be normalized, got %#v", entryParam.SourceNodes[0].Location)
	}
	cryptoParam := chain[1].CryptoCall.Parameters[0]
	if cryptoParam.ParameterIndex != 0 || chain[1].CryptoCall.Parameters[1].ParameterIndex != 1 {
		t.Fatalf("unexpected crypto_call parameter indexes: %#v", chain[1].CryptoCall.Parameters)
	}
	if cryptoParam.ResolvedValue != "" {
		t.Fatalf("did not expect crypto_call param to resolve once upstream controller provenance is truncated, got %#v", cryptoParam)
	}
	if len(cryptoParam.SourceNodes) != 1 || len(cryptoParam.SourceNodes[0].SourceNodes) != 1 {
		t.Fatalf("expected nested parameter provenance on crypto_call param, got %#v", cryptoParam.SourceNodes)
	}
	if cryptoParam.SourceNodes[0].SourceNodes[0].Type != "PARAMETER" {
		t.Fatalf("expected service-level parameter provenance on crypto_call param, got %#v", cryptoParam.SourceNodes)
	}
	if chain[1].CryptoCall.Parameters[1].ResolvedValue != "" {
		t.Fatalf("did not expect field-backed secret parameter to resolve to propagated algorithm value, got %#v", chain[1].CryptoCall.Parameters[1])
	}
}

func TestExportCallGraph_PropagatesReceiverProvenanceWithinCallResult(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	controllerID := callgraph.FunctionID{Package: "example.app", Type: "DynamicJWTController", Name: "dynamicBuilderSpecific#1"}
	depID := callgraph.FunctionID{Package: "io.jsonwebtoken.impl", Type: "DefaultJwtBuilder", Name: "signWith#2$SignatureAlgorithm,byte"}
	interfaceID := callgraph.FunctionID{Package: "io.jsonwebtoken", Type: "JwtBuilder", Name: "signWith#2$SignatureAlgorithm,byte"}
	getJcaNameID := callgraph.FunctionID{Package: "io.jsonwebtoken", Type: "SignatureAlgorithm", Name: "getJcaName#0"}
	secretKeySpecID := callgraph.FunctionID{Package: "javax.crypto.spec", Type: "SecretKeySpec", Name: "<init>"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			controllerID.String(): {
				ID:        controllerID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/DynamicJWTController.java"),
				StartLine: 47,
				EndLine:   88,
				Calls: []callgraph.FunctionCall{{
					Callee:   interfaceID,
					FilePath: joinTestPath(projectRoot, "src/main/java/example/app/DynamicJWTController.java"),
					Line:     86,
					Arguments: []string{
						"SignatureAlgorithm.HS256",
						"secretService.getHS256SecretBytes()",
					},
					ArgumentSources: [][]callgraph.SourceNode{
						{{Type: "VALUE", Name: "SignatureAlgorithm.HS256", Value: "SignatureAlgorithm.HS256"}},
						{{Type: "CALL_RESULT", Value: "secretService.getHS256SecretBytes()"}},
					},
				}},
			},
			depID.String(): {
				ID:        depID,
				FilePath:  joinTestPath(projectRoot, ".deps/io/jsonwebtoken/impl/DefaultJwtBuilder.java"),
				StartLine: 261,
				EndLine:   267,
				Calls: []callgraph.FunctionCall{{
					Callee:   secretKeySpecID,
					FilePath: joinTestPath(projectRoot, ".deps/io/jsonwebtoken/impl/DefaultJwtBuilder.java"),
					Line:     266,
					Arguments: []string{
						"secretKeyBytes",
						"alg.getJcaName()",
					},
					ArgumentSources: [][]callgraph.SourceNode{
						{{
							Type:           "PARAMETER",
							Name:           "secretKeyBytes",
							DeclaredType:   "byte[]",
							ParameterIndex: 1,
							Location:       &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, ".deps/io/jsonwebtoken/impl/DefaultJwtBuilder.java"), Line: 261},
						}},
						{{
							Type:       "CALL_RESULT",
							Value:      "alg.getJcaName()",
							CallTarget: &getJcaNameID,
							Location:   &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, ".deps/io/jsonwebtoken/impl/DefaultJwtBuilder.java"), Line: 266},
							SourceNodes: []callgraph.SourceNode{{
								Type:           "PARAMETER",
								Name:           "alg",
								DeclaredType:   "SignatureAlgorithm",
								ParameterIndex: 0,
								Location:       &callgraph.SourceLocation{FilePath: joinTestPath(projectRoot, ".deps/io/jsonwebtoken/impl/DefaultJwtBuilder.java"), Line: 261},
							}},
						}},
					},
				}},
				Parameters: []callgraph.FunctionParameter{
					{Type: "SignatureAlgorithm"},
					{Type: "byte[]"},
				},
			},
			interfaceID.String(): {
				ID:        interfaceID,
				FilePath:  joinTestPath(projectRoot, ".deps/io/jsonwebtoken/JwtBuilder.java"),
				StartLine: 100,
				EndLine:   110,
				Parameters: []callgraph.FunctionParameter{
					{Type: "io.jsonwebtoken.SignatureAlgorithm"},
					{Type: "byte[]"},
				},
			},
			secretKeySpecID.String(): {
				ID:        secretKeySpecID,
				FilePath:  joinTestPath(projectRoot, ".deps/javax/crypto/spec/SecretKeySpec.java"),
				StartLine: 10,
				EndLine:   20,
				Parameters: []callgraph.FunctionParameter{
					{Type: "byte[]"},
					{Type: "java.lang.String"},
				},
			},
		},
		Callers: map[string][]string{
			depID.String(): {controllerID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "io/jsonwebtoken/impl/DefaultJwtBuilder.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 266,
				EndLine:   266,
				Match:     "new SecretKeySpec(secretKeyBytes, alg.getJcaName())",
				Rules:     []entities.RuleInfo{{ID: "java.jca.secretkeyspec", Message: "secret key spec", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "SecretKeySpec"},
				FindingID: "dep-call-result-1",
				Source:    "dependency",
				DependencyInfo: &entities.DependencyInfo{
					Module:  "io.jsonwebtoken:jjwt-impl",
					Version: "0.12.3",
				},
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
		Dependencies: []dependency.Dependency{{
			Module:  "io.jsonwebtoken:jjwt-impl",
			Version: "0.12.3",
			Dir:     joinTestPath(projectRoot, ".deps"),
		}},
	}

	out := filepath.Join(t.TempDir(), "cg-dep-call-result.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if len(payload.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs count = %d, want 1", len(payload.FindingGraphs))
	}

	chain := payload.FindingGraphs[0].CallChains[0]
	if len(chain) != 2 {
		t.Fatalf("expected 2-node chain, got %#v", chain)
	}
	if chain[1].EntryCall == nil || len(chain[1].EntryCall.Parameters) != 2 {
		t.Fatalf("expected dependency entry_call with two params, got %#v", chain[1].EntryCall)
	}
	if chain[1].EntryCall.Parameters[0].ParameterIndex != 0 || chain[1].EntryCall.Parameters[1].ParameterIndex != 1 {
		t.Fatalf("unexpected dependency entry_call parameter indexes: %#v", chain[1].EntryCall.Parameters)
	}
	if chain[1].EntryCall.Parameters[0].ResolvedValue != "SignatureAlgorithm.HS256" {
		t.Fatalf("expected boundary algorithm resolved value, got %#v", chain[1].EntryCall.Parameters[0])
	}
	cryptoCall := chain[1].CryptoCall
	if cryptoCall == nil || len(cryptoCall.Parameters) != 2 {
		t.Fatalf("expected dependency crypto_call with two params, got %#v", cryptoCall)
	}
	if cryptoCall.Parameters[0].ParameterIndex != 0 || cryptoCall.Parameters[1].ParameterIndex != 1 {
		t.Fatalf("unexpected dependency crypto_call parameter indexes: %#v", cryptoCall.Parameters)
	}
	if cryptoCall.Parameters[0].ResolvedValue != "" {
		t.Fatalf("did not expect secretKeyBytes to resolve to algorithm value, got %#v", cryptoCall.Parameters[0])
	}
	if cryptoCall.Parameters[1].ResolvedValue != "" {
		t.Fatalf("did not expect CALL_RESULT to collapse to a simple value, got %#v", cryptoCall.Parameters[1])
	}
	if len(cryptoCall.Parameters[1].SourceNodes) != 1 {
		t.Fatalf("expected single CALL_RESULT source node, got %#v", cryptoCall.Parameters[1].SourceNodes)
	}
	callResult := cryptoCall.Parameters[1].SourceNodes[0]
	if callResult.Type != "CALL_RESULT" || callResult.CallTarget != "io.jsonwebtoken.SignatureAlgorithm.getJcaName" {
		t.Fatalf("unexpected call result provenance: %#v", callResult)
	}
	if len(callResult.SourceNodes) != 1 || callResult.SourceNodes[0].Type != "PARAMETER" {
		t.Fatalf("expected nested receiver parameter provenance, got %#v", callResult.SourceNodes)
	}
	receiver := callResult.SourceNodes[0]
	if receiver.ParameterIndex == nil || *receiver.ParameterIndex != 0 {
		t.Fatalf("expected nested receiver parameter_index=0, got %#v", receiver)
	}
	if len(receiver.SourceNodes) != 1 || receiver.SourceNodes[0].Type != "VALUE" || receiver.SourceNodes[0].Value != "SignatureAlgorithm.HS256" {
		t.Fatalf("expected propagated HS256 value under nested receiver param, got %#v", receiver.SourceNodes)
	}
	if receiver.Location == nil ||
		receiver.Location.FilePath != "io/jsonwebtoken/impl/DefaultJwtBuilder.java" ||
		receiver.Location.Line != 261 {
		t.Fatalf("expected dependency receiver parameter location to be normalized, got %#v", receiver.Location)
	}
	if receiver.SourceNodes[0].Location == nil ||
		receiver.SourceNodes[0].Location.FilePath != "src/main/java/example/app/DynamicJWTController.java" ||
		receiver.SourceNodes[0].Location.Line != 86 {
		t.Fatalf("expected propagated receiver value location from controller call site, got %#v", receiver.SourceNodes[0].Location)
	}
}

func TestCountFindings(t *testing.T) {
	t.Parallel()

	if got := CountFindings(nil); got != 0 {
		t.Fatalf("CountFindings(nil) = %d, want 0", got)
	}

	report := &entities.InterimReport{
		Findings: []entities.Finding{
			{CryptographicAssets: []entities.CryptographicAsset{{}, {}}},
			{CryptographicAssets: []entities.CryptographicAsset{{}}},
		},
	}
	if got := CountFindings(report); got != 3 {
		t.Fatalf("CountFindings(report) = %d, want 3", got)
	}
}

func TestPrintSummary(t *testing.T) {
	t.Parallel()

	if err := PrintSummary("", 3, 7); err != nil {
		t.Fatalf("PrintSummary(empty path): %v", err)
	}
	if err := PrintSummary("-", 3, 7); err != nil {
		t.Fatalf("PrintSummary(stdout marker): %v", err)
	}
	if err := PrintSummary("/tmp/out.json", 1, 2); err != nil {
		t.Fatalf("PrintSummary(custom path): %v", err)
	}
}

func TestValidateFlags(t *testing.T) {
	t.Parallel()

	target := t.TempDir()
	rulesDir := filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir rules dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "go.yaml"), []byte("rules: []"), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	validOpts := ValidationOptions{
		RuleFiles:        []string{"rule.yaml"},
		RuleDirs:         nil,
		NoRemoteRules:    false,
		Scanner:          "semgrep",
		AllowedScanners:  []string{"semgrep", "opengrep"},
		Interfile:        false,
		InterfileScanner: "semgrep",
		Format:           "json",
		SupportedFormats: []string{"json", "cyclonedx"},
		Languages:        []string{" Go ", "PYTHON"},
		ScanDependencies: true,
		ExportCallgraph:  "graph.json",
	}

	langs, err := ValidateFlags(target, validOpts)
	if err != nil {
		t.Fatalf("ValidateFlags(valid): %v", err)
	}
	if len(langs) != 2 || langs[0] != "go" || langs[1] != "python" {
		t.Fatalf("unexpected normalized languages: %#v", langs)
	}

	tests := []struct {
		name   string
		target string
		opts   ValidationOptions
		want   string
	}{
		{
			name:   "missing-target",
			target: filepath.Join(t.TempDir(), "does-not-exist"),
			opts:   validOpts,
			want:   "target path does not exist",
		},
		{
			name:   "no-rules",
			target: target,
			opts:   func() ValidationOptions { o := validOpts; o.RuleFiles = nil; o.NoRemoteRules = true; return o }(),
			want:   "no rules specified",
		},
		{
			name:   "empty-rules-dir",
			target: target,
			opts: func() ValidationOptions {
				o := validOpts
				empty := t.TempDir()
				o.RuleFiles = nil
				o.RuleDirs = []string{empty}
				return o
			}(),
			want: "contains no rule files",
		},
		{
			name:   "invalid-scanner",
			target: target,
			opts:   func() ValidationOptions { o := validOpts; o.Scanner = "unknown"; return o }(),
			want:   "invalid scanner name",
		},
		{
			name:   "invalid-interfile-scanner",
			target: target,
			opts:   func() ValidationOptions { o := validOpts; o.Interfile = true; o.Scanner = "opengrep"; return o }(),
			want:   "--interfile flag is only supported",
		},
		{
			name:   "unsupported-format",
			target: target,
			opts:   func() ValidationOptions { o := validOpts; o.Format = "xml"; return o }(),
			want:   "unsupported output format",
		},
		{
			name:   "callgraph-without-scan-dependencies",
			target: target,
			opts:   func() ValidationOptions { o := validOpts; o.ScanDependencies = false; return o }(),
			want:   "",
		},
		{
			name:   "valid-rules-dir",
			target: target,
			opts: func() ValidationOptions {
				o := validOpts
				o.RuleFiles = nil
				o.RuleDirs = []string{rulesDir}
				o.ExportCallgraph = ""
				return o
			}(),
			want: "",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, gotErr := ValidateFlags(tc.target, tc.opts)
			if tc.want == "" {
				if gotErr != nil {
					t.Fatalf("ValidateFlags() unexpected error: %v", gotErr)
				}
				return
			}
			if gotErr == nil || !strings.Contains(gotErr.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, gotErr)
			}
		})
	}
}

func TestExportCallGraph_CryptoEntryPointsBuiltFromChains(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	// Two findings with overlapping chains to test deduplication.
	//
	// Chain 1: Controller → Service → Cipher.getInstance  (finding A)
	// Chain 2: Service → Cipher.getInstance                (finding A, shorter path)
	// Chain 3: Controller → Service → Mac.getInstance      (finding B)
	//
	// Expected entry points:
	//   Controller: finding A (depth 3), finding B (depth 3)
	//   Service:    finding A (depth 2, shallowest), finding B (depth 2)
	controllerID := callgraph.FunctionID{Package: "com.app", Type: "Controller", Name: "handle#0"}
	serviceID := callgraph.FunctionID{Package: "com.app", Type: "Service", Name: "process#1"}
	cipherGetInstanceID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	macGetInstanceID := callgraph.FunctionID{Package: "javax.crypto", Type: "Mac", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			controllerID.String(): {
				ID:              controllerID,
				FilePath:        joinTestPath(projectRoot, "src/main/java/com/app/Controller.java"),
				StartLine:       10,
				EndLine:         20,
				ReturnType:      "Response",
				Visibility:      callgraph.VisibilityPublic,
				OwnerVisibility: callgraph.VisibilityPublic,
				Calls: []callgraph.FunctionCall{{
					Callee:   serviceID,
					FilePath: joinTestPath(projectRoot, "src/main/java/com/app/Controller.java"),
					Line:     15,
				}},
			},
			serviceID.String(): {
				ID:              serviceID,
				FilePath:        joinTestPath(projectRoot, "src/main/java/com/app/Service.java"),
				StartLine:       30,
				EndLine:         40,
				ReturnType:      "Response",
				Visibility:      callgraph.VisibilityPublic,
				OwnerVisibility: callgraph.VisibilityPackagePrivate,
				Parameters: []callgraph.FunctionParameter{
					{Type: "Request"},
				},
				Calls: []callgraph.FunctionCall{
					{
						Callee:   cipherGetInstanceID,
						FilePath: joinTestPath(projectRoot, "src/main/java/com/app/Service.java"),
						Line:     35,
					},
					{
						Callee:   macGetInstanceID,
						FilePath: joinTestPath(projectRoot, "src/main/java/com/app/Service.java"),
						Line:     36,
					},
				},
			},
		},
		Callers: map[string][]string{
			serviceID.String():           {controllerID.String()},
			cipherGetInstanceID.String(): {serviceID.String()},
			macGetInstanceID.String():    {serviceID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{
			{
				FilePath: "src/main/java/com/app/Service.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 35,
					EndLine:   35,
					Match:     "Cipher.getInstance(\"AES\")",
					Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
					Status:    "pending",
					FindingID: "finding-cipher",
					Source:    "direct",
				}},
			},
			{
				FilePath: "src/main/java/com/app/Service.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 36,
					EndLine:   36,
					Match:     "Mac.getInstance(\"HmacSHA256\")",
					Rules:     []entities.RuleInfo{{ID: "java.crypto.mac", Message: "mac", Severity: "INFO"}},
					Status:    "pending",
					FindingID: "finding-mac",
					Source:    "direct",
				}},
			},
		},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "com.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-entry-points.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json: %v", err)
	}

	if payload.SchemaVersion != "6.5" {
		t.Fatalf("schema_version = %q, want 6.5", payload.SchemaVersion)
	}

	if len(payload.CryptoEntryPoints) == 0 {
		t.Fatal("crypto_entry_points is empty, expected entry points")
	}

	// Build a lookup for assertions
	epMap := make(map[string]callGraphCryptoEntryPoint)
	for _, ep := range payload.CryptoEntryPoints {
		epMap[ep.FunctionName] = ep
	}

	// Controller should be an entry point reaching both findings
	controllerEP, ok := epMap["com.app.Controller.handle"]
	if !ok {
		t.Fatalf("missing entry point for Controller.handle, got: %v", keys(epMap))
	}
	if controllerEP.Class != "com.app.Controller" || controllerEP.Method != "handle" {
		t.Fatalf("unexpected class/method: %q / %q", controllerEP.Class, controllerEP.Method)
	}
	if controllerEP.CanonicalSignature != "com.app.Controller.handle(): Response" {
		t.Fatalf("unexpected controller canonical signature: %q", controllerEP.CanonicalSignature)
	}
	if controllerEP.ReturnType != "Response" {
		t.Fatalf("unexpected controller return_type: %q", controllerEP.ReturnType)
	}
	if controllerEP.Visibility != callgraph.VisibilityPublic || controllerEP.OwnerVisibility != callgraph.VisibilityPublic {
		t.Fatalf("unexpected controller visibilities: %q / %q", controllerEP.Visibility, controllerEP.OwnerVisibility)
	}
	if len(controllerEP.ParameterTypes) != 0 {
		t.Fatalf("unexpected controller parameter_types: %#v", controllerEP.ParameterTypes)
	}
	if len(controllerEP.ReachableFindings) != 2 {
		t.Fatalf("Controller.handle should reach 2 findings, got %d", len(controllerEP.ReachableFindings))
	}

	// Service should also be an entry point with shallowest depth
	serviceEP, ok := epMap["com.app.Service.process"]
	if !ok {
		t.Fatalf("missing entry point for Service.process, got: %v", keys(epMap))
	}
	if len(serviceEP.ReachableFindings) != 2 {
		t.Fatalf("Service.process should reach 2 findings, got %d", len(serviceEP.ReachableFindings))
	}
	if serviceEP.CanonicalSignature != "com.app.Service.process(Request): Response" {
		t.Fatalf("unexpected service canonical signature: %q", serviceEP.CanonicalSignature)
	}
	if serviceEP.ReturnType != "Response" {
		t.Fatalf("unexpected service return_type: %q", serviceEP.ReturnType)
	}
	if serviceEP.Visibility != callgraph.VisibilityPublic || serviceEP.OwnerVisibility != callgraph.VisibilityPackagePrivate {
		t.Fatalf("unexpected service visibilities: %q / %q", serviceEP.Visibility, serviceEP.OwnerVisibility)
	}
	if len(serviceEP.ParameterTypes) != 1 || serviceEP.ParameterTypes[0] != "Request" {
		t.Fatalf("unexpected service parameter_types: %#v", serviceEP.ParameterTypes)
	}
	chain := payload.FindingGraphs[0].CallChains[0]
	if len(chain) < 2 {
		t.Fatalf("expected chain with at least 2 nodes, got %d", len(chain))
	}
	if chain[0].Visibility != callgraph.VisibilityPublic || chain[0].OwnerVisibility != callgraph.VisibilityPublic {
		t.Fatalf("unexpected controller chain visibilities: %q / %q", chain[0].Visibility, chain[0].OwnerVisibility)
	}
	if chain[1].Visibility != callgraph.VisibilityPublic || chain[1].OwnerVisibility != callgraph.VisibilityPackagePrivate {
		t.Fatalf("unexpected service chain visibilities: %q / %q", chain[1].Visibility, chain[1].OwnerVisibility)
	}
	// Service.process → Cipher.getInstance is depth 2 (Service node + crypto node)
	for _, rf := range serviceEP.ReachableFindings {
		if rf.ChainDepth > 2 {
			t.Fatalf("Service.process chain_depth should be ≤ 2, got %d for %s", rf.ChainDepth, rf.FindingID)
		}
	}
}

func TestExportCallGraph_CryptoEntryPointsPreservesOverloadedFunctions(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	stringOverloadID := callgraph.FunctionID{Package: "com.app", Type: "Service", Name: "process#1$String"}
	bytesOverloadID := callgraph.FunctionID{Package: "com.app", Type: "Service", Name: "process#1$byte[]"}
	cipherGetInstanceID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	macGetInstanceID := callgraph.FunctionID{Package: "javax.crypto", Type: "Mac", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			stringOverloadID.String(): {
				ID:         stringOverloadID,
				FilePath:   joinTestPath(projectRoot, "src/main/java/com/app/Service.java"),
				StartLine:  10,
				EndLine:    20,
				ReturnType: "Response",
				Parameters: []callgraph.FunctionParameter{{Type: "String"}},
				Calls: []callgraph.FunctionCall{{
					Callee:   cipherGetInstanceID,
					FilePath: joinTestPath(projectRoot, "src/main/java/com/app/Service.java"),
					Line:     15,
				}},
			},
			bytesOverloadID.String(): {
				ID:         bytesOverloadID,
				FilePath:   joinTestPath(projectRoot, "src/main/java/com/app/Service.java"),
				StartLine:  30,
				EndLine:    40,
				ReturnType: "Response",
				Parameters: []callgraph.FunctionParameter{{Type: "byte[]"}},
				Calls: []callgraph.FunctionCall{{
					Callee:   macGetInstanceID,
					FilePath: joinTestPath(projectRoot, "src/main/java/com/app/Service.java"),
					Line:     35,
				}},
			},
		},
		Callers: map[string][]string{
			cipherGetInstanceID.String(): {stringOverloadID.String()},
			macGetInstanceID.String():    {bytesOverloadID.String()},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{
			{
				FilePath: "src/main/java/com/app/Service.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 15,
					EndLine:   15,
					Match:     "Cipher.getInstance(\"AES\")",
					Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
					Status:    "pending",
					FindingID: "finding-cipher-overload",
					Source:    "direct",
				}},
			},
			{
				FilePath: "src/main/java/com/app/Service.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 35,
					EndLine:   35,
					Match:     "Mac.getInstance(\"HmacSHA256\")",
					Rules:     []entities.RuleInfo{{ID: "java.crypto.mac", Message: "mac", Severity: "INFO"}},
					Status:    "pending",
					FindingID: "finding-mac-overload",
					Source:    "direct",
				}},
			},
		},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "com.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-entry-points-overloaded.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json: %v", err)
	}

	var overloaded []callGraphCryptoEntryPoint
	for _, ep := range payload.CryptoEntryPoints {
		if ep.FunctionName == "com.app.Service.process" {
			overloaded = append(overloaded, ep)
		}
	}
	if len(overloaded) != 2 {
		t.Fatalf("expected 2 overloaded entry point records, got %d (%#v)", len(overloaded), overloaded)
	}

	var foundString, foundBytes bool
	for _, ep := range overloaded {
		switch ep.CanonicalSignature {
		case "com.app.Service.process(String): Response":
			foundString = true
		case "com.app.Service.process(byte[]): Response":
			foundBytes = true
		}
	}
	if !foundString || !foundBytes {
		t.Fatalf("missing overloaded canonical signatures: %#v", overloaded)
	}
}

func TestExportCallGraph_NormalizesExternalConstructorReturnType(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	constructorID := callgraph.FunctionID{Package: "javax.crypto.spec", Type: "PBEKeySpec", Name: "<init>"}
	containerID := callgraph.FunctionID{Package: "example.app", Type: "KeyOps", Name: "derive#0"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			containerID.String(): {
				ID:        containerID,
				FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/KeyOps.java"),
				StartLine: 10,
				EndLine:   20,
				Calls: []callgraph.FunctionCall{{
					Callee:    constructorID,
					FilePath:  joinTestPath(projectRoot, "src/main/java/example/app/KeyOps.java"),
					Line:      14,
					Arguments: []string{"password", "salt", "iterations", "keyLength"},
				}},
			},
		},
		ExternalMethodSignatures: map[string][]callgraph.ExternalMethodSignature{
			callgraph.ExternalMethodSignatureKey(constructorID): {{
				ParameterTypes: []string{"char[]", "byte[]", "int", "int"},
				ReturnType:     "void",
			}},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "src/main/java/example/app/KeyOps.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 14,
				EndLine:   14,
				Match:     "new PBEKeySpec(password, salt, iterations, keyLength)",
				Rules:     []entities.RuleInfo{{ID: "java.kdf.pbkdf2", Message: "pbkdf2", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "PBEKeySpec"},
				FindingID: "constructor-normalization-1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-constructor-normalization.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	var payload callGraphExportV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	cryptoCall := payload.FindingGraphs[0].CallChains[0][0].CryptoCall
	if cryptoCall == nil {
		t.Fatal("expected crypto_call metadata")
	}
	if cryptoCall.ReturnType != "PBEKeySpec" {
		t.Fatalf("return_type = %q, want PBEKeySpec", cryptoCall.ReturnType)
	}
	if cryptoCall.CanonicalSignature != "javax.crypto.spec.PBEKeySpec.<init>(char[], byte[], int, int): PBEKeySpec" {
		t.Fatalf("canonical_signature = %q, want normalized constructor signature", cryptoCall.CanonicalSignature)
	}
}

func TestExportCallGraph_CryptoEntryPointsEmptyWhenNoChains(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{},
		Callers:   map[string][]string{},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "src/main/java/com/app/App.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 10,
				EndLine:   10,
				Match:     "Cipher.getInstance(\"AES\")",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher", Message: "cipher", Severity: "INFO"}},
				Status:    "pending",
				FindingID: "unresolved-1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "com.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-no-chains.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	var payload callGraphExportV2
	data, _ := os.ReadFile(out)
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json: %v", err)
	}

	if len(payload.CryptoEntryPoints) != 0 {
		t.Fatalf("crypto_entry_points should be empty for unresolved findings, got %d entries", len(payload.CryptoEntryPoints))
	}
}

func keys(m map[string]callGraphCryptoEntryPoint) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

// TestExportCallGraph_ExposesStructuredGenericParameters verifies that a
// crypto chain whose entry function and external dependency both carry
// parametrized types preserves that structure in the exported JSON. The
// flat parameter_types/return_type strings keep the erased name (so existing
// consumers continue to work) while the new *_ref fields surface nested
// generic_parameters per IBM/QSC's CBOM enrichment request.
func TestExportCallGraph_ExposesStructuredGenericParameters(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	digestProviderID := callgraph.FunctionID{Package: "org.bouncycastle.operator.bc", Type: "BcDefaultDigestProvider", Name: "createTable#0"}
	entryID := callgraph.FunctionID{Package: "example.app", Type: "Service", Name: "lookup#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			entryID.String(): {
				ID:         entryID,
				FilePath:   joinTestPath(projectRoot, "src/main/java/example/app/Service.java"),
				StartLine:  10,
				EndLine:    30,
				ReturnType: "Map",
				ReturnTypeRef: callgraph.TypeRef{
					Name: "Map",
					GenericParameters: []callgraph.TypeRef{
						{Name: "String"},
						{Name: "Digest"},
					},
				},
				Parameters: []callgraph.FunctionParameter{{
					Type: "List",
					TypeRef: callgraph.TypeRef{
						Name:              "List",
						GenericParameters: []callgraph.TypeRef{{Name: "String"}},
					},
				}},
				Calls: []callgraph.FunctionCall{{
					Callee:   digestProviderID,
					FilePath: joinTestPath(projectRoot, "src/main/java/example/app/Service.java"),
					Line:     22,
				}},
			},
		},
		ExternalMethodSignatures: map[string][]callgraph.ExternalMethodSignature{
			callgraph.ExternalMethodSignatureKey(digestProviderID): {{
				ParameterTypes: nil,
				ReturnType:     "java.util.Map",
				ReturnTypeRef: callgraph.TypeRef{
					Name: "Map",
					GenericParameters: []callgraph.TypeRef{
						{Name: "String"},
						{Name: "Digest"},
					},
				},
			}},
		},
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "src/main/java/example/app/Service.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 22,
				EndLine:   22,
				Match:     "BcDefaultDigestProvider.createTable()",
				Rules:     []entities.RuleInfo{{ID: "java.bc.digest", Message: "digest table", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "BcDefaultDigestProvider.createTable"},
				FindingID: "generics-1",
				Source:    "direct",
			}},
		}},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		RootModule:  "example.app",
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
	}

	out := filepath.Join(t.TempDir(), "cg-generics.json")
	if err := ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph(json): %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var payload callGraphExportV2
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	if len(payload.FindingGraphs) != 1 || len(payload.FindingGraphs[0].CallChains) == 0 {
		t.Fatalf("expected one finding graph with chains, got %#v", payload.FindingGraphs)
	}
	chain := payload.FindingGraphs[0].CallChains[0]
	if len(chain) == 0 {
		t.Fatal("empty chain")
	}

	entry := chain[0]
	if entry.ReturnType != "Map" {
		t.Fatalf("entry return_type = %q, want erased %q", entry.ReturnType, "Map")
	}
	if entry.ReturnTypeRef == nil {
		t.Fatalf("entry return_type_ref is nil; expected structured generics")
	}
	if entry.ReturnTypeRef.Name != "Map" {
		t.Fatalf("entry return_type_ref.name = %q, want Map", entry.ReturnTypeRef.Name)
	}
	if len(entry.ReturnTypeRef.GenericParameters) != 2 ||
		entry.ReturnTypeRef.GenericParameters[0].Name != "String" ||
		entry.ReturnTypeRef.GenericParameters[1].Name != "Digest" {
		t.Fatalf("entry return_type_ref.generic_parameters = %#v, want [String, Digest]", entry.ReturnTypeRef.GenericParameters)
	}

	if len(entry.ParameterTypes) != 1 || entry.ParameterTypes[0] != "List" {
		t.Fatalf("entry parameter_types = %#v, want [List]", entry.ParameterTypes)
	}
	if len(entry.ParameterTypeRefs) != 1 {
		t.Fatalf("entry parameter_type_refs = %#v, want 1 entry", entry.ParameterTypeRefs)
	}
	if entry.ParameterTypeRefs[0].Name != "List" || len(entry.ParameterTypeRefs[0].GenericParameters) != 1 ||
		entry.ParameterTypeRefs[0].GenericParameters[0].Name != "String" {
		t.Fatalf("entry parameter_type_refs[0] = %#v, want List<String>", entry.ParameterTypeRefs[0])
	}

	terminal := chain[len(chain)-1]
	if terminal.CryptoCall == nil {
		t.Fatal("expected crypto_call on terminal chain node")
	}
	cryptoCall := *terminal.CryptoCall
	if cryptoCall.ReturnType != "java.util.Map" {
		t.Fatalf("crypto_call.return_type = %q, want java.util.Map", cryptoCall.ReturnType)
	}
	if cryptoCall.ReturnTypeRef == nil {
		t.Fatalf("crypto_call.return_type_ref is nil; expected structured generics from external signature")
	}
	if cryptoCall.ReturnTypeRef.Name != "Map" || len(cryptoCall.ReturnTypeRef.GenericParameters) != 2 {
		t.Fatalf("crypto_call.return_type_ref = %#v, want Map<String, Digest>", cryptoCall.ReturnTypeRef)
	}

	if !strings.Contains(string(data), "\"return_type_ref\"") {
		t.Fatalf("exported JSON missing return_type_ref field; got: %s", data)
	}
	if !strings.Contains(string(data), "\"parameter_type_refs\"") {
		t.Fatalf("exported JSON missing parameter_type_refs field; got: %s", data)
	}
}
