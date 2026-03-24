package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

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
		{name: "weeks", input: "2w", want: 14 * 24 * time.Hour},
		{name: "invalid", input: "not-a-duration", wantErr: true},
		{name: "invalid-days", input: "xd", wantErr: true},
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
				MatchType: "semgrep",
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
		if payload.SchemaVersion != "2.0" {
			t.Fatalf("schema_version = %q, want 2.0", payload.SchemaVersion)
		}
		if len(payload.FindingGraphs) != 1 {
			t.Fatalf("finding_graphs count = %d, want 1", len(payload.FindingGraphs))
		}
		fg := payload.FindingGraphs[0]
		if fg.FindingID != "ab12cd34" {
			t.Fatalf("finding_id = %q, want ab12cd34", fg.FindingID)
		}
		if fg.ContainingFunction == nil || fg.ContainingFunction.FunctionName == "" {
			t.Fatal("containing_function should be set")
		}
		if fg.ContainingFunction.FunctionName != "main" {
			t.Fatalf("containing_function.function_name = %q, want main", fg.ContainingFunction.FunctionName)
		}
		if fg.ContainingFunction.Namespace != "app" {
			t.Fatalf("containing_function.namespace = %q, want app", fg.ContainingFunction.Namespace)
		}
		if len(fg.BackwardPaths) == 0 {
			t.Fatal("backward_paths should have at least a self-chain")
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
			name:   "callgraph-requires-scan-dependencies",
			target: target,
			opts:   func() ValidationOptions { o := validOpts; o.ScanDependencies = false; return o }(),
			want:   "--export-callgraph requires --scan-dependencies",
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
