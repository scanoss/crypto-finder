package dependency

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

func TestParsePipShowOutput(t *testing.T) {
	output := `Name: cryptography
Version: 41.0.7
Location: /usr/lib/python3/dist-packages
Requires: cffi
---
Name: cffi
Version: 1.16.0
Location: /usr/lib/python3/dist-packages
Requires: pycparser
---
Name: pycparser
Version: 2.21
Location: /usr/lib/python3/dist-packages
Requires: `

	result := parsePipShowOutput(output)

	if len(result) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(result))
	}

	// Check cryptography
	crypto, ok := result["cryptography"]
	if !ok {
		t.Fatal("missing 'cryptography' package")
	}
	if crypto.Version != "41.0.7" {
		t.Errorf("cryptography version = %q, want %q", crypto.Version, "41.0.7")
	}
	if crypto.Location != "/usr/lib/python3/dist-packages" {
		t.Errorf("cryptography location = %q, want %q", crypto.Location, "/usr/lib/python3/dist-packages")
	}
	if crypto.Requires != "cffi" {
		t.Errorf("cryptography requires = %q, want %q", crypto.Requires, "cffi")
	}

	// Check cffi
	cffi, ok := result["cffi"]
	if !ok {
		t.Fatal("missing 'cffi' package")
	}
	if cffi.Requires != "pycparser" {
		t.Errorf("cffi requires = %q, want %q", cffi.Requires, "pycparser")
	}

	// Check pycparser (no dependencies)
	pycparser, ok := result["pycparser"]
	if !ok {
		t.Fatal("missing 'pycparser' package")
	}
	if pycparser.Requires != "" {
		t.Errorf("pycparser requires = %q, want empty", pycparser.Requires)
	}
}

func TestParsePipShowOutput_Empty(t *testing.T) {
	result := parsePipShowOutput("")
	if len(result) != 0 {
		t.Errorf("expected 0 packages from empty output, got %d", len(result))
	}
}

func TestParsePyprojectName(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "standard pyproject.toml",
			content: `[build-system]
requires = ["setuptools"]

[project]
name = "my-crypto-lib"
version = "1.0.0"
`,
			want: "my-crypto-lib",
		},
		{
			name: "single-quoted name",
			content: `[project]
name = 'another-lib'
`,
			want: "another-lib",
		},
		{
			name:    "no project section",
			content: `[build-system]\nrequires = ["setuptools"]`,
			want:    "",
		},
		{
			name:    "empty content",
			content: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePyprojectName(tt.content)
			if got != tt.want {
				t.Errorf("parsePyprojectName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"cryptography", "cryptography"},
		{"Pillow", "pillow"},
		{"my-package", "my_package"},
		{"some.dotted.name", "some_dotted_name"},
		{"PyYAML", "pyyaml"},
	}

	for _, tt := range tests {
		got := normalizePackageName(tt.input)
		if got != tt.want {
			t.Errorf("normalizePackageName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPipResolver_Ecosystem(t *testing.T) {
	r := NewPipResolver()
	if got := r.Ecosystem(); got != "python" {
		t.Errorf("Ecosystem() = %q, want %q", got, "python")
	}
}

func TestParsePackagesDistributions(t *testing.T) {
	// Simulates the JSON from: python3 -c "import json,importlib.metadata as m; print(json.dumps(m.packages_distributions()))"
	input := []byte(`{
		"bs4": ["beautifulsoup4"],
		"opentelemetry": ["opentelemetry-api", "opentelemetry-sdk"],
		"ruamel": ["ruamel.yaml"],
		"typing_extensions": ["typing-extensions"],
		"six": ["six"],
		"PIL": ["Pillow"]
	}`)

	result := parsePackagesDistributions(input)

	tests := []struct {
		distName    string
		wantImports []string
	}{
		{"beautifulsoup4", []string{"bs4"}},
		{"opentelemetry_api", []string{"opentelemetry"}},
		{"opentelemetry_sdk", []string{"opentelemetry"}},
		{"ruamel_yaml", []string{"ruamel"}},
		{"typing_extensions", []string{"typing_extensions"}},
		{"six", []string{"six"}},
		{"pillow", []string{"PIL"}},
	}

	for _, tt := range tests {
		t.Run(tt.distName, func(t *testing.T) {
			got := result[tt.distName]
			if got == nil {
				t.Fatalf("missing mapping for dist %q", tt.distName)
			}
			sort.Strings(got)
			sort.Strings(tt.wantImports)
			if !slices.Equal(got, tt.wantImports) {
				t.Errorf("dist %q → %v, want %v", tt.distName, got, tt.wantImports)
			}
		})
	}
}

func TestParsePackagesDistributions_InvalidJSON(t *testing.T) {
	result := parsePackagesDistributions([]byte(`not json`))
	if result != nil {
		t.Errorf("expected nil for invalid JSON, got %v", result)
	}
}

func TestParsePackagesDistributions_Empty(t *testing.T) {
	result := parsePackagesDistributions([]byte(`{}`))
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestResolvePackageDir_WithMapping(t *testing.T) {
	// Create a temp site-packages directory structure
	tmpDir := t.TempDir()
	sitePackages := tmpDir

	// Create directory packages
	os.MkdirAll(filepath.Join(sitePackages, "bs4"), 0o755)
	os.MkdirAll(filepath.Join(sitePackages, "PIL"), 0o755)

	// Create a single-file module
	os.WriteFile(filepath.Join(sitePackages, "six.py"), []byte("# six"), 0o644)

	distToImport := map[string][]string{
		"beautifulsoup4": {"bs4"},
		"pillow":         {"PIL"},
		"six":            {"six"},
	}

	r := NewPipResolver()

	tests := []struct {
		name       string
		pkgName    string
		info       pipShowInfo
		wantDir    string
		wantReason skipReason
	}{
		{
			name:    "beautifulsoup4 resolves via mapping to bs4/",
			pkgName: "beautifulsoup4",
			info:    pipShowInfo{Location: sitePackages},
			wantDir: filepath.Join(sitePackages, "bs4"),
		},
		{
			name:    "Pillow resolves via mapping to PIL/",
			pkgName: "Pillow",
			info:    pipShowInfo{Location: sitePackages},
			wantDir: filepath.Join(sitePackages, "PIL"),
		},
		{
			name:       "six is single-file, skipped",
			pkgName:    "six",
			info:       pipShowInfo{Location: sitePackages},
			wantDir:    "",
			wantReason: skipReasonSingleFile,
		},
		{
			name:       "missing-pkg has no source",
			pkgName:    "missing-pkg",
			info:       pipShowInfo{Location: sitePackages},
			wantDir:    "",
			wantReason: skipReasonNoSource,
		},
		{
			name:       "empty location",
			pkgName:    "anything",
			info:       pipShowInfo{Location: ""},
			wantDir:    "",
			wantReason: skipReasonNoSource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, reason := r.resolvePackageDir(tt.pkgName, tt.info, distToImport)
			if dir != tt.wantDir {
				t.Errorf("dir = %q, want %q", dir, tt.wantDir)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %v, want %v", reason, tt.wantReason)
			}
		})
	}
}

func TestResolvePackageDir_FallbackWithoutMapping(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a package dir matching the normalized name
	os.MkdirAll(filepath.Join(tmpDir, "my_package"), 0o755)

	r := NewPipResolver()

	// With nil distToImport, falls back to heuristic
	dir, reason := r.resolvePackageDir("my-package", pipShowInfo{Location: tmpDir}, nil)
	if dir != filepath.Join(tmpDir, "my_package") {
		t.Errorf("dir = %q, want %q", dir, filepath.Join(tmpDir, "my_package"))
	}
	if reason != 0 {
		t.Errorf("reason = %v, want 0", reason)
	}
}

func TestBuildDistInfoMapping(t *testing.T) {
	// Create a fake site-packages with dist-info directories
	sitePackages := t.TempDir()

	// beautifulsoup4-4.12.3.dist-info/top_level.txt → "bs4"
	distInfo1 := filepath.Join(sitePackages, "beautifulsoup4-4.12.3.dist-info")
	os.MkdirAll(distInfo1, 0o755)
	os.WriteFile(filepath.Join(distInfo1, "top_level.txt"), []byte("bs4\n"), 0o644)

	// opentelemetry_api-1.0.0.dist-info/top_level.txt → "opentelemetry"
	distInfo2 := filepath.Join(sitePackages, "opentelemetry_api-1.0.0.dist-info")
	os.MkdirAll(distInfo2, 0o755)
	os.WriteFile(filepath.Join(distInfo2, "top_level.txt"), []byte("opentelemetry\n"), 0o644)

	// ruamel.yaml-0.18.0.dist-info/top_level.txt → "ruamel"
	distInfo3 := filepath.Join(sitePackages, "ruamel.yaml-0.18.0.dist-info")
	os.MkdirAll(distInfo3, 0o755)
	os.WriteFile(filepath.Join(distInfo3, "top_level.txt"), []byte("ruamel\n"), 0o644)

	// typing_extensions-4.12.0.dist-info/top_level.txt → "typing_extensions"
	distInfo4 := filepath.Join(sitePackages, "typing_extensions-4.12.0.dist-info")
	os.MkdirAll(distInfo4, 0o755)
	os.WriteFile(filepath.Join(distInfo4, "top_level.txt"), []byte("typing_extensions\n"), 0o644)

	// six-1.16.0.dist-info/top_level.txt → "six" (single-file module)
	distInfo5 := filepath.Join(sitePackages, "six-1.16.0.dist-info")
	os.MkdirAll(distInfo5, 0o755)
	os.WriteFile(filepath.Join(distInfo5, "top_level.txt"), []byte("six\n"), 0o644)

	// multi_top-1.0.dist-info/top_level.txt → two import names
	distInfo6 := filepath.Join(sitePackages, "multi_top-1.0.dist-info")
	os.MkdirAll(distInfo6, 0o755)
	os.WriteFile(filepath.Join(distInfo6, "top_level.txt"), []byte("foo\nbar\n"), 0o644)

	// cyclonedx_python_lib-7.0.0.dist-info — NO top_level.txt, only RECORD
	distInfo7 := filepath.Join(sitePackages, "cyclonedx_python_lib-7.0.0.dist-info")
	os.MkdirAll(distInfo7, 0o755)
	os.WriteFile(filepath.Join(distInfo7, "RECORD"), []byte(
		"cyclonedx/__init__.py,sha256=abc,100\n"+
			"cyclonedx/model/__init__.py,sha256=def,200\n"+
			"cyclonedx_python_lib-7.0.0.dist-info/METADATA,sha256=ghi,300\n"+
			"cyclonedx_python_lib-7.0.0.dist-info/RECORD,,\n",
	), 0o644)

	// markdown_it-3.0.0.dist-info — NO top_level.txt, only RECORD
	distInfo8 := filepath.Join(sitePackages, "markdown_it-3.0.0.dist-info")
	os.MkdirAll(distInfo8, 0o755)
	os.WriteFile(filepath.Join(distInfo8, "RECORD"), []byte(
		"markdown_it/__init__.py,sha256=abc,50\n"+
			"markdown_it/main.py,sha256=def,1000\n"+
			"markdown_it-3.0.0.dist-info/RECORD,,\n",
	), 0o644)

	result := buildDistInfoMapping([]string{sitePackages})

	tests := []struct {
		distName    string
		wantImports []string
	}{
		{"beautifulsoup4", []string{"bs4"}},
		{"opentelemetry_api", []string{"opentelemetry"}},
		{"ruamel_yaml", []string{"ruamel"}},
		{"typing_extensions", []string{"typing_extensions"}},
		{"six", []string{"six"}},
		{"multi_top", []string{"foo", "bar"}},
		{"cyclonedx_python_lib", []string{"cyclonedx"}},
		{"markdown_it", []string{"markdown_it"}},
	}

	for _, tt := range tests {
		t.Run(tt.distName, func(t *testing.T) {
			got := result[tt.distName]
			if got == nil {
				t.Fatalf("missing mapping for dist %q, full map: %v", tt.distName, result)
			}
			sort.Strings(got)
			sort.Strings(tt.wantImports)
			if !slices.Equal(got, tt.wantImports) {
				t.Errorf("dist %q → %v, want %v", tt.distName, got, tt.wantImports)
			}
		})
	}
}

func TestBuildDistInfoMapping_EmptyLocations(t *testing.T) {
	result := buildDistInfoMapping(nil)
	if len(result) != 0 {
		t.Errorf("expected empty map for nil locations, got %d entries", len(result))
	}
}

func TestParseRecordImportNames(t *testing.T) {
	tests := []struct {
		name            string
		recordContent   string
		distInfoDirName string
		wantImports     []string
	}{
		{
			name: "standard package with __init__.py",
			recordContent: "bs4/__init__.py,sha256=abc,100\n" +
				"bs4/element.py,sha256=def,5000\n" +
				"bs4/builder/__init__.py,sha256=ghi,200\n" +
				"beautifulsoup4-4.12.3.dist-info/METADATA,sha256=jkl,300\n" +
				"beautifulsoup4-4.12.3.dist-info/RECORD,,\n",
			distInfoDirName: "beautifulsoup4-4.12.3.dist-info",
			wantImports:     []string{"bs4"},
		},
		{
			name: "single-file module",
			recordContent: "typing_extensions.py,sha256=abc,50000\n" +
				"typing_extensions-4.12.0.dist-info/METADATA,sha256=def,300\n" +
				"typing_extensions-4.12.0.dist-info/RECORD,,\n",
			distInfoDirName: "typing_extensions-4.12.0.dist-info",
			wantImports:     []string{"typing_extensions"},
		},
		{
			name: "namespace package — no top-level __init__.py, inferred from sub-package",
			recordContent: "google/protobuf/__init__.py,sha256=abc,100\n" +
				"google/protobuf/descriptor.py,sha256=def,5000\n" +
				"protobuf-4.25.0.dist-info/METADATA,sha256=ghi,300\n" +
				"protobuf-4.25.0.dist-info/RECORD,,\n",
			distInfoDirName: "protobuf-4.25.0.dist-info",
			wantImports:     []string{"google"}, // namespace candidate from google/protobuf/__init__.py
		},
		{
			name: "binary-only package — no .py files",
			recordContent: "rpds/rpds.cpython-311-x86_64-linux-gnu.so,sha256=abc,100000\n" +
				"rpds_py-0.18.0.dist-info/METADATA,sha256=def,300\n" +
				"rpds_py-0.18.0.dist-info/RECORD,,\n",
			distInfoDirName: "rpds_py-0.18.0.dist-info",
			wantImports:     nil,
		},
		{
			name: "package with both __init__.py and single-file module",
			recordContent: "mypkg/__init__.py,sha256=abc,100\n" +
				"mypkg_utils.py,sha256=def,500\n" +
				"mypkg-1.0.dist-info/RECORD,,\n",
			distInfoDirName: "mypkg-1.0.dist-info",
			wantImports:     []string{"mypkg", "mypkg_utils"},
		},
		{
			name: "namespace package with depth-1 __init__.py takes priority",
			recordContent: "mypkg/__init__.py,sha256=abc,100\n" +
				"mypkg/sub/__init__.py,sha256=def,200\n" +
				"mypkg-1.0.dist-info/RECORD,,\n",
			distInfoDirName: "mypkg-1.0.dist-info",
			wantImports:     []string{"mypkg"}, // only one entry, not duplicated
		},
		{
			name: "opentelemetry-style namespace package",
			recordContent: "opentelemetry/trace/__init__.py,sha256=abc,100\n" +
				"opentelemetry/trace/span.py,sha256=def,5000\n" +
				"opentelemetry/context/__init__.py,sha256=ghi,200\n" +
				"opentelemetry_api-1.0.0.dist-info/RECORD,,\n",
			distInfoDirName: "opentelemetry_api-1.0.0.dist-info",
			wantImports:     []string{"opentelemetry"}, // inferred from sub-packages
		},
		{
			name:            "empty RECORD file",
			recordContent:   "",
			distInfoDirName: "empty-1.0.dist-info",
			wantImports:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write RECORD to a temp dir
			tmpDir := t.TempDir()
			distInfoDir := filepath.Join(tmpDir, tt.distInfoDirName)
			os.MkdirAll(distInfoDir, 0o755)
			recordPath := filepath.Join(distInfoDir, "RECORD")
			os.WriteFile(recordPath, []byte(tt.recordContent), 0o644)

			got := parseRecordImportNames(recordPath, tt.distInfoDirName)
			sort.Strings(got)
			sort.Strings(tt.wantImports)

			if len(got) == 0 && len(tt.wantImports) == 0 {
				return // both nil/empty — pass
			}
			if !slices.Equal(got, tt.wantImports) {
				t.Errorf("parseRecordImportNames() = %v, want %v", got, tt.wantImports)
			}
		})
	}
}

func TestParseRecordImportNames_MissingFile(t *testing.T) {
	got := parseRecordImportNames("/nonexistent/path/RECORD", "fake-1.0.dist-info")
	if got != nil {
		t.Errorf("expected nil for missing RECORD, got %v", got)
	}
}

func TestCollectUniqueLocations(t *testing.T) {
	infoMap := map[string]pipShowInfo{
		"pkg1": {Location: "/usr/lib/python3/dist-packages"},
		"pkg2": {Location: "/usr/lib/python3/dist-packages"},
		"pkg3": {Location: "/home/user/.local/lib/python3/dist-packages"},
		"pkg4": {Location: ""},
	}

	locations := collectUniqueLocations(infoMap)
	sort.Strings(locations)

	if len(locations) != 2 {
		t.Fatalf("expected 2 unique locations, got %d: %v", len(locations), locations)
	}
	if locations[0] != "/home/user/.local/lib/python3/dist-packages" {
		t.Errorf("locations[0] = %q, unexpected", locations[0])
	}
	if locations[1] != "/usr/lib/python3/dist-packages" {
		t.Errorf("locations[1] = %q, unexpected", locations[1])
	}
}
