// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package opengrep_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
)

const wireFixtures = "testdata/native-wire"

// Child-only dispatcher: normal tests do not invoke this branch. The actual
// built-in adapter starts this binary through its ordinary command execution.
func init() {
	if os.Getenv("CRYPTO_WIRE_REPLAY_CHILD") != "1" {
		return
	}
	args := strings.Join(os.Args[1:], " ")
	if strings.Contains(args, "--version") {
		if os.Getenv("CRYPTO_WIRE_REPLAY_MODE") == "x-tool-version" {
			fmt.Print("1.12.1\n")
		} else {
			fmt.Print("1.29.0\n")
		}
		os.Exit(0)
	}
	if strings.Contains(args, "--help") {
		fmt.Print("--x-ignore-semgrepignore-files\n")
		os.Exit(0)
	}
	if !strings.Contains(args, "--config") {
		os.Exit(97)
	}
	mode := os.Getenv("CRYPTO_WIRE_REPLAY_MODE")
	capture := "positive"
	if strings.HasPrefix(mode, "x-") {
		capture = "xnotice"
	}
	if mode == "no-match" || mode == "telemetry" {
		capture = mode
	}
	root := os.Getenv("CRYPTO_WIRE_REPLAY_FIXTURES")
	data, err := os.ReadFile(filepath.Join(root, capture+".stdout.json"))
	if err != nil {
		panic(err)
	}
	stderr, err := os.ReadFile(filepath.Join(root, capture+".stderr.txt"))
	if err != nil {
		panic(err)
	}
	// Only the two actual source-path fields contain @TARGET@. All rule IDs,
	// metadata, match spans, metavariables and fingerprints stay byte-identical.
	target, err := json.Marshal(filepath.ToSlash(os.Getenv("CRYPTO_WIRE_REPLAY_TARGET")))
	if err != nil {
		panic(err)
	}
	data = bytes.ReplaceAll(data, []byte("@TARGET@"), target[1:len(target)-1])
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		panic(err)
	}
	switch mode {
	case "x-extra-field":
		var results []map[string]json.RawMessage
		_ = json.Unmarshal(wire["results"], &results)
		var extra map[string]json.RawMessage
		_ = json.Unmarshal(results[0]["extra"], &extra)
		extra["future"] = json.RawMessage(`true`)
		results[0]["extra"], _ = json.Marshal(extra)
		wire["results"], _ = json.Marshal(results)
	case "x-result":
		var results []map[string]json.RawMessage
		_ = json.Unmarshal(wire["results"], &results)
		results[0]["future"] = json.RawMessage(`true`)
		wire["results"], _ = json.Marshal(results)
	case "x-result-unscanned", "x-result-outside", "x-result-alias":
		var results []map[string]json.RawMessage
		_ = json.Unmarshal(wire["results"], &results)
		path := filepath.Join(os.Getenv("CRYPTO_WIRE_REPLAY_TARGET"), "other.py")
		if mode == "x-result-outside" {
			path = filepath.Join(filepath.Dir(os.Getenv("CRYPTO_WIRE_REPLAY_TARGET")), "outside.py")
		}
		if mode == "x-result-alias" {
			path = os.Getenv("CRYPTO_WIRE_REPLAY_TARGET") + string(filepath.Separator) + "sub" + string(filepath.Separator) + ".." + string(filepath.Separator) + "compute.py"
		}
		results[0]["path"], _ = json.Marshal(filepath.ToSlash(path))
		wire["results"], _ = json.Marshal(results)
	case "x-position":
		var results []map[string]json.RawMessage
		_ = json.Unmarshal(wire["results"], &results)
		results[0]["start"] = json.RawMessage(`{"line":5,"col":12,"offset":89,"future":true}`)
		wire["results"], _ = json.Marshal(results)
	case "x-engine":
		data = bytes.ReplaceAll(data, []byte(`"engine_kind":"OSS"`), []byte(`"engine_kind":"OTHER"`))
		_ = json.Unmarshal(data, &wire)
	case "x-punctuation":
		stderr = bytes.ReplaceAll(stderr, []byte("'--x-'."), []byte("'--x-'!"))
	case "x-timestamp":
		stderr = bytes.ReplaceAll(stderr, []byte("[00.06]"), []byte("[00.08]"))
	case "x-extra":
		stderr = append(stderr, []byte("additional warning\n")...)
	case "x-severity":
		stderr = bytes.ReplaceAll(stderr, []byte("WARNING"), []byte("ERROR"))
	case "x-prefix":
		stderr = bytes.ReplaceAll(stderr, []byte("[00.06]"), []byte("[bad]"))
	case "x-payload":
		stderr = bytes.ReplaceAll(stderr, []byte("API"), []byte("api"))
	case "x-null":
		wire["errors"] = json.RawMessage(`null`)
	case "x-unknown":
		wire["future"] = json.RawMessage(`true`)
	case "x-path":
		wire["paths"] = json.RawMessage(`{"scanned":[]}`)
	case "x-version":
		wire["version"] = json.RawMessage(`"1.12.1"`)
	case "x-skip":
		wire["skipped_rules"] = json.RawMessage(`["uncertain"]`)
	case "x-missing":
		delete(wire, "errors")
	case "x-relative":
		wire["paths"] = json.RawMessage(`{"scanned":["compute.py"]}`)
	case "x-skipped-path":
		wire["paths"] = json.RawMessage(`{"scanned":[],"skipped":["compute.py"]}`)
	case "x-time":
		wire["time"] = json.RawMessage(`{}`)
	case "warning":
		wire["errors"] = json.RawMessage(`[{"type":"ReplayWarning","level":"warning","message":"explicit wire perturbation"}]`)
	case "error":
		wire["errors"] = json.RawMessage(`[{"type":"ReplayError","level":"error","message":"explicit wire perturbation"}]`)
	case "skipped":
		wire["skipped_rules"] = json.RawMessage(`["explicit wire perturbation"]`)
	case "stderr":
		stderr = []byte("explicit unrecognized wire warning\n")
	case "empty":
		data = nil
	case "malformed":
		data = []byte("{invalid")
	}
	if mode == "warning" || mode == "error" || mode == "skipped" || strings.HasPrefix(mode, "x-") {
		data, err = json.Marshal(wire)
		if err != nil {
			panic(err)
		}
	}
	record := os.Getenv("CRYPTO_WIRE_REPLAY_RECORD")
	invocation, err := json.Marshal(os.Args[1:])
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(record+".argv.json", invocation, 0o600); err != nil {
		panic(err)
	}
	file, err := os.OpenFile(record, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	if _, err := file.WriteString("one scan"); err != nil {
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
	if err := os.WriteFile(record+".stdout", data, 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(record+".stderr", stderr, 0o600); err != nil {
		panic(err)
	}
	if mode == "x-timeout" {
		time.Sleep(time.Second)
	}
	fmt.Fprint(os.Stdout, string(data))
	fmt.Fprint(os.Stderr, string(stderr))
	if mode == "exit2" {
		os.Exit(2)
	}
	if mode == "x-exit1" {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestNativeWireReplayContract(t *testing.T) {
	for _, adapter := range []string{"opengrep", "semgrep"} {
		for _, mode := range []string{"positive", "no-match", "telemetry", "warning", "error", "skipped", "stderr", "empty", "malformed", "exit2"} {
			t.Run(adapter+"/"+mode, func(t *testing.T) { testNativeWireReplay(t, adapter, mode) })
		}
	}
}

func TestAtomicNativeOutcome(t *testing.T) {
	for _, mode := range []string{"x-positive", "x-timestamp", "x-punctuation", "x-exit1", "x-extra-field", "x-result", "x-result-unscanned", "x-result-outside", "x-result-alias", "x-position", "x-engine", "x-extra", "x-severity", "x-prefix", "x-payload", "x-null", "x-unknown", "x-path", "x-version", "x-tool-version", "x-skip", "x-time", "x-timeout", "x-env", "x-workdir", "x-missing", "x-relative", "x-skipped-path", "x-profile", "x-symlink", "warning", "error", "skipped", "stderr", "empty", "malformed", "exit2", "no-match", "telemetry"} {
		t.Run(mode, func(t *testing.T) { testNativeWireReplay(t, "outcome", mode) })
	}
}

func testNativeWireReplay(t *testing.T, adapter, mode string) {
	t.Helper()
	fixture, err := filepath.Abs(wireFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var provenance map[string]struct {
		Portable string `json:"portable_stdout_sha256"`
		Stderr   string `json:"stderr_sha256"`
		SHA      string `json:"sha256"`
	}
	manifest, err := os.ReadFile(filepath.Join(fixture, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifest, &provenance); err != nil {
		t.Fatal(err)
	}
	for name, entry := range provenance {
		files := map[string]string{name: entry.SHA}
		if entry.Portable != "" {
			files = map[string]string{name + ".stdout.json": entry.Portable, name + ".stderr.txt": entry.Stderr}
		}
		for name, want := range files {
			data, err := os.ReadFile(filepath.Join(fixture, name))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(data)) != want {
				t.Fatalf("authentic fixture hash mismatch: %s", name)
			}
		}
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	source := "compute.py"
	if mode == "no-match" {
		source = "nomatch.py"
	}
	data, err := os.ReadFile(filepath.Join(fixture, source))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(data, []byte("def compute(")) != 1 {
		t.Fatal("captured source declaration count differs")
	}
	if mode != "no-match" && (len(data) < 99 || string(data[89:99]) != "h.digest()") {
		t.Fatal("known independent terminal byte span differs")
	}
	if err := os.WriteFile(filepath.Join(target, "compute.py"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if mode == "x-result-alias" {
		if err := os.Mkdir(filepath.Join(target, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "x-result-unscanned" || mode == "x-result-outside" {
		path := filepath.Join(target, "other.py")
		if mode == "x-result-outside" {
			path = filepath.Join(root, "outside.py")
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, "calls")
	// Initialization probes run before Config.Env is applied. Scoped parent env
	// reaches those same real child executions; tests intentionally do not parallel.
	for name, value := range map[string]string{"CRYPTO_WIRE_REPLAY_CHILD": "1", "CRYPTO_WIRE_REPLAY_MODE": mode, "CRYPTO_WIRE_REPLAY_FIXTURES": fixture, "CRYPTO_WIRE_REPLAY_TARGET": target, "CRYPTO_WIRE_REPLAY_RECORD": record} {
		t.Setenv(name, value)
	}
	var s scanner.Scanner = opengrep.NewScanner()
	if adapter == "semgrep" {
		s = semgrep.NewScanner()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := scanner.Config{ExecutablePath: executable}
	if adapter == "outcome" {
		config.ExtraArgs = []string{"--quiet", "--jobs", "2"}
	}
	if mode == "x-timeout" {
		config.Timeout = 50 * time.Millisecond
	}
	if mode == "x-env" {
		config.Env = map[string]string{"WIRE_OPTION": "uncertain"}
	}
	if mode == "x-workdir" {
		config.WorkDir = target
	}
	if mode == "x-profile" {
		config.ExtraArgs = append(config.ExtraArgs, "--unknown")
	}
	if mode == "x-symlink" {
		if err := os.Symlink(filepath.Join(target, "compute.py"), filepath.Join(target, "link.py")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Initialize(ctx, config); err != nil {
		t.Fatal(err)
	}
	expectedVersion := "1.29.0"
	if mode == "x-tool-version" {
		expectedVersion = "1.12.1"
	}
	if s.GetInfo().Version != expectedVersion {
		t.Fatal("captured transport version not propagated")
	}
	tool := entities.ToolInfo{Name: "wire-contract", Version: "1"}
	var report *entities.InterimReport
	if adapter == "outcome" {
		outcome, scanErr := s.(scanner.OutcomeScanner).ScanWithOutcome(ctx, target, []string{filepath.Join(fixture, "digest.yaml")}, tool)
		report, err = outcome.Report, scanErr
		assertOutcome(t, outcome, mode, record, expectedVersion)
		if mode == "x-timeout" {
			assertNativeTerminalFailure(t, report, err, mode)
			return // A canceled process has no observed invocation record or native exit.
		}
	} else {
		report, err = s.Scan(ctx, target, []string{filepath.Join(fixture, "digest.yaml")}, tool)
	}
	calls, readErr := os.ReadFile(record)
	if readErr != nil || string(calls) != "one scan" {
		t.Fatal("scan execution missing")
	}
	invocation, readErr := os.ReadFile(record + ".argv.json")
	var actualArgs []string
	if readErr != nil || json.Unmarshal(invocation, &actualArgs) != nil {
		t.Fatal("actual public scanner argv missing")
	}
	if len(actualArgs) == 0 || actualArgs[len(actualArgs)-1] != target || !strings.Contains(strings.Join(actualArgs, " "), "--config "+filepath.Join(fixture, "digest.yaml")) {
		t.Fatal("native replay must receive actual rule and target")
	}
	if mode == "exit2" || mode == "malformed" || mode == "x-timeout" {
		assertNativeTerminalFailure(t, report, err, mode)
		return
	}
	if err != nil {
		t.Fatalf("legacy partial/empty report must preserve nil Go error: %v", err)
	}
	want := &entities.InterimReport{Version: "1.1", Tool: tool, Findings: []entities.Finding{}}
	if mode != "no-match" && mode != "empty" {
		id := "fixture.digest"
		if strings.HasPrefix(mode, "x-") {
			id = "testdata.native-wire.fixture.digest"
		}
		if mode == "telemetry" {
			id = "tmp.TestNativeOutcomeGuardsPublictelemetry2994491851.001.fixture.digest"
		}
		wantPath := "compute.py"
		if mode == "x-result-unscanned" {
			wantPath = "other.py"
		}
		if mode == "x-result-outside" {
			wantPath = filepath.Join("..", "outside.py")
		}
		want.Findings = []entities.Finding{{FilePath: wantPath, Language: "python", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 5, EndLine: 5, StartCol: 12, EndCol: 22, Match: "return h.digest()", Rules: []entities.RuleInfo{{ID: id, Message: "SHA-256 terminal", Severity: "INFO"}}, Status: "pending", Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256"}}}}}
	}
	actual, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("known native report contract differs:\nactual %s\nexpected %s", actual, expected)
	}
	if adapter == "outcome" && mode == "x-positive" {
		// A caller's mutations cannot become adapter state or affect the next result.
		report.Findings[0].CryptographicAssets[0].Metadata["algorithmName"] = "mutated"
		if err := os.Remove(record); err != nil {
			t.Fatal(err)
		}
		next, err := s.Scan(ctx, target, []string{filepath.Join(fixture, "digest.yaml")}, tool)
		if err != nil {
			t.Fatal(err)
		}
		nextJSON, _ := json.Marshal(next)
		calls, _ := os.ReadFile(record)
		if !bytes.Equal(nextJSON, expected) || string(calls) != "one scan" {
			t.Fatal("legacy parity/independent invocation lost")
		}
	}
	if len(report.Findings) > 0 {
		a := report.Findings[0].CryptographicAssets[0]
		if a.TerminalStartCol != 0 || a.TerminalEndCol != 0 || a.DependencyInfo != nil || a.PURL != "" || a.OID != "" || len(a.ParameterConditions) != 0 {
			t.Fatal("native transport invented hidden/dependency/selector/OID metadata")
		}
	}
}

func assertOutcome(t *testing.T, outcome scanner.Outcome, mode, record, expectedVersion string) {
	t.Helper()
	if outcome.ScopedComplete != (mode == "x-positive" || mode == "x-timestamp") {
		t.Fatalf("scoped verdict %v: %s", outcome.ScopedComplete, outcome.Reason)
	}
	stdout, _ := os.ReadFile(record + ".stdout")
	stderr, _ := os.ReadFile(record + ".stderr")
	if mode == "x-timeout" {
		stdout = nil
		stderr = nil
	}
	if !bytes.Equal(outcome.Stdout, stdout) || outcome.Stderr != string(stderr) || outcome.Version != expectedVersion || outcome.Scanner != "opengrep" || outcome.ExitAvailable != (mode != "x-timeout") {
		t.Fatal("raw invocation evidence lost")
	}
	wantExit := 0
	if mode == "x-exit1" {
		wantExit = 1
	}
	if mode == "exit2" {
		wantExit = 2
	}
	if mode == "x-timeout" {
		wantExit = -1
	}
	if outcome.ExitCode != wantExit {
		t.Fatal("observed native exit lost")
	}
	if mode == "x-timeout" {
		if len(outcome.Argv) == 0 || outcome.Argv[len(outcome.Argv)-1] != os.Getenv("CRYPTO_WIRE_REPLAY_TARGET") {
			t.Fatal("attempted native argv lost on cancellation")
		}
		return
	}
	invocation, _ := os.ReadFile(record + ".argv.json")
	args, _ := json.Marshal(outcome.Argv)
	if !bytes.Equal(invocation, args) {
		t.Fatal("effective ordered argv lost")
	}
}

func assertNativeTerminalFailure(t *testing.T, report *entities.InterimReport, err error, mode string) {
	t.Helper()
	if err == nil || report != nil {
		t.Fatal("native terminal failure must remain report=nil,error")
	}
	typed, ok := failure.As(err)
	if !ok || typed.Stage != failure.StageScan {
		t.Fatal("terminal failure lost boundary stage")
	}
	expectedCodes := map[string]failure.Code{"x-timeout": failure.CodeScannerTimeout, "exit2": failure.CodeScannerExecutionFailed, "malformed": failure.CodeScannerOutputParseFailed}
	if typed.Code != expectedCodes[mode] {
		t.Fatal("terminal boundary code lost")
	}
	if mode == "exit2" && typed.Code != failure.CodeScannerExecutionFailed {
		t.Fatal("native exit2 lost execution failure code")
	}
	if mode == "malformed" && typed.Code != failure.CodeScannerOutputParseFailed {
		t.Fatal("malformed native output lost parse code")
	}
}
