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
		fmt.Print("1.29.0\n")
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
	if mode == "warning" || mode == "error" || mode == "skipped" {
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
	fmt.Fprint(os.Stdout, string(data))
	fmt.Fprint(os.Stderr, string(stderr))
	if mode == "exit2" {
		os.Exit(2)
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
	if err := s.Initialize(ctx, scanner.Config{ExecutablePath: executable}); err != nil {
		t.Fatal(err)
	}
	if s.GetInfo().Version != "1.29.0" {
		t.Fatal("captured transport version not propagated")
	}
	tool := entities.ToolInfo{Name: "wire-contract", Version: "1"}
	report, err := s.Scan(ctx, target, []string{filepath.Join(fixture, "digest.yaml")}, tool)
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
	if mode == "exit2" || mode == "malformed" {
		if err == nil || report != nil {
			t.Fatal("native terminal failure must remain report=nil,error")
		}
		typed, ok := failure.As(err)
		if !ok || typed.Stage != failure.StageScan {
			t.Fatal("terminal failure lost boundary stage")
		}
		if mode == "exit2" && typed.Code != failure.CodeScannerExecutionFailed {
			t.Fatal("native exit2 lost execution failure code")
		}
		if mode == "malformed" && typed.Code != failure.CodeScannerOutputParseFailed {
			t.Fatal("malformed native output lost parse code")
		}
		return
	}
	if err != nil {
		t.Fatalf("legacy partial/empty report must preserve nil Go error: %v", err)
	}
	want := &entities.InterimReport{Version: "1.1", Tool: tool, Findings: []entities.Finding{}}
	if mode != "no-match" && mode != "empty" {
		id := "fixture.digest"
		if mode == "telemetry" {
			id = "tmp.TestNativeOutcomeGuardsPublictelemetry2994491851.001.fixture.digest"
		}
		want.Findings = []entities.Finding{{FilePath: "compute.py", Language: "python", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 5, EndLine: 5, StartCol: 12, EndCol: 22, Match: "return h.digest()", Rules: []entities.RuleInfo{{ID: id, Message: "SHA-256 terminal", Severity: "INFO"}}, Status: "pending", Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256"}}}}}
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
	if len(report.Findings) > 0 {
		a := report.Findings[0].CryptographicAssets[0]
		if a.TerminalStartCol != 0 || a.TerminalEndCol != 0 || a.DependencyInfo != nil || a.PURL != "" || a.OID != "" || len(a.ParameterConditions) != 0 {
			t.Fatal("native transport invented hidden/dependency/selector/OID metadata")
		}
	}
}
