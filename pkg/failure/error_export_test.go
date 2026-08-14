// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package failure_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/failure"
)

func TestPublicFailureContract(t *testing.T) {
	err := failure.Wrap(
		errors.New("disk full"),
		failure.CodeOutputWriteFailed,
		failure.StageOutput,
		"write findings",
		failure.WithRetryable(true),
		failure.WithDetail("path", "findings.json"),
	)
	payload := failure.ToPayload(err)

	data, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"code", "stage", "retryable", "message", "details", "cause"} {
		if _, ok := got[key]; !ok {
			t.Errorf("field %q missing from %s", key, data)
		}
	}
	if _, ok := got["raw_error"]; ok {
		t.Errorf("optional raw_error unexpectedly present in %s", data)
	}
	if payload.Code != failure.CodeOutputWriteFailed || payload.Stage != failure.StageOutput {
		t.Fatalf("enum values changed: %#v", payload)
	}
}

func TestPublicFailurePayloadOmitsEmptyOptionalFields(t *testing.T) {
	data, err := json.Marshal(failure.Payload{
		Code: failure.CodeUnknown, Stage: failure.StageUnknown, Message: "unknown",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"details", "cause", "raw_error"} {
		if _, ok := got[key]; ok {
			t.Errorf("optional field %q present in %s", key, data)
		}
	}
}

func TestPublicFailureEnumValues(t *testing.T) {
	codes := map[failure.Code]string{
		failure.CodeUnknown: "unknown_error", failure.CodeInvalidArguments: "invalid_arguments", failure.CodeInvalidTimeout: "invalid_timeout",
		failure.CodeConfigInitializationFailed: "config_initialization_failed", failure.CodeJavaRuntimeConfigInvalid: "java_runtime_config_invalid", failure.CodeCacheInitializationFailed: "cache_initialization_failed",
		failure.CodeRulesLoadFailed: "rules_load_failed", failure.CodeScannerUnavailable: "scanner_unavailable", failure.CodeScannerInitializationFailed: "scanner_initialization_failed",
		failure.CodeScannerExecutionFailed: "scanner_execution_failed", failure.CodeScannerTimeout: "scanner_timeout", failure.CodeScannerCancelled: "scanner_canceled",
		failure.CodeScannerOutputParseFailed: "scanner_output_parse_failed", failure.CodeLanguageDetectionFailed: "language_detection_failed", failure.CodeDependencyResolutionFailed: "dependency_resolution_failed",
		failure.CodeDependencyBuildToolUnknown: "java_build_tool_unknown", failure.CodeJavaBuildToolAmbiguous: "java_build_tool_ambiguous", failure.CodeGradleToolMissing: "gradle_tool_missing",
		failure.CodeGradleExportFailed: "gradle_export_failed", failure.CodeGradleJavaIncompatible: "gradle_java_incompatible", failure.CodeCallGraphBuildFailed: "callgraph_build_failed",
		failure.CodeCallGraphExportFailed: "callgraph_export_failed", failure.CodeOutputWriterUnavailable: "output_writer_unavailable", failure.CodeOutputWriteFailed: "output_write_failed",
		failure.CodeFindingsDetected: "findings_detected",
	}
	for code, want := range codes {
		if string(code) != want {
			t.Errorf("Code %q = %q, want %q", code, code, want)
		}
	}

	stages := map[failure.Stage]string{
		failure.StageUnknown: "unknown", failure.StageInput: "input", failure.StageConfig: "config", failure.StageRules: "rules", failure.StageScan: "scan",
		failure.StageDependency: "dependency", failure.StageCallGraph: "callgraph", failure.StageExport: "export", failure.StageOutput: "output", failure.StagePolicy: "policy",
	}
	for stage, want := range stages {
		if string(stage) != want {
			t.Errorf("Stage %q = %q, want %q", stage, stage, want)
		}
	}
}
