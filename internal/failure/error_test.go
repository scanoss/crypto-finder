package failure

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestWrapUnknown_PreservesTypedFailures(t *testing.T) {
	root := New(
		CodeGradleJavaIncompatible,
		StageDependency,
		"Gradle 6.9.2 cannot run on Java 21",
		WithDetail("gradle_version", "6.9.2"),
	)

	err := WrapUnknown(root, CodeDependencyResolutionFailed, StageDependency, "dependency resolution failed")

	structured, ok := As(err)
	if !ok {
		t.Fatal("expected structured failure")
	}
	if structured.Code != CodeGradleJavaIncompatible {
		t.Fatalf("Code = %q, want %q", structured.Code, CodeGradleJavaIncompatible)
	}

	payload := ToPayload(err)
	if payload.RawError != "dependency resolution failed: Gradle 6.9.2 cannot run on Java 21" {
		t.Fatalf("RawError = %q", payload.RawError)
	}
}

func TestWrapUnknown_WrapsPlainErrors(t *testing.T) {
	err := WrapUnknown(errors.New("bad timeout"), CodeInvalidTimeout, StageInput, "invalid timeout")

	structured, ok := As(err)
	if !ok {
		t.Fatal("expected structured failure")
	}
	if structured.Code != CodeInvalidTimeout {
		t.Fatalf("Code = %q, want %q", structured.Code, CodeInvalidTimeout)
	}
	if structured.Stage != StageInput {
		t.Fatalf("Stage = %q, want %q", structured.Stage, StageInput)
	}
}

func TestMarshalJSON_UsesStructuredPayload(t *testing.T) {
	err := Prefix(
		New(
			CodeGradleExportFailed,
			StageDependency,
			"Gradle dependency export failed",
			WithRetryable(true),
			WithDetail("exit_code", "1"),
		),
		"dependency scan failed",
	)

	data, marshalErr := MarshalJSON(err)
	if marshalErr != nil {
		t.Fatalf("MarshalJSON: %v", marshalErr)
	}

	var payload Payload
	if unmarshalErr := json.Unmarshal(data, &payload); unmarshalErr != nil {
		t.Fatalf("Unmarshal: %v", unmarshalErr)
	}

	if payload.Code != CodeGradleExportFailed {
		t.Fatalf("Code = %q, want %q", payload.Code, CodeGradleExportFailed)
	}
	if !payload.Retryable {
		t.Fatal("Retryable = false, want true")
	}
	if payload.RawError != "dependency scan failed: Gradle dependency export failed" {
		t.Fatalf("RawError = %q", payload.RawError)
	}
}
