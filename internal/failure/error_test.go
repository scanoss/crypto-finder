package failure

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestWrapUnknown_PreservesTypedFailures(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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

func TestToPayload_DefaultsMissingStructuredFields(t *testing.T) {
	t.Parallel()

	err := &Error{
		Message: "missing fields",
		Cause:   errors.New("root cause"),
	}

	payload := ToPayload(err)
	if payload.Code != CodeUnknown {
		t.Fatalf("Code = %q, want %q", payload.Code, CodeUnknown)
	}
	if payload.Stage != StageUnknown {
		t.Fatalf("Stage = %q, want %q", payload.Stage, StageUnknown)
	}
	if payload.Cause != "root cause" {
		t.Fatalf("Cause = %q, want root cause", payload.Cause)
	}
}

func TestFailureHelpers_OptionsAndErrorBranches(t *testing.T) {
	t.Parallel()

	err := New(
		CodeUnknown,
		StageUnknown,
		"",
		WithRetryable(true),
		WithDetail("", "ignored"),
		WithDetail("kept", "value"),
		WithDetails(map[string]string{
			"":        "ignored",
			"skip":    "",
			"merged":  "yes",
			"another": "entry",
		}),
		nil,
	)

	if !err.Retryable {
		t.Fatal("Retryable = false, want true")
	}
	if len(err.Details) != 3 {
		t.Fatalf("Details len = %d, want 3", len(err.Details))
	}
	if err.Details["kept"] != "value" || err.Details["merged"] != "yes" || err.Details["another"] != "entry" {
		t.Fatalf("Details = %#v", err.Details)
	}

	cause := errors.New("fallback cause")
	err.Message = ""
	err.Cause = cause
	if got := err.Error(); got != "fallback cause" {
		t.Fatalf("Error() with cause = %q, want fallback cause", got)
	}

	err.Cause = nil
	err.Code = CodeOutputWriteFailed
	if got := err.Error(); got != string(CodeOutputWriteFailed) {
		t.Fatalf("Error() with code = %q, want %q", got, CodeOutputWriteFailed)
	}

	err.Code = ""
	if got := err.Error(); got != string(CodeUnknown) {
		t.Fatalf("Error() default = %q, want %q", got, CodeUnknown)
	}

	if got := (*Error)(nil).Error(); got != "" {
		t.Fatalf("nil Error() = %q, want empty string", got)
	}
	if got := (*Error)(nil).Unwrap(); got != nil {
		t.Fatalf("nil Unwrap() = %v, want nil", got)
	}
}

func TestFailureHelpers_WrapPrefixAsAndPayloadFallbacks(t *testing.T) {
	t.Parallel()

	if got := Wrap(nil, CodeInvalidArguments, StageInput, "ignored"); got != nil {
		t.Fatalf("Wrap(nil) = %v, want nil", got)
	}
	if got := WrapUnknown(nil, CodeInvalidArguments, StageInput, "ignored"); got != nil {
		t.Fatalf("WrapUnknown(nil) = %v, want nil", got)
	}

	plain := errors.New("plain error")
	if got := Prefix(nil, "ctx"); got != nil {
		t.Fatalf("Prefix(nil) = %v, want nil", got)
	}
	if got := Prefix(plain, ""); !errors.Is(got, plain) || errors.Unwrap(got) != nil {
		t.Fatalf("Prefix with empty message should return original error, got %v", got)
	}
	if got := Prefix(plain, plain.Error()); !errors.Is(got, plain) || errors.Unwrap(got) != nil {
		t.Fatalf("Prefix with identical message should return original error, got %v", got)
	}

	if structured, ok := As(nil); ok || structured != nil {
		t.Fatalf("As(nil) = (%v, %v), want (nil, false)", structured, ok)
	}
	if structured, ok := As(plain); ok || structured != nil {
		t.Fatalf("As(plain) = (%v, %v), want (nil, false)", structured, ok)
	}

	payload := ToPayload(plain)
	if payload.Code != CodeUnknown || payload.Stage != StageUnknown {
		t.Fatalf("fallback payload = %#v", payload)
	}
	if payload.Message != "plain error" || payload.RawError != "plain error" {
		t.Fatalf("fallback payload message/raw = %#v", payload)
	}

	data, err := MarshalJSON(nil)
	if err != nil {
		t.Fatalf("MarshalJSON(nil): %v", err)
	}
	if string(data) != "{\"code\":\"\",\"stage\":\"\",\"retryable\":false,\"message\":\"\"}" {
		t.Fatalf("MarshalJSON(nil) = %s", data)
	}
}

func TestFailureHelpers_WithDetailsUnwrapAndStructuredPayloadFallbackMessage(t *testing.T) {
	t.Parallel()

	err := New(CodeUnknown, StageUnknown, "", WithDetails(nil))
	if err.Details != nil {
		t.Fatalf("Details = %#v, want nil", err.Details)
	}

	cause := errors.New("wrapped cause")
	wrapped := &Error{Cause: cause}
	if got := wrapped.Unwrap(); !errors.Is(got, cause) || errors.Unwrap(got) != nil {
		t.Fatalf("Unwrap() = %v, want %v", got, cause)
	}

	payload := ToPayload(wrapped)
	if payload.Message != "wrapped cause" {
		t.Fatalf("Message = %q, want wrapped cause", payload.Message)
	}
	if payload.Cause != "wrapped cause" {
		t.Fatalf("Cause = %q, want wrapped cause", payload.Cause)
	}
}

func TestWithDetails_InitializesMapForNonEmptyInput(t *testing.T) {
	t.Parallel()

	err := New(CodeUnknown, StageUnknown, "", WithDetails(map[string]string{
		"alpha": "1",
		"beta":  "2",
	}))

	if len(err.Details) != 2 {
		t.Fatalf("Details len = %d, want 2", len(err.Details))
	}
	if err.Details["alpha"] != "1" || err.Details["beta"] != "2" {
		t.Fatalf("Details = %#v", err.Details)
	}
}
