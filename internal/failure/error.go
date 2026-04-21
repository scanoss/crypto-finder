// Package failure defines structured machine-readable terminal errors.
package failure

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Code is a stable machine-readable failure identifier.
type Code string

// Stage identifies the pipeline stage that produced the failure.
type Stage string

// Failure codes are stable machine-readable identifiers for terminal errors.
const (
	CodeUnknown                     Code = "unknown_error"
	CodeInvalidArguments            Code = "invalid_arguments"
	CodeInvalidTimeout              Code = "invalid_timeout"
	CodeConfigInitializationFailed  Code = "config_initialization_failed"
	CodeJavaRuntimeConfigInvalid    Code = "java_runtime_config_invalid"
	CodeCacheInitializationFailed   Code = "cache_initialization_failed"
	CodeRulesLoadFailed             Code = "rules_load_failed"
	CodeScannerUnavailable          Code = "scanner_unavailable"
	CodeScannerInitializationFailed Code = "scanner_initialization_failed"
	CodeScannerExecutionFailed      Code = "scanner_execution_failed"
	CodeScannerTimeout              Code = "scanner_timeout"
	CodeScannerCancelled            Code = "scanner_canceled"
	CodeScannerOutputParseFailed    Code = "scanner_output_parse_failed"
	CodeLanguageDetectionFailed     Code = "language_detection_failed"
	CodeDependencyResolutionFailed  Code = "dependency_resolution_failed"
	CodeDependencyBuildToolUnknown  Code = "java_build_tool_unknown"
	CodeJavaBuildToolAmbiguous      Code = "java_build_tool_ambiguous"
	CodeGradleToolMissing           Code = "gradle_tool_missing"
	CodeGradleExportFailed          Code = "gradle_export_failed"
	CodeGradleJavaIncompatible      Code = "gradle_java_incompatible"
	CodeCallGraphBuildFailed        Code = "callgraph_build_failed"
	CodeCallGraphExportFailed       Code = "callgraph_export_failed"
	CodeOutputWriterUnavailable     Code = "output_writer_unavailable"
	CodeOutputWriteFailed           Code = "output_write_failed"
	CodeFindingsDetected            Code = "findings_detected"
)

// Failure stages identify which pipeline phase produced a terminal error.
const (
	StageUnknown    Stage = "unknown"
	StageInput      Stage = "input"
	StageConfig     Stage = "config"
	StageRules      Stage = "rules"
	StageScan       Stage = "scan"
	StageDependency Stage = "dependency"
	StageCallGraph  Stage = "callgraph"
	StageExport     Stage = "export"
	StageOutput     Stage = "output"
	StagePolicy     Stage = "policy"
)

// Error is a structured machine-readable terminal failure.
type Error struct {
	Code      Code
	Stage     Stage
	Retryable bool
	Message   string
	Details   map[string]string
	Cause     error
}

// Option configures a structured failure.
type Option func(*Error)

// WithRetryable sets whether the failure should be retried.
func WithRetryable(retryable bool) Option {
	return func(err *Error) {
		err.Retryable = retryable
	}
}

// WithDetail adds a structured detail field.
func WithDetail(key, value string) Option {
	return func(err *Error) {
		if key == "" || value == "" {
			return
		}
		if err.Details == nil {
			err.Details = make(map[string]string)
		}
		err.Details[key] = value
	}
}

// WithDetails adds multiple structured detail fields.
func WithDetails(details map[string]string) Option {
	return func(err *Error) {
		if len(details) == 0 {
			return
		}
		if err.Details == nil {
			err.Details = make(map[string]string, len(details))
		}
		for key, value := range details {
			if key == "" || value == "" {
				continue
			}
			err.Details[key] = value
		}
	}
}

// New constructs a new structured failure.
func New(code Code, stage Stage, message string, opts ...Option) *Error {
	err := &Error{
		Code:    code,
		Stage:   stage,
		Message: message,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(err)
		}
	}
	return err
}

// Wrap constructs a new structured failure that preserves the cause.
func Wrap(err error, code Code, stage Stage, message string, opts ...Option) error {
	if err == nil {
		return nil
	}
	wrapped := New(code, stage, message, opts...)
	wrapped.Cause = err
	return wrapped
}

// Prefix adds human-readable context without changing the underlying typed failure.
func Prefix(err error, message string) error {
	if err == nil || message == "" {
		return err
	}
	if message == err.Error() {
		return err
	}
	return fmt.Errorf("%s: %w", message, err)
}

// WrapUnknown wraps plain errors into structured failures while preserving
// already-typed failures.
func WrapUnknown(err error, code Code, stage Stage, message string, opts ...Option) error {
	if err == nil {
		return nil
	}
	if structured, ok := As(err); ok {
		return Prefix(structured, message)
	}
	return Wrap(err, code, stage, message, opts...)
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	if e.Code != "" {
		return string(e.Code)
	}
	return string(CodeUnknown)
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// As extracts a structured failure from the error chain.
func As(err error) (*Error, bool) {
	if err == nil {
		return nil, false
	}
	var structured *Error
	if errors.As(err, &structured) {
		return structured, true
	}
	return nil, false
}

// Payload is the machine-readable representation emitted by CLI adapters.
type Payload struct {
	Code      Code              `json:"code"`
	Stage     Stage             `json:"stage"`
	Retryable bool              `json:"retryable"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details,omitempty"`
	Cause     string            `json:"cause,omitempty"`
	RawError  string            `json:"raw_error,omitempty"`
}

// ToPayload converts any error into a machine-readable payload.
func ToPayload(err error) Payload {
	if err == nil {
		return Payload{}
	}

	raw := err.Error()
	if structured, ok := As(err); ok {
		return structuredPayload(structured, raw)
	}

	return Payload{
		Code:     CodeUnknown,
		Stage:    StageUnknown,
		Message:  raw,
		RawError: raw,
	}
}

// MarshalJSON serializes any error into the machine-readable payload.
func MarshalJSON(err error) ([]byte, error) {
	return json.Marshal(ToPayload(err))
}

func structuredPayload(structured *Error, raw string) Payload {
	payload := Payload{
		Code:      structured.Code,
		Stage:     structured.Stage,
		Retryable: structured.Retryable,
		Message:   structured.Error(),
		Details:   cloneDetails(structured.Details),
	}
	if structured.Cause != nil {
		payload.Cause = structured.Cause.Error()
	}
	if raw != "" && raw != payload.Message {
		payload.RawError = raw
	}
	if payload.Code == "" {
		payload.Code = CodeUnknown
	}
	if payload.Stage == "" {
		payload.Stage = StageUnknown
	}
	if payload.Message == "" {
		payload.Message = raw
	}
	return payload
}

func cloneDetails(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(details))
	for key, value := range details {
		cloned[key] = value
	}
	return cloned
}
