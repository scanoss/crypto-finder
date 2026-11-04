// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package failure defines the public structured machine-readable terminal error contract.
//
// It forwards to github.com/scanoss/static-engine/failure, which holds the
// implementation; the names here are aliases so both paths share one type.
package failure

import enginefailure "github.com/scanoss/static-engine/failure"

type (
	// Code is a stable machine-readable failure identifier.
	Code = enginefailure.Code
	// Stage identifies the pipeline stage that produced the failure.
	Stage = enginefailure.Stage
	// Error is a structured machine-readable terminal failure.
	Error = enginefailure.Error
	// Option configures a structured failure.
	Option = enginefailure.Option
	// Payload is the machine-readable representation emitted by CLI adapters.
	Payload = enginefailure.Payload
)

// Failure codes are stable machine-readable identifiers for terminal errors.
const (
	CodeUnknown                     = enginefailure.CodeUnknown
	CodeInvalidArguments            = enginefailure.CodeInvalidArguments
	CodeInvalidTimeout              = enginefailure.CodeInvalidTimeout
	CodeConfigInitializationFailed  = enginefailure.CodeConfigInitializationFailed
	CodeJavaRuntimeConfigInvalid    = enginefailure.CodeJavaRuntimeConfigInvalid
	CodeCacheInitializationFailed   = enginefailure.CodeCacheInitializationFailed
	CodeRulesLoadFailed             = enginefailure.CodeRulesLoadFailed
	CodeScannerUnavailable          = enginefailure.CodeScannerUnavailable
	CodeScannerInitializationFailed = enginefailure.CodeScannerInitializationFailed
	CodeScannerExecutionFailed      = enginefailure.CodeScannerExecutionFailed
	CodeScannerTimeout              = enginefailure.CodeScannerTimeout
	CodeScannerCancelled            = enginefailure.CodeScannerCancelled
	CodeScannerOutputParseFailed    = enginefailure.CodeScannerOutputParseFailed
	CodeLanguageDetectionFailed     = enginefailure.CodeLanguageDetectionFailed
	CodeDependencyResolutionFailed  = enginefailure.CodeDependencyResolutionFailed
	CodeDependencyBuildToolUnknown  = enginefailure.CodeDependencyBuildToolUnknown
	CodeJavaBuildToolAmbiguous      = enginefailure.CodeJavaBuildToolAmbiguous
	CodeGradleToolMissing           = enginefailure.CodeGradleToolMissing
	CodeGradleExportFailed          = enginefailure.CodeGradleExportFailed
	CodeGradleJavaIncompatible      = enginefailure.CodeGradleJavaIncompatible
	CodeCallGraphBuildFailed        = enginefailure.CodeCallGraphBuildFailed
	CodeCallGraphExportFailed       = enginefailure.CodeCallGraphExportFailed
	CodeOutputWriterUnavailable     = enginefailure.CodeOutputWriterUnavailable
	CodeOutputWriteFailed           = enginefailure.CodeOutputWriteFailed
	CodeFindingsDetected            = enginefailure.CodeFindingsDetected
	CodeComponentLookupFailed       = enginefailure.CodeComponentLookupFailed
)

// Failure stages identify which pipeline phase produced a terminal error.
const (
	StageUnknown    = enginefailure.StageUnknown
	StageInput      = enginefailure.StageInput
	StageConfig     = enginefailure.StageConfig
	StageRules      = enginefailure.StageRules
	StageScan       = enginefailure.StageScan
	StageDependency = enginefailure.StageDependency
	StageCallGraph  = enginefailure.StageCallGraph
	StageExport     = enginefailure.StageExport
	StageOutput     = enginefailure.StageOutput
	StagePolicy     = enginefailure.StagePolicy
)

// WithRetryable sets whether the failure should be retried.
func WithRetryable(retryable bool) Option {
	return enginefailure.WithRetryable(retryable)
}

// WithDetail adds a structured detail field.
func WithDetail(key, value string) Option {
	return enginefailure.WithDetail(key, value)
}

// WithDetails adds multiple structured detail fields.
func WithDetails(details map[string]string) Option {
	return enginefailure.WithDetails(details)
}

// New constructs a new structured failure.
func New(code Code, stage Stage, message string, opts ...Option) *Error {
	return enginefailure.New(code, stage, message, opts...)
}

// Wrap constructs a new structured failure that preserves the cause.
func Wrap(err error, code Code, stage Stage, message string, opts ...Option) error {
	return enginefailure.Wrap(err, code, stage, message, opts...)
}

// Prefix adds human-readable context without changing the underlying typed failure.
func Prefix(err error, message string) error {
	return enginefailure.Prefix(err, message)
}

// WrapUnknown wraps plain errors into structured failures while preserving
// already-typed failures.
func WrapUnknown(err error, code Code, stage Stage, message string, opts ...Option) error {
	return enginefailure.WrapUnknown(err, code, stage, message, opts...)
}

// As extracts a structured failure from the error chain.
func As(err error) (*Error, bool) {
	return enginefailure.As(err)
}

// ToPayload converts any error into a machine-readable payload.
func ToPayload(err error) Payload {
	return enginefailure.ToPayload(err)
}

// MarshalJSON serializes any error into the machine-readable payload.
func MarshalJSON(err error) ([]byte, error) {
	return enginefailure.MarshalJSON(err)
}
