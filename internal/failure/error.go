// Package failure provides internal compatibility aliases for the public error contract.
package failure

import publicfailure "github.com/scanoss/crypto-finder/pkg/failure"

type (
	// Code is a stable machine-readable failure identifier.
	Code = publicfailure.Code
	// Stage identifies the pipeline stage that produced the failure.
	Stage = publicfailure.Stage
	// Error is a structured machine-readable terminal failure.
	Error = publicfailure.Error
	// Option configures a structured failure.
	Option = publicfailure.Option
	// Payload is the machine-readable representation emitted by CLI adapters.
	Payload = publicfailure.Payload
)

// Compatibility aliases for the public failure codes and stages.
const (
	CodeUnknown                     = publicfailure.CodeUnknown
	CodeInvalidArguments            = publicfailure.CodeInvalidArguments
	CodeInvalidTimeout              = publicfailure.CodeInvalidTimeout
	CodeConfigInitializationFailed  = publicfailure.CodeConfigInitializationFailed
	CodeJavaRuntimeConfigInvalid    = publicfailure.CodeJavaRuntimeConfigInvalid
	CodeCacheInitializationFailed   = publicfailure.CodeCacheInitializationFailed
	CodeRulesLoadFailed             = publicfailure.CodeRulesLoadFailed
	CodeScannerUnavailable          = publicfailure.CodeScannerUnavailable
	CodeScannerInitializationFailed = publicfailure.CodeScannerInitializationFailed
	CodeScannerExecutionFailed      = publicfailure.CodeScannerExecutionFailed
	CodeScannerTimeout              = publicfailure.CodeScannerTimeout
	CodeScannerCancelled            = publicfailure.CodeScannerCancelled
	CodeScannerOutputParseFailed    = publicfailure.CodeScannerOutputParseFailed
	CodeLanguageDetectionFailed     = publicfailure.CodeLanguageDetectionFailed
	CodeDependencyResolutionFailed  = publicfailure.CodeDependencyResolutionFailed
	CodeDependencyBuildToolUnknown  = publicfailure.CodeDependencyBuildToolUnknown
	CodeJavaBuildToolAmbiguous      = publicfailure.CodeJavaBuildToolAmbiguous
	CodeGradleToolMissing           = publicfailure.CodeGradleToolMissing
	CodeGradleExportFailed          = publicfailure.CodeGradleExportFailed
	CodeGradleJavaIncompatible      = publicfailure.CodeGradleJavaIncompatible
	CodeCallGraphBuildFailed        = publicfailure.CodeCallGraphBuildFailed
	CodeCallGraphExportFailed       = publicfailure.CodeCallGraphExportFailed
	CodeOutputWriterUnavailable     = publicfailure.CodeOutputWriterUnavailable
	CodeOutputWriteFailed           = publicfailure.CodeOutputWriteFailed
	CodeFindingsDetected            = publicfailure.CodeFindingsDetected

	StageUnknown    = publicfailure.StageUnknown
	StageInput      = publicfailure.StageInput
	StageConfig     = publicfailure.StageConfig
	StageRules      = publicfailure.StageRules
	StageScan       = publicfailure.StageScan
	StageDependency = publicfailure.StageDependency
	StageCallGraph  = publicfailure.StageCallGraph
	StageExport     = publicfailure.StageExport
	StageOutput     = publicfailure.StageOutput
	StagePolicy     = publicfailure.StagePolicy
)

var (
	// WithRetryable sets whether the failure should be retried.
	WithRetryable = publicfailure.WithRetryable
	// WithDetail adds a structured detail field.
	WithDetail = publicfailure.WithDetail
	// WithDetails adds multiple structured detail fields.
	WithDetails = publicfailure.WithDetails
	// New constructs a new structured failure.
	New = publicfailure.New
	// Wrap constructs a new structured failure that preserves the cause.
	Wrap = publicfailure.Wrap
	// Prefix adds human-readable context without changing the underlying typed failure.
	Prefix = publicfailure.Prefix
	// WrapUnknown wraps plain errors into structured failures.
	WrapUnknown = publicfailure.WrapUnknown
	// As extracts a structured failure from the error chain.
	As = publicfailure.As
	// ToPayload converts any error into a machine-readable payload.
	ToPayload = publicfailure.ToPayload
	// MarshalJSON serializes an error into the machine-readable payload.
	MarshalJSON = publicfailure.MarshalJSON
)
