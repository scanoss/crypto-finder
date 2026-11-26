// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

// InfoCode is the per-request outcome carried in every reachability response
// envelope (values from the crypto reachability OpenAPI contract).
type InfoCode string

// The info codes a component lookup answers with.
const (
	InfoReady             InfoCode = "READY"
	InfoInvalidPurl       InfoCode = "INVALID_PURL"
	InfoComponentNotFound InfoCode = "COMPONENT_NOT_FOUND"
	InfoVersionNotFound   InfoCode = "VERSION_NOT_FOUND"
	InfoInvalidSemver     InfoCode = "INVALID_SEMVER"
	InfoUnsupportedSchema InfoCode = "UNSUPPORTED_SCHEMA"
	InfoNoInfo            InfoCode = "NO_INFO"
	// InfoDependencyUnresolved is dep-tree-only: an authoritative pinned
	// version required by this root's closure has no serveable patch in its
	// bucket. Never data-bearing — the block carries no findings and the cause
	// is itemized in dependency_resolution_errors. Not listed in
	// missing_components, which stays exactly the NO_INFO blocks.
	InfoDependencyUnresolved InfoCode = "DEPENDENCY_UNRESOLVED"
	// InfoInvalidRequest is dep-tree-only (e.g. empty dependencies array, or
	// conflicting exact versions for one canonical purl).
	InfoInvalidRequest InfoCode = "INVALID_REQUEST"
)

// StatusEnvelope is the nested status object present in every response. Per the
// contract, status.status is always "SUCCESS" for 200 responses; the message
// differentiates a computed result from a processed-but-unsuccessful request.
type StatusEnvelope struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// OKStatus is the status object of a 200 response with outcome code.
func OKStatus(code InfoCode) StatusEnvelope {
	msg := "Request processed"
	if code == InfoReady {
		msg = "Reachability computed"
	}
	return StatusEnvelope{Status: "SUCCESS", Message: msg}
}
