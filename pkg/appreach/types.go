// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"

	"github.com/scanoss/crypto-finder/pkg/pqc"
)

// ComponentInput carries the raw findings + callgraph bytes and request-time
// filter parameters needed to build one ComponentDataDTO block. For /component
// it is invoked once with the merged stitch envelope; for /dep-tree once per
// supplied dep with that dep's own findings. Callgraph is the merged stitched
// callgraph (authoritative for chain JOIN).
type ComponentInput struct {
	Purl        string
	Version     string
	Requirement string

	Findings  []byte // crypto-finder findings.json (v1.4) for this block
	Callgraph []byte // merged crypto-finder callgraph (6.x); may be nil

	EntryPointSignatures []string
	MaxChainsPerAsset    int

	IncludeCallChains        bool
	IncludeCryptoEntryPoints bool
	IncludeSupportingCalls   bool
	IncludeForwardCalls      bool
	IncludeRawCallgraph      bool
}

// ComponentDataDTO is one per-component block in the response's data[] array.
//
// The shipped /component surface (purl, version, requirement,
// actual_mined_version, findings, finding_count, schemas, crypto_entry_points,
// supporting_calls, mined_at) is unchanged. Everything else is /dep-tree-only
// block surface, stripped by ComponentReachability so /component blocks stay
// the shipped shape. Envelope missing_components is additive for unmined
// transitives.
type ComponentDataDTO struct {
	Purl string `json:"purl"`

	// Version is the version actually served — unchanged in name and meaning
	// from previous releases, and the field #69 calls `resolved_version`. It is
	// deliberately NOT renamed: every existing client reads it, and a rename
	// fails silently rather than loudly.
	Version string `json:"version"`

	// ─── resolution provenance (issue #69; /dep-tree blocks only) ──────────
	// #69 also names a `request_index` field; it is deliberately NOT shipped
	// (declared deviation): identical duplicates collapse, so (purl,
	// requirement) is unique per block and blocks keep request order — the
	// index would restate the block's position.

	// Requirement is the client's literal requirement, echoed verbatim.
	Requirement string `json:"requirement,omitempty"`
	// RequestedVersion is what the client asked for: the exact version on a
	// pin, or the requirement string itself on a range (a range requests a
	// set, and the set is what was asked for).
	RequestedVersion string `json:"requested_version,omitempty"`
	// ResolvedVersion is #69's name for the served version. Same value as
	// Version whenever resolution produced one; carried so the block is
	// self-describing under the ticket's vocabulary.
	ResolvedVersion string `json:"resolved_version,omitempty"`
	// Fallback is ALWAYS present on blocks whose resolution produced a served
	// version: true iff that version differs from the requested exact pin,
	// explicit false otherwise (a field present only when true would signal by
	// presence — the actual_mined_version defect this provenance retires).
	// Omitted (nil) when resolution never produced a version.
	Fallback *bool `json:"fallback,omitempty"`
	// Method is how the served version was selected: "exact", "range",
	// "nearest_greater_patch_same_major_minor", or
	// "highest_patch_same_major_minor". Omitted alongside Fallback.
	Method string `json:"method,omitempty"`

	// MinedAt is when the served version's findings row was written
	// (RFC3339, UTC) — issue #168. Lets a caller that just re-triggered a
	// mine tell a fresh result apart from a previous mine's leftover data,
	// which "findings exist" alone cannot do. Unlike Fallback/Method, this
	// is part of the shipped /component surface too — ComponentReachability
	// does NOT strip it — since that single-component endpoint is exactly
	// where this provenance is needed.
	MinedAt string `json:"mined_at,omitempty"`

	// ActualMinedVersion is the pre-existing fallback signal: present only when
	// the served version differs from the exact version requested, carrying the
	// same value as Version. Emitted exactly as every previous release — it is
	// shipped contract and is not renamed, deprecated, or removed.
	ActualMinedVersion string `json:"actual_mined_version,omitempty"`

	// InfoCode is this block's own outcome. /dep-tree evaluates every requested
	// dependency independently, so a non-READY block can sit next to blocks
	// that carry data. Empty on /component blocks (production carries the
	// outcome on the envelope only).
	InfoCode    InfoCode `json:"info_code,omitempty"`
	InfoMessage string   `json:"info_message,omitempty"`

	// AppliedDependencyOverrides names each closure node whose stored version
	// was replaced by a version the client pinned elsewhere in the request.
	// READY blocks only, present only when non-empty.
	AppliedDependencyOverrides []AppliedOverride `json:"applied_dependency_overrides,omitempty"`

	// DependencyResolutionErrors records authoritative pins this root's closure
	// requires but that have no serveable patch in their bucket. It makes only
	// this root DEPENDENCY_UNRESOLVED; siblings are unaffected.
	DependencyResolutionErrors []DependencyResolutionError `json:"dependency_resolution_errors,omitempty"`

	Findings     []*FindingDTO `json:"findings"`
	FindingCount int           `json:"finding_count"`
	// MigrationSummary folds the vulnerable findings' migration paths per
	// component: the requested one for direct findings, each dependency for
	// indirect ones.
	MigrationSummary []MigrationSummaryDTO `json:"migration_summary,omitempty"`

	Schemas           *SchemasDTO     `json:"schemas,omitempty"`
	CryptoEntryPoints json.RawMessage `json:"crypto_entry_points,omitempty"`
	SupportingCalls   json.RawMessage `json:"supporting_calls,omitempty"`
}

// AppliedOverride is one closure node whose version was replaced by a client
// pin taken from elsewhere in the same request. It carries the same
// asked/served/flag triple as the block, at dependency granularity, so a pin
// honored from its bucket rather than exactly is impossible to miss.
type AppliedOverride struct {
	Purl string `json:"purl"`
	// RequestedVersion is the client's pin for this purl.
	RequestedVersion string `json:"requested_version"`
	// StoredVersion is what component_deps recorded at mining time.
	StoredVersion string `json:"stored_version"`
	// AppliedVersion is the version actually used during expansion — the pin,
	// or the highest serveable patch of the pin's bucket.
	AppliedVersion string `json:"applied_version"`
	// Fallback is true iff AppliedVersion is neither RequestedVersion nor its
	// Maven release spelling.
	Fallback bool `json:"fallback"`
}

// DependencyResolutionError is an authoritative client override that could not
// be resolved to serveable data for one root.
type DependencyResolutionError struct {
	Purl             string `json:"purl"`
	RequestedVersion string `json:"requested_version"`
	Reason           string `json:"reason"`
}

// FindingDTO is one file-level findings entry (crypto-finder findings[] shape).
//
// DependencyInfo sits here, not on each asset: every asset in one file comes
// from the same dependency-graph node by construction (crypto-finder groups
// findings by resolved file path within one closure member), so per-asset
// placement only repeated an identical value across every asset in the file.
type FindingDTO struct {
	FilePath            string                   `json:"file_path"`
	Language            string                   `json:"language"`
	DependencyInfo      *DependencyInfoDTO       `json:"dependency_info,omitempty"`
	CryptographicAssets []*CryptographicAssetDTO `json:"cryptographic_assets"`
}

// CryptoRuleDTO is the rules[] entry on an asset. The annotation-rendered
// path fills only ID from CryptoOperation.RuleID; a block served from the
// stored report carries every rule with its message and severity.
type CryptoRuleDTO struct {
	ID       string `json:"id"`
	Message  string `json:"message,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// CryptographicAssetDTO is a thin pass-through of one cryptographic asset;
// metadata / call_chains are raw JSON (no curation).
//
// The fields from StartCol to DependencyInfo exist only in crypto-finder's
// own report, so only a block served from the stored report (findings-only
// /component) carries them; the annotation-rendered path leaves them empty.
type CryptographicAssetDTO struct {
	FindingID           string          `json:"finding_id"`
	OID                 string          `json:"oid,omitempty"`
	Match               string          `json:"match"`
	Source              string          `json:"source"`
	PURL                string          `json:"purl,omitempty"`
	StartLine           int             `json:"start_line"`
	EndLine             int             `json:"end_line"`
	Metadata            json.RawMessage `json:"metadata"`
	ParameterConditions json.RawMessage `json:"parameter_conditions,omitempty"`
	Rules               []CryptoRuleDTO `json:"rules,omitempty"`
	// PQC is the finding's one post-quantum block: as mined when current,
	// recomputed when an older dataset produced it or none did.
	PQC *pqc.Classification `json:"pqc,omitempty"`
	// Migration is what moving a vulnerable finding to post-quantum takes.
	Migration *pqc.Migration `json:"migration,omitempty"`

	StartCol         int                `json:"start_col,omitempty"`
	EndCol           int                `json:"end_col,omitempty"`
	TerminalStartCol int                `json:"terminal_start_col,omitempty"`
	TerminalEndCol   int                `json:"terminal_end_col,omitempty"`
	ConditionedValue string             `json:"conditioned_value,omitempty"`
	Status           string             `json:"status,omitempty"`
	OccurrenceKey    string             `json:"occurrence_key,omitempty"`
	DependencyInfo   *DependencyInfoDTO `json:"dependency_info,omitempty"`

	Reachability      string          `json:"reachability,omitempty"`
	Analysis          json.RawMessage `json:"analysis,omitempty"`
	CallChains        json.RawMessage `json:"call_chains,omitempty"`
	ForwardCalls      json.RawMessage `json:"forward_calls,omitempty"`
	SupportingCallIDs []string        `json:"supporting_call_ids,omitempty"`

	// ReachabilityReason says why an unknown reachability is unknown. Only
	// /reachability/application sets it.
	ReachabilityReason string `json:"reachability_reason,omitempty"`
}

// DependencyInfoDTO carries the resolved dependency coordinate for an
// indirect finding, so callers can deduplicate against the same artifact's
// direct occurrence in another /dep-tree block.
type DependencyInfoDTO struct {
	Module  string `json:"module"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// SchemasDTO reports the source crypto-finder schema versions.
type SchemasDTO struct {
	Findings  string `json:"findings,omitempty"`
	Callgraph string `json:"callgraph,omitempty"`
}

// BlockReport carries ComponentBlock's auxiliary outputs (unmatched signatures
// per block) for the handler to union into the top-level envelope.
type BlockReport struct {
	UnmatchedSignatures []string
	// DroppedCallChains lists finding IDs whose call_chains were dropped
	// because an already-inline chain frame had no matching structural
	// function (a self-contained crypto call anchored to something like a
	// field or static initializer). The finding itself and its
	// reachability/analysis are kept; only that chain body is omitted. Never
	// fails the block — the caller only needs this to log the anomaly.
	DroppedCallChains []string
}
