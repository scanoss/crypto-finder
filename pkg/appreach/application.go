// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	core "github.com/scanoss/reach/appreach"
	gf "github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/pkg/conditioned"
)

// RequestSchemaVersion is the version of the project request and response
// bodies. A request naming another version is refused.
const RequestSchemaVersion = "1"

// MaxChainsHigh is the upper bound of max_chains_per_finding.
const MaxChainsHigh = 128

// Request is a decoded project request.
type Request struct {
	SchemaVersion string
	Dependencies  []Dependency
	// CallSites is the project's graph-fragment document; only its call sites
	// into dependencies are read (see applicationFragment).
	CallSites           *gf.GraphFragmentExport
	IncludeCallChains   bool
	MaxChainsPerFinding int
	// ConditionedRules are the client's conditioned rules: with them the
	// closure's generic findings are specialized by the values one dependency
	// passes another (conditioned.go). None specializes nothing.
	ConditionedRules []conditioned.Rule
}

// Summary counts findings by verdict.
type Summary struct {
	Reachable   int `json:"reachable"`
	Unknown     int `json:"unknown"`
	Unreachable int `json:"unreachable"`
}

func (s *Summary) add(verdict string) {
	switch verdict {
	case VerdictReachable:
		s.Reachable++
	case VerdictUnknown:
		s.Unknown++
	default:
		s.Unreachable++
	}
}

// DependencyDTO is one dependency of the project and its findings.
type DependencyDTO struct {
	Purl         string        `json:"purl"`
	Version      string        `json:"version"`
	Direct       bool          `json:"direct"`
	InfoCode     InfoCode      `json:"info_code"`
	InfoMessage  string        `json:"info_message,omitempty"`
	RulesVersion string        `json:"rules_version,omitempty"`
	Summary      Summary       `json:"summary"`
	Findings     []*FindingDTO `json:"findings"`
	FindingCount int           `json:"finding_count"`
	// MigrationSummary folds the vulnerable findings' migration paths.
	MigrationSummary []MigrationSummaryDTO `json:"migration_summary,omitempty"`
}

// Response is the project response envelope.
type Response struct {
	SchemaVersion string           `json:"schema_version"`
	RulesVersion  string           `json:"rules_version,omitempty"`
	Dependencies  []*DependencyDTO `json:"dependencies,omitempty"`
	Summary       Summary          `json:"summary"`
	InfoCode      InfoCode         `json:"info_code"`
	InfoMessage   string           `json:"info_message,omitempty"`
	Status        StatusEnvelope   `json:"status"`
}

// ErrorResponse is the envelope of a request that produced no verdicts.
func ErrorResponse(code InfoCode, msg string) Response {
	return Response{SchemaVersion: RequestSchemaVersion, InfoCode: code, InfoMessage: msg, Status: OKStatus(code)}
}

// Plan is a validated request: its canonical closure and parsed rules.
type Plan struct {
	Request Request
	Pins    Pins
	// Keys are the pinned components in request order.
	Keys    []ComponentKey
	Catalog *conditioned.Catalog
}

// NewPlan validates req against limits. A rejected request returns the
// response to answer with instead of a plan.
func NewPlan(req Request, limits Limits) (*Plan, *Response) {
	reject := func(code InfoCode, msg string) (*Plan, *Response) {
		resp := ErrorResponse(code, msg)
		return nil, &resp
	}
	if req.SchemaVersion != RequestSchemaVersion {
		return reject(InfoInvalidRequest, fmt.Sprintf("schema_version: must be %q", RequestSchemaVersion))
	}
	pins, err := core.ParseDependencies(req.Dependencies, limits)
	if err != nil {
		return reject(InfoInvalidRequest, err.Error())
	}
	if req.CallSites == nil {
		return reject(InfoInvalidRequest, "call_sites: required")
	}
	if err := ValidateSchemaVersion("graph fragment", req.CallSites.SchemaVersion, SchemaVersion); err != nil {
		return reject(InfoUnsupportedSchema, "call_sites: "+err.Error())
	}
	if n := len(req.CallSites.ExternalCalls); n > limits.MaxCallSites {
		return reject(InfoInvalidRequest, fmt.Sprintf("call_sites: %d external calls, at most %d", n, limits.MaxCallSites))
	}
	if maxChains := req.MaxChainsPerFinding; maxChains < 0 || maxChains > MaxChainsHigh {
		return reject(InfoInvalidRequest, fmt.Sprintf("max_chains_per_finding must be 0 (no cap) or in [1, %d]", MaxChainsHigh))
	}
	if n := len(req.ConditionedRules); n > MaxConditionedRules {
		return reject(InfoInvalidRequest, fmt.Sprintf("conditioned_rules: %d rules, at most %d", n, MaxConditionedRules))
	}
	catalog, err := conditioned.NewCatalog(req.ConditionedRules)
	if err != nil {
		return reject(InfoInvalidRequest, "conditioned_rules: "+err.Error())
	}
	return &Plan{Request: req, Pins: pins, Keys: pins.Keys(), Catalog: catalog}, nil
}

// RequestEdges returns the dependency edges the request names among the
// pinned closure, and whether any dependency named what it requires. When
// none did, the caller supplies the edges (EdgesFrom).
func (p *Plan) RequestEdges() (map[ComponentKey][]ComponentKey, bool) {
	return p.Pins.RequestEdges()
}

// EdgesFrom keeps, of the edges recorded elsewhere (each pinned version and
// the purls it depended on), those between pinned components.
func (p *Plan) EdgesFrom(recorded map[ComponentKey][]string) map[ComponentKey][]ComponentKey {
	return p.Pins.EdgesFrom(recorded)
}

// Component is one pinned dependency as its caller loaded it: its fragment
// (graph and annotation), or the code and message saying why it has none.
type Component struct {
	Fragment *Fragment
	// Stored is the component's findings report; nil when it has none or it
	// is unusable, and StoredErr then says why.
	Stored    *StoredFindings
	StoredErr string
	Code      InfoCode
	Message   string
}

// RunOptions are a run's hooks.
type RunOptions struct {
	// AfterStitch, when set, runs once the stitch's result is read, before
	// rendering (the API releases its trace slot there).
	AfterStitch func()
}

// Stats is what a run did, for the caller's log.
type Stats struct {
	WithGraph          int
	ConditionedAnchors int
	ConditionedAdded   int
	Stitch             time.Duration
	Render             time.Duration
}

// Run decides, for every finding of the pinned closure, whether the project's
// call sites reach it. It stitches the loaded components of exactly the
// pinned versions under the call sites with reach's application reachability
// (github.com/scanoss/reach/appreach), whose stitch policy was validated
// against labeled truth, and serves the verdicts on every finding of the
// closure. edges are the dependency edges among the pinned components
// (RequestEdges or EdgesFrom).
// loaded must hold every pinned key; a component without a fragment is
// served with its own code.
func (p *Plan) Run(ctx context.Context, loaded map[ComponentKey]Component, edges map[ComponentKey][]ComponentKey, opts RunOptions) (Response, Stats, error) {
	var stats Stats
	present := make(map[ComponentKey]Fragment, len(loaded))
	for k, l := range loaded {
		if l.Fragment != nil {
			present[k] = *l.Fragment
		}
	}
	stats.WithGraph = len(present)
	closure := core.NewClosure(core.Input{
		Root:      Root,
		Keys:      p.Keys,
		Direct:    p.Pins.Direct(),
		Edges:     edges,
		Fragments: present,
		CallSites: p.Request.CallSites,
	})
	fragments := closure.Fragments

	started := time.Now()
	plan := conditioned.NewPlan(fragments, Root, p.Catalog)
	stats.ConditionedAnchors = len(plan.Anchors)
	out, err := closure.Run(ctx, core.RunConfig{
		SelectorCalls:     plan.Calls,
		IncludeCallChains: p.Request.IncludeCallChains,
		MaxChains:         resolveMaxChains(p.Request.MaxChainsPerFinding),
	})
	if err != nil {
		return Response{}, stats, err
	}
	expansions := groupExpansions(plan.Expand(out.Result.SelectorValues()))
	if opts.AfterStitch != nil {
		opts.AfterStitch()
	}
	stitched := time.Now()
	stats.Stitch = stitched.Sub(started)

	block, err := renderApplication(fragments, closure.Deps, closure.Meta, out.Callgraph, p.Request.IncludeCallChains, p.Request.MaxChainsPerFinding)
	if err != nil {
		return Response{}, stats, &RunError{Stage: "render", Err: err}
	}
	resp, added := applicationResponse(p.Pins, p.Keys, loaded, block, fragments, out.Verdicts, closure.ViaMissingOnly, expansions)
	stats.ConditionedAdded = added
	stats.Render = time.Since(stitched)
	return resp, stats, nil
}

// renderApplication renders every finding of the closure, as /dep-tree renders a
// block, from the findings envelope and the stitched callgraph.
func renderApplication(fragments map[ComponentKey]Fragment, deps DependencyGraph, meta ScanMeta, cg CallgraphExport, includeChains bool, maxChains int) (*ComponentDataDTO, error) {
	findings, err := MarshalFindingsJSON(Root, deps, fragments, meta)
	if err != nil {
		return nil, err
	}
	callgraph, err := json.Marshal(cg)
	if err != nil {
		return nil, err
	}
	block, _, err := ComponentBlock(ComponentInput{
		Purl:              Root.Purl,
		Findings:          findings,
		Callgraph:         callgraph,
		MaxChainsPerAsset: maxChains,
		IncludeCallChains: includeChains,
	})
	return block, err
}

// applicationResponse builds the envelope in request order. A dependency's
// findings are its stored findings report, served as findings-only /component
// serves it, with the stitch's verdict attached to each asset; a dependency
// whose report is unusable keeps the findings rendered from its annotation.
func applicationResponse(pins Pins, keys []ComponentKey, loaded map[ComponentKey]Component, block *ComponentDataDTO, fragments map[ComponentKey]Fragment, verdicts map[string]core.Verdict, viaMissingOnly map[ComponentKey]bool, expansions conditionedExpansions) (Response, int) { //nolint:funlen,gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	owners := core.FindingOwners(Root, fragments)
	byKey := make(map[ComponentKey][]*FindingDTO)
	rendered := make(map[string]*CryptographicAssetDTO)
	for _, file := range block.Findings {
		for _, asset := range file.CryptographicAssets {
			rendered[asset.FindingID] = asset
		}
		if len(file.CryptographicAssets) == 0 {
			continue
		}
		key, ok := owners[file.CryptographicAssets[0].FindingID]
		if !ok {
			continue
		}
		byKey[key] = append(byKey[key], file)
	}

	resp := Response{SchemaVersion: RequestSchemaVersion, Dependencies: make([]*DependencyDTO, 0, len(keys))}
	added := 0
	var rulesVersions []string
	ready := 0
	for _, key := range keys {
		d := pins.Dep[key.Purl]
		dto := &DependencyDTO{Purl: key.Purl, Version: key.Version, Direct: d.Direct, Findings: []*FindingDTO{}}
		resp.Dependencies = append(resp.Dependencies, dto)
		l := loaded[key]
		if l.Fragment == nil {
			dto.InfoCode, dto.InfoMessage = l.Code, l.Message
			continue
		}
		ready++
		dto.InfoCode, dto.RulesVersion = InfoReady, l.Fragment.RulesVersion
		rulesVersions = append(rulesVersions, l.Fragment.RulesVersion)

		frag := fragments[key]
		// stitchID is the id the stitch gave a finding of this dependency;
		// the stored report names it by its own finding_id. An annotation
		// whose operations name no report asset (written before operations
		// carried finding ids) cannot be joined: the rendered findings stay.
		stitchID := func(a *CryptographicAssetDTO) (string, bool) { return a.FindingID, true }
		findings, fromReport := byKey[key], false
		if ids := core.StitchIDs(key, frag); l.Stored != nil && (len(ids) > 0 || len(frag.CryptoOperations) == 0) {
			findings, fromReport = servedStoredFindings(key, frag.Module, l.Stored), true
			stitchID = func(a *CryptographicAssetDTO) (string, bool) {
				id, ok := ids[a.FindingID]
				return id, ok
			}
		}
		for _, file := range findings {
			for _, asset := range file.CryptographicAssets {
				id, annotated := stitchID(asset)
				v, ok := verdicts[id]
				switch {
				case !annotated:
					v = core.Verdict{Reachability: VerdictUnknown, Reason: ReasonNotAnnotated}
				case !ok:
					v = core.Verdict{Reachability: VerdictUnreachable}
				}
				if v.Reachability == VerdictUnreachable && viaMissingOnly[key] {
					v = core.Verdict{Reachability: VerdictUnknown, Reason: ReasonDependencyWithoutGraph}
				}
				asset.Reachability, asset.ReachabilityReason = v.Reachability, v.Reason
				if r := rendered[id]; r != nil && fromReport {
					asset.Analysis, asset.CallChains = r.Analysis, r.CallChains
				}
				if v.Reachability == VerdictUnreachable {
					// What the stitch lists for a finding without a route is the
					// finding's own function, which is no chain from the project.
					asset.CallChains = nil
				}
				dto.Summary.add(v.Reachability)
				resp.Summary.add(v.Reachability)
			}
			dto.FindingCount += len(file.CryptographicAssets)
		}
		if fromReport {
			for _, asset := range addConditionedAssets(&frag, l.Stored.Findings, findings, expansions[key]) {
				if asset.Reachability == VerdictUnreachable && viaMissingOnly[key] {
					asset.Reachability, asset.ReachabilityReason = VerdictUnknown, ReasonDependencyWithoutGraph
				}
				dto.Summary.add(asset.Reachability)
				resp.Summary.add(asset.Reachability)
				dto.FindingCount++
				added++
			}
		}
		dto.Findings = append(dto.Findings, findings...)
		migration := &ComponentDataDTO{Findings: dto.Findings}
		AnnotateMigration(migration)
		dto.MigrationSummary = migration.MigrationSummary
	}
	resp.InfoCode = InfoNoInfo
	if ready > 0 {
		resp.InfoCode = InfoReady
		resp.RulesVersion = HighestRulesVersion(rulesVersions)
	}
	resp.InfoMessage = fmt.Sprintf("%d of %d dependencies have reachability data", ready, len(keys))
	resp.Status = OKStatus(resp.InfoCode)
	return resp, added
}

// servedStoredFindings copies a dependency's stored report for one response:
// the assets as findings-only /component serves them, under the
// dependency-prefixed path and dependency_info every project finding has
// carried, with source indirect (the project reaches them through a
// dependency). The stored report itself is never written.
func servedStoredFindings(key ComponentKey, module string, stored *StoredFindings) []*FindingDTO {
	info := DependencyInfoDTO{Module: module, Version: key.Version, PURL: key.Purl + "@" + key.Version}
	out := make([]*FindingDTO, 0, len(stored.Findings))
	for _, file := range stored.Findings {
		served := &FindingDTO{
			FilePath:            DepPrefixedPath(file.FilePath, module, key.Version),
			Language:            file.Language,
			CryptographicAssets: make([]*CryptographicAssetDTO, len(file.CryptographicAssets)),
		}
		if file.DependencyInfo != nil {
			fileInfo := *file.DependencyInfo
			served.DependencyInfo = &fileInfo
		} else {
			fileInfo := info
			served.DependencyInfo = &fileInfo
		}
		for i, asset := range file.CryptographicAssets {
			a := *asset
			a.Source = SourceIndirect
			served.CryptographicAssets[i] = &a
		}
		out = append(out, served)
	}
	return out
}
