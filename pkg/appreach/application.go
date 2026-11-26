// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	gf "github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/pkg/conditioned"
)

// RequestSchemaVersion is the version of the project request and response
// bodies. A request naming another version is refused.
const RequestSchemaVersion = "1"

// Reachability verdicts.
const (
	VerdictReachable   = "reachable"
	VerdictUnreachable = "unreachable"
	VerdictUnknown     = "unknown"
)

// Reasons an unknown verdict carries (reachability_reason).
const (
	// ReasonAmbiguousDispatch: the project reaches the finding only through an
	// interface call with several implementations in the closure.
	ReasonAmbiguousDispatch = gf.UnresolvedReasonAmbiguousDispatch
	// ReasonUnresolvedDispatch: only through a call linked by name.
	ReasonUnresolvedDispatch = gf.UnresolvedReasonDispatch
	// ReasonSearchCapped: the route search hit a cap before it could decide.
	ReasonSearchCapped = "search_capped"
	// ReasonNoContainingFunction: the finding sits outside any function (a
	// field or static initializer), so no call can reach it.
	ReasonNoContainingFunction = "no_containing_function"
	// ReasonDependencyEntryPointOnly: the project reaches a function that the
	// dependency's mine-time entry-point index says reaches the finding, but
	// the stitch holds no route of calls to it.
	ReasonDependencyEntryPointOnly = "dependency_entry_point_only"
	// ReasonDependencyWithoutGraph: every dependency path from the project to
	// the finding's dependency crosses a dependency with no graph, whose
	// calls are therefore not in the graph.
	ReasonDependencyWithoutGraph = "dependency_without_graph"
	// ReasonNotAnnotated: the dependency's stored findings report holds the
	// finding but its crypto annotation does not, so the stitch never saw it.
	ReasonNotAnnotated = "finding_not_annotated"
	// ReasonUnpinned: the client could not pin the dependency's version (a
	// range, no lock). It never reaches the API, which needs a version; the
	// client reports the dependency without findings under this reason.
	ReasonUnpinned = "unpinned"
)

// MaxChainsHigh is the upper bound of max_chains_per_finding.
const MaxChainsHigh = 128

// Limits bounds one project request.
type Limits struct {
	MaxDependencies int
	MaxCallSites    int
}

// DefaultLimits are the limits the API starts with.
var DefaultLimits = Limits{MaxDependencies: 1000, MaxCallSites: 50000}

// Dependency is one member of the project's pinned dependency closure.
type Dependency struct {
	Purl    string `json:"purl"`
	Version string `json:"version"`
	// Direct marks a dependency the project declares itself.
	Direct bool `json:"direct"`
	// Requires lists the purls this dependency depends on in the project's
	// resolved tree, each pinned elsewhere in the request. When no dependency
	// carries it, the caller supplies the edges (the API reads those recorded
	// at mining time).
	Requires []string `json:"requires,omitempty"`
	// Markers and Extras, for a Python dependency, are the PEP 508
	// environment markers under which the project installs it and the
	// extras it enables, as the lock writes them. They are informational:
	// the closure is the union of every marker branch, and no verdict reads
	// them.
	Markers []string `json:"markers,omitempty"`
	Extras  []string `json:"extras,omitempty"`
}

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

// Root is the stitch root standing for the client's project.
var Root = ComponentKey{Purl: "pkg:generic/project"}

// Pins is the request's dependency closure, keyed by canonical versionless
// purl, in request order.
type Pins struct {
	Order []string
	Dep   map[string]Dependency
}

// Direct lists the dependencies the project declares, in request order.
func (p Pins) Direct() []string {
	var out []string
	for _, purl := range p.Order {
		if p.Dep[purl].Direct {
			out = append(out, purl)
		}
	}
	return out
}

// Key is the pinned component of a purl, versioned or not, if it is pinned.
func (p Pins) Key(purl string) (ComponentKey, bool) {
	parsed, err := ParsePurl(purl)
	if err != nil {
		return ComponentKey{}, false
	}
	parsed.Version = ""
	d, ok := p.Dep[parsed.String()]
	return ComponentKey{Purl: d.Purl, Version: d.Version}, ok
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
	pins, rejection := parseDependencies(req.Dependencies, limits)
	if rejection != "" {
		return reject(InfoInvalidRequest, rejection)
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
	keys := make([]ComponentKey, len(pins.Order))
	for i, purl := range pins.Order {
		keys[i] = ComponentKey{Purl: purl, Version: pins.Dep[purl].Version}
	}
	return &Plan{Request: req, Pins: pins, Keys: keys, Catalog: catalog}, nil
}

// parseDependencies canonicalizes the closure. A malformed request (empty, too
// large, an invalid purl, a missing version, conflicting versions for one
// purl, no direct dependency) is rejected as a whole: the closure is one
// resolved classpath, and a hole in it changes every verdict.
func parseDependencies(deps []Dependency, limits Limits) (Pins, string) { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	if len(deps) == 0 {
		return Pins{}, "dependencies: must not be empty"
	}
	if len(deps) > limits.MaxDependencies {
		return Pins{}, fmt.Sprintf("dependencies: %d entries, at most %d", len(deps), limits.MaxDependencies)
	}
	pins := Pins{Dep: make(map[string]Dependency, len(deps))}
	anyDirect := false
	for i, d := range deps {
		p, err := ParsePurl(d.Purl)
		if err != nil {
			return Pins{}, fmt.Sprintf("dependencies[%d]: invalid purl %q", i, d.Purl)
		}
		version := strings.TrimSpace(d.Version)
		if version == "" {
			version = p.Version
		}
		if version == "" {
			return Pins{}, fmt.Sprintf("dependencies[%d]: version is required", i)
		}
		pypi := p.Type == "pypi"
		if pypi {
			version = PyPIVersion(version)
		}
		p.Version = ""
		canonical := p.String()
		if prev, seen := pins.Dep[canonical]; seen {
			if prev.Version != version && (!pypi || !PyPIVersionsEqual(prev.Version, version)) {
				return Pins{}, fmt.Sprintf("dependencies[%d]: conflicting versions for %s (%s and %s)", i, canonical, prev.Version, version)
			}
			prev.Direct = prev.Direct || d.Direct
			prev.Requires = append(prev.Requires, d.Requires...)
			pins.Dep[canonical] = prev
			continue
		}
		d.Purl, d.Version = canonical, version
		pins.Dep[canonical] = d
		pins.Order = append(pins.Order, canonical)
		anyDirect = anyDirect || d.Direct
	}
	if !anyDirect {
		return Pins{}, "dependencies: at least one must be direct"
	}
	return pins, ""
}

// RequestEdges returns the dependency edges the request names among the
// pinned closure, and whether any dependency named what it requires. When
// none did, the caller supplies the edges (EdgesFrom).
func (p *Plan) RequestEdges() (map[ComponentKey][]ComponentKey, bool) {
	out := make(map[ComponentKey][]ComponentKey)
	fromRequest := false
	for _, purl := range p.Pins.Order {
		d := p.Pins.Dep[purl]
		if len(d.Requires) == 0 {
			continue
		}
		fromRequest = true
		parent := ComponentKey{Purl: d.Purl, Version: d.Version}
		for _, r := range d.Requires {
			if child, ok := p.Pins.Key(r); ok && child != parent {
				out[parent] = append(out[parent], child)
			}
		}
	}
	return out, fromRequest
}

// EdgesFrom keeps, of the edges recorded elsewhere (each pinned version and
// the purls it depended on), those between pinned components.
func (p *Plan) EdgesFrom(recorded map[ComponentKey][]string) map[ComponentKey][]ComponentKey {
	out := make(map[ComponentKey][]ComponentKey)
	for parent, children := range recorded {
		for _, purl := range children {
			if child, ok := p.Pins.Key(purl); ok && child != parent {
				out[parent] = append(out[parent], child)
			}
		}
	}
	return out
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

// RunError is a failed run: the stage that failed (stitch, hydrate or
// render) and its error. A canceled or expired ctx fails as the stitch
// stage with ctx's error.
type RunError struct {
	Stage string
	Err   error
}

func (e *RunError) Error() string {
	return "application reachability " + e.Stage + ": " + e.Err.Error()
}

func (e *RunError) Unwrap() error { return e.Err }

// Run decides, for every finding of the pinned closure, whether the project's
// call sites reach it. It stitches the loaded components of exactly the
// pinned versions under the call sites, with the stitcher options validated
// against labeled truth (a labeled Java benchmark): classpath targets, hierarchy
// from supertypes, and ambiguous dispatch served unknown. Closure targets stay
// off: on that benchmark they resolve the edges the Maven tree omits but cost a correct
// verdict (an over-approximated iText route into bcprov) and win none. A
// Python component resolves what its requires leave unresolved against the
// whole pinned environment (EnvironmentTargets): Python imports anything
// installed, and a lock's requires miss optional imports. edges
// are the dependency edges among the pinned components (RequestEdges or
// EdgesFrom).
// loaded must hold every pinned key; a component without a fragment is
// served with its own code.
func (p *Plan) Run(ctx context.Context, loaded map[ComponentKey]Component, edges map[ComponentKey][]ComponentKey, opts RunOptions) (Response, Stats, error) {
	var stats Stats
	fragments := make(map[ComponentKey]Fragment, len(loaded)+1)
	for k, l := range loaded {
		if l.Fragment == nil {
			continue
		}
		frag := *l.Fragment
		// A component mined on its own records no module (the miner stores
		// it empty). The callgraph export then prefixes a finding's
		// path with the purl, while the findings envelope and the stitch's
		// translation of a dependency's entry-point index do not prefix it at
		// all: the three would disagree on every dependency finding id, and
		// findings proven through the index would be dropped. Name the module
		// once, for all three.
		if frag.Module == "" {
			frag.Module = PurlToModule(k.Purl)
		}
		fragments[k] = frag
	}
	stats.WithGraph = len(fragments)
	deps, viaMissingOnly := dependencyGraph(Root, p.Keys, p.Pins.Direct(), edges, fragments)
	fragments[Root] = applicationFragment(Root, p.Request.CallSites)

	started := time.Now()
	plan := conditioned.NewPlan(fragments, Root, p.Catalog)
	stats.ConditionedAnchors = len(plan.Anchors)
	res, err := StitchWithContext(ctx, Root, deps, fragments, StitchOptions{
		EntryRootedOnly:          true,
		ClasspathTargets:         true,
		EnvironmentTargets:       []string{"python"},
		HierarchyFromSupertypes:  true,
		ServiceProviderDispatch:  true,
		AmbiguousDispatchUnknown: true,
		SelectorCalls:            plan.Calls,
		SuppressedSummaryOnly:    true,
	})
	if err != nil {
		return Response{}, stats, &RunError{Stage: "stitch", Err: err}
	}
	meta := ScanMeta{SchemaVersion: CallgraphSchemaVersion, RootModule: Root.Purl, Ecosystem: EcosystemForPurl(p.Pins.Order[0])}
	cg := res.ToCallgraphExport(Root, meta)
	verdicts := findingVerdicts(cg.FindingGraphs)
	expansions := groupExpansions(plan.Expand(res.SelectorValues()))
	if !p.Request.IncludeCallChains {
		// The verdicts are read; nothing below renders a chain.
		cg.Functions = nil
		for i := range cg.FindingGraphs {
			cg.FindingGraphs[i].CallChains, cg.FindingGraphs[i].CallChainIndexes = nil, nil
		}
	} else {
		if !cg.HydrateChainIdentities() {
			return Response{}, stats, &RunError{Stage: "hydrate", Err: fmt.Errorf("interned callgraph frames")}
		}
		keepServedChains(cg.FindingGraphs, resolveMaxChains(p.Request.MaxChainsPerFinding))
	}
	if opts.AfterStitch != nil {
		opts.AfterStitch()
	}
	stitched := time.Now()
	stats.Stitch = stitched.Sub(started)

	block, err := renderApplication(fragments, deps, meta, cg, p.Request.IncludeCallChains, p.Request.MaxChainsPerFinding)
	if err != nil {
		return Response{}, stats, &RunError{Stage: "render", Err: err}
	}
	resp, added := applicationResponse(p.Pins, p.Keys, loaded, block, fragments, verdicts, viaMissingOnly, expansions)
	stats.ConditionedAdded = added
	stats.Render = time.Since(stitched)
	return resp, stats, nil
}

// dependencyGraph builds the stitch's dependency graph over the components
// that have a graph. A component without one is spliced out (its
// dependencies hang from its parents), so the classpath stays whole; the
// components reachable from the project only through such a component are
// returned in viaMissingOnly. A pinned dependency no edge reaches hangs from
// the project: the client resolved it into the closure, so it is on the
// classpath.
func dependencyGraph(root ComponentKey, keys []ComponentKey, direct []string, edges map[ComponentKey][]ComponentKey, present map[ComponentKey]Fragment) (DependencyGraph, map[ComponentKey]bool) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	full := make(map[ComponentKey][]ComponentKey, len(keys)+1)
	versionOf := make(map[string]string, len(keys))
	for _, k := range keys {
		versionOf[k.Purl] = k.Version
	}
	for _, purl := range direct {
		full[root] = append(full[root], ComponentKey{Purl: purl, Version: versionOf[purl]})
	}
	for parent, children := range edges {
		full[parent] = append(full[parent], children...)
	}
	reach := func(skipMissing bool) map[ComponentKey]bool {
		seen := map[ComponentKey]bool{root: true}
		stack := []ComponentKey{root}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, c := range full[n] {
				if seen[c] {
					continue
				}
				seen[c] = true
				if _, ok := present[c]; ok || !skipMissing {
					stack = append(stack, c)
				}
			}
		}
		return seen
	}
	connected := reach(false)
	for _, k := range keys {
		if !connected[k] {
			full[root] = append(full[root], k)
		}
	}
	withMissing, withoutMissing := reach(false), reach(true)
	viaMissingOnly := make(map[ComponentKey]bool)
	for _, k := range keys {
		if _, ok := present[k]; ok && withMissing[k] && !withoutMissing[k] {
			viaMissingOnly[k] = true
		}
	}

	// Splice: the present children of a node, looking through missing ones.
	var kids func(n ComponentKey, seen map[ComponentKey]bool) []ComponentKey
	kids = func(n ComponentKey, seen map[ComponentKey]bool) []ComponentKey {
		var out []ComponentKey
		for _, c := range full[n] {
			if seen[c] {
				continue
			}
			seen[c] = true
			if _, ok := present[c]; ok {
				out = append(out, c)
			} else {
				out = append(out, kids(c, seen)...)
			}
		}
		return out
	}
	deps := make(DependencyGraph, len(present)+1)
	deps[root] = kids(root, map[ComponentKey]bool{root: true})
	for k := range present {
		deps[k] = kids(k, map[ComponentKey]bool{k: true})
	}
	return deps, viaMissingOnly
}

// applicationFragment is the root fragment the stitch walks from: the client's
// call-site functions and their calls into dependencies, nothing else. Internal
// edges, project crypto and entry kinds are dropped, so every call-site function
// is a root and a verdict never depends on what else the client sent. Which
// functions are call-site functions is the client's decision: it leaves out
// the ones its own entry points do not reach.
func applicationFragment(root ComponentKey, doc *gf.GraphFragmentExport) Fragment {
	frag := doc.ToFragment(root)
	callers := make(map[string]bool, len(frag.ExternalCalls))
	for _, c := range frag.ExternalCalls {
		callers[c.Caller] = true
	}
	fns := frag.Functions[:0]
	for _, f := range frag.Functions {
		if callers[f.Signature] {
			fns = append(fns, f)
		}
	}
	frag.Functions, frag.InternalEdges = fns, nil
	frag.CryptoOperations, frag.SupportingCalls, frag.CryptoEntryPoints = nil, nil, nil
	frag.EntryKinds = nil
	return frag
}

// verdict is one finding's served reachability.
type verdict struct {
	reachability string
	reason       string
}

// findingVerdicts reads the stitched finding graphs as served verdicts. The
// stitched export reads every finding without a route as unknown as soon as
// the stitch suppressed any call anywhere in the closure, which on a real
// closure is every finding. Per finding, unknown is a route that needs a call
// the stitch could not resolve (the export names it in unresolved_reason) or a
// search that hit a cap; any other finding without a route is unreachable.
// A finding with no finding graph has no route either.
func findingVerdicts(graphs []ExportFindingGraph) map[string]verdict {
	out := make(map[string]verdict, len(graphs))
	for i := range graphs {
		g := &graphs[i]
		v := verdict{reachability: VerdictUnreachable}
		switch {
		case g.Reachability == VerdictReachable && !hasRoute(g):
			v = verdict{reachability: VerdictUnknown, reason: ReasonDependencyEntryPointOnly}
		case g.Reachability == VerdictReachable:
			v.reachability = VerdictReachable
		case g.Reachability == VerdictUnknown && g.UnresolvedReason != "":
			v = verdict{reachability: VerdictUnknown, reason: g.UnresolvedReason}
		case g.Reachability == VerdictUnknown && g.Analysis != nil && g.Analysis.CallChains == "partial":
			v = verdict{reachability: VerdictUnknown, reason: ReasonSearchCapped}
		case g.Reachability == gf.ReachabilityNotApplicable:
			v = verdict{reachability: VerdictUnknown, reason: ReasonNoContainingFunction}
		}
		out[g.FindingID] = v
	}
	return out
}

// hasRoute reports whether a finding graph holds a route of at least one call
// (two frames), interned or not.
func hasRoute(g *ExportFindingGraph) bool {
	for _, c := range g.CallChains {
		if len(c) >= 2 {
			return true
		}
	}
	for _, c := range g.CallChainIndexes {
		if len(c) >= 2 {
			return true
		}
	}
	return false
}

// keepServedChains trims each finding graph to the chains ComponentBlock
// serves: the first limit whose frames all have identity. The stitch keeps up to
// 128 chains per operation and a request usually asks for one; the renderer
// would marshal, parse and check every chain only to drop the rest. A graph
// with a nameless frame and no indexes is left whole, for the renderer to
// refuse as before.
func keepServedChains(graphs []ExportFindingGraph, limit int) {
	for i := range graphs {
		g := &graphs[i]
		withIndexes := len(g.CallChainIndexes) > 0
		if !withIndexes && slices.ContainsFunc(g.CallChains, chainMissingIdentity) {
			continue
		}
		kept := 0
		for j := range g.CallChains {
			if kept == limit {
				break
			}
			if chainMissingIdentity(g.CallChains[j]) {
				continue
			}
			g.CallChains[kept] = g.CallChains[j]
			if withIndexes {
				g.CallChainIndexes[kept] = g.CallChainIndexes[j]
			}
			kept++
		}
		g.CallChains = g.CallChains[:kept]
		if withIndexes {
			g.CallChainIndexes = g.CallChainIndexes[:kept]
		}
	}
}

// chainMissingIdentity is frameMissingIdentity over a typed chain: a frame
// with neither function_name nor canonical_signature.
func chainMissingIdentity(chain []ExportChainNode) bool {
	for i := range chain {
		if chain[i].FunctionName == "" && chain[i].CanonicalSignature == "" {
			return true
		}
	}
	return false
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

// findingOwners maps each finding id of the closure to the component it sits
// in, computed as the stitch computes the ids of dependency findings.
func findingOwners(fragments map[ComponentKey]Fragment) map[string]ComponentKey {
	out := make(map[string]ComponentKey)
	for key, frag := range fragments {
		if key == Root {
			continue
		}
		for i := range frag.CryptoOperations {
			op := &frag.CryptoOperations[i]
			path := DepPrefixedPath(op.FilePath, frag.Module, key.Version)
			out[ComputeFindingID(path, op.StartLine, op.RuleID)] = key
		}
	}
	return out
}

// applicationResponse builds the envelope in request order. A dependency's
// findings are its stored findings report, served as findings-only /component
// serves it, with the stitch's verdict attached to each asset; a dependency
// whose report is unusable keeps the findings rendered from its annotation.
func applicationResponse(pins Pins, keys []ComponentKey, loaded map[ComponentKey]Component, block *ComponentDataDTO, fragments map[ComponentKey]Fragment, verdicts map[string]verdict, viaMissingOnly map[ComponentKey]bool, expansions conditionedExpansions) (Response, int) { //nolint:funlen,gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	owners := findingOwners(fragments)
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
		if ids := storedStitchIDs(key, frag); l.Stored != nil && (len(ids) > 0 || len(frag.CryptoOperations) == 0) {
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
					v = verdict{reachability: VerdictUnknown, reason: ReasonNotAnnotated}
				case !ok:
					v = verdict{reachability: VerdictUnreachable}
				}
				if v.reachability == VerdictUnreachable && viaMissingOnly[key] {
					v = verdict{reachability: VerdictUnknown, reason: ReasonDependencyWithoutGraph}
				}
				asset.Reachability, asset.ReachabilityReason = v.reachability, v.reason
				if r := rendered[id]; r != nil && fromReport {
					asset.Analysis, asset.CallChains = r.Analysis, r.CallChains
				}
				if v.reachability == VerdictUnreachable {
					// What the stitch lists for a finding without a route is the
					// finding's own function, which is no chain from the project.
					asset.CallChains = nil
				}
				dto.Summary.add(v.reachability)
				resp.Summary.add(v.reachability)
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

// storedStitchIDs maps a dependency's stored finding ids to the ids the
// stitch gives its findings. Each annotation operation carries the finding id
// of the report asset it was built from, while the stitch derives its own from
// the operation's dependency-prefixed path, line and first rule. Several
// assets on one line under one first rule share a stitch id, and so a verdict.
func storedStitchIDs(key ComponentKey, frag Fragment) map[string]string {
	out := make(map[string]string, len(frag.CryptoOperations))
	for i := range frag.CryptoOperations {
		op := &frag.CryptoOperations[i]
		if op.FindingID == "" {
			continue
		}
		out[op.FindingID] = ComputeFindingID(DepPrefixedPath(op.FilePath, frag.Module, key.Version), op.StartLine, op.RuleID)
	}
	return out
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
