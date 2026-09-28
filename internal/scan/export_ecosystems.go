package scan

import (
	"sort"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// A scan resolves dependencies for one ecosystem, the primary one, but a
// repository can hold first-party code in several: a Java service beside a
// TypeScript front end. Each supported ecosystem gets its own call graph, and a
// finding resolves against the graph of the language it is written in. Looking
// a TypeScript finding up in a Java graph finds no containing function, which
// used to be reported as if the code had been analyzed and nothing contained it.

const (
	ecosystemC   = "c"
	ecosystemCPP = "cpp"

	unresolvedNoContainingFunction = "no_containing_function"
	// unresolvedLanguageNotAnalyzed marks a finding whose language had no call
	// graph in this scan: the language has no call graph parser, or its graph
	// could not be built. Nothing about its reachability was examined.
	unresolvedLanguageNotAnalyzed = "language_not_analyzed"
)

// EcosystemForLanguage maps a finding's detected language to the call graph
// ecosystem that parses it, or "" when no call graph parser supports it.
func EcosystemForLanguage(language string) string {
	switch language {
	case ecosystemC:
		return ecosystemC
	case ecosystemCPP, "c++":
		return ecosystemCPP
	case ecosystemGo, ecosystemJava, ecosystemPython, ecosystemRust:
		return language
	case ecosystemNode, "javascript", "typescript":
		return ecosystemNode
	default:
		return ""
	}
}

// sameCallGraphFamily reports whether findings of ecosystem a resolve in a call
// graph built for b. C and C++ share headers and translation units, and a scan
// has always resolved both against whichever of the two it built.
func sameCallGraphFamily(a, b string) bool {
	if a == b {
		return true
	}
	cFamily := func(e string) bool { return e == ecosystemC || e == ecosystemCPP }
	return cFamily(a) && cFamily(b)
}

// AdditionalCallGraphEcosystems lists, sorted, the supported ecosystems other
// than primary that the report's first-party findings are written in. These
// are the call graphs a scan builds beside the primary one.
func AdditionalCallGraphEcosystems(report *entities.InterimReport, primary string) []string {
	if report == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for i := range report.Findings {
		finding := &report.Findings[i]
		ecosystem := EcosystemForLanguage(finding.Language)
		if ecosystem == "" || seen[ecosystem] || sameCallGraphFamily(ecosystem, primary) || !hasFirstPartyAsset(finding) {
			continue
		}
		seen[ecosystem] = true
		out = append(out, ecosystem)
	}
	sort.Strings(out)
	return out
}

func hasFirstPartyAsset(finding *entities.Finding) bool {
	for i := range finding.CryptographicAssets {
		info := finding.CryptographicAssets[i].DependencyInfo
		if info == nil || info.Module == "" {
			return true
		}
	}
	return false
}

// exportContextSet is the build context for every call graph one export
// covers. The primary context is the one a single-ecosystem export always had,
// so a scan with no additional ecosystem exports exactly what it did before.
type exportContextSet struct {
	primary    *exportBuildContext
	additional map[string]*exportBuildContext
	// ordered lists every context, the primary first and then the additional
	// ones by ecosystem name, so output that merges them is deterministic.
	ordered []*exportBuildContext
}

func singleExportContextSet(ctx *exportBuildContext) *exportContextSet {
	return &exportContextSet{primary: ctx, ordered: []*exportBuildContext{ctx}}
}

func newCallGraphExportContextSet(result *engine.DepScanResult, findings []entities.Finding, options CallGraphExportOptions) *exportContextSet {
	set := singleExportContextSet(newCallGraphExportBuildContext(result, findings, options))
	if len(result.AdditionalEcosystems) == 0 {
		return set
	}
	// An additional ecosystem resolves no dependencies, so its findings are
	// all first-party. They are classified against its own source packages
	// whenever the primary ecosystem is: when dependencies were resolved, or
	// when project reachability was requested.
	projectReach := len(result.Dependencies) > 0 || options.ProjectReachability
	set.additional = make(map[string]*exportBuildContext, len(result.AdditionalEcosystems))
	for _, extra := range sortedAdditionalEcosystems(result.AdditionalEcosystems) {
		if extra.CallGraph == nil || extra.Ecosystem == "" || set.additional[extra.Ecosystem] != nil {
			continue
		}
		routed := findingsInEcosystem(findings, extra.Ecosystem)
		var userPackages map[string]bool
		if projectReach {
			userPackages = projectUserPackages(extra)
		}
		ctx := newExportBuildContextWithUserPackages(extra, routed, options.MaxChains, userPackages)
		set.additional[extra.Ecosystem] = ctx
		set.ordered = append(set.ordered, ctx)
	}
	return set
}

func sortedAdditionalEcosystems(extras []*engine.DepScanResult) []*engine.DepScanResult {
	out := make([]*engine.DepScanResult, 0, len(extras))
	for _, extra := range extras {
		if extra != nil {
			out = append(out, extra)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ecosystem < out[j].Ecosystem })
	return out
}

func findingsInEcosystem(findings []entities.Finding, ecosystem string) []entities.Finding {
	var out []entities.Finding
	for i := range findings {
		if EcosystemForLanguage(findings[i].Language) == ecosystem {
			out = append(out, findings[i])
		}
	}
	return out
}

// forFinding returns the context a finding resolves against, and whether a
// call graph for its language exists at all. A finding of the primary
// ecosystem, or of a language that maps to no ecosystem, keeps the primary
// context, exactly as before additional ecosystems existed.
func (s *exportContextSet) forFinding(finding entities.Finding) (ctx *exportBuildContext, analyzed bool) {
	ecosystem := EcosystemForLanguage(finding.Language)
	switch {
	case ecosystem == "":
		// An empty language is a finding the tool synthesized for the primary
		// graph; any other unmapped language has no call graph parser.
		return s.primary, finding.Language == ""
	case sameCallGraphFamily(ecosystem, s.primary.ecosystem):
		return s.primary, true
	case s.additional[ecosystem] != nil:
		return s.additional[ecosystem], true
	default:
		return s.primary, false
	}
}

// markLanguageNotAnalyzed replaces the generic no-containing-function reason
// with the one that says why: no call graph was built for the language.
func markLanguageNotAnalyzed(fg *callGraphExportFinding) {
	if fg.UnresolvedReason == unresolvedNoContainingFunction {
		fg.UnresolvedReason = unresolvedLanguageNotAnalyzed
	}
}

// exportEcosystemsMeta lists every call graph the export analyzed, primary
// first. It is nil for a single-ecosystem result, so that export is unchanged.
func exportEcosystemsMeta(result *engine.DepScanResult) []graphfrag.ExportEcosystem {
	extras := sortedAdditionalEcosystems(result.AdditionalEcosystems)
	if len(extras) == 0 || result.CallGraph == nil {
		return nil
	}
	out := []graphfrag.ExportEcosystem{{
		Ecosystem:     result.Ecosystem,
		RootModule:    result.RootModule,
		FunctionCount: len(result.CallGraph.Functions),
		EdgeCount:     countCallGraphEdges(result.CallGraph),
	}}
	for _, extra := range extras {
		if extra.CallGraph == nil {
			continue
		}
		out = append(out, graphfrag.ExportEcosystem{
			Ecosystem:     extra.Ecosystem,
			RootModule:    extra.RootModule,
			FunctionCount: len(extra.CallGraph.Functions),
			EdgeCount:     countCallGraphEdges(extra.CallGraph),
		})
	}
	if len(out) == 1 {
		return nil
	}
	return out
}

// applyExportEcosystemsMeta stamps the analyzed-ecosystems list on the
// interned render, the schema that declares it. The inlined compatibility
// render stays on schema 6.14, which does not.
func applyExportEcosystemsMeta(meta *callGraphExportScanMeta, result *engine.DepScanResult, options CallGraphExportOptions) {
	if options.InternedFrames {
		meta.Ecosystems = exportEcosystemsMeta(result)
	}
}
