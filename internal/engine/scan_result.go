package engine

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/pkg/conditioned"
)

// The call graph ecosystems LanguageEcosystem names besides Java, Python and
// Rust.
const (
	ecosystemC   = "c"
	ecosystemCPP = "cpp"
	npmEcosystem = "node"
)

// The languages the node ecosystem parses.
const (
	languageJavaScript = "javascript"
	languageTypeScript = "typescript"
)

const (
	findingSourceDependency = "dependency"
	findingSourceDirect     = "direct"
)

// DepScanResult is a scan's call graph with the report it was built for and,
// after a dependency scan, the project's resolved dependency closure. The
// exports and the rule graph passes read it.
type DepScanResult struct {
	Report    *entities.InterimReport
	CallGraph *callgraph.CallGraph
	// OccurrenceAnchors retains source-only declarations used to enrich finding
	// occurrence keys without changing the exported dependency call graph.
	// Keys are ecosystem-qualified FunctionID strings.
	OccurrenceAnchors map[string]*callgraph.FunctionDecl
	RootModule        string
	Ecosystem         string
	ProjectRoot       string
	Dependencies      []dependency.Dependency
	// DependencyPaths holds, per dependency module, its shortest route from
	// the application in the resolved dependency graph and whether every
	// route crosses a dependency parsed without source. Nil when the resolver
	// produced no graph.
	DependencyPaths map[string]dependency.Path
	// AdditionalEcosystems holds one call graph per other supported
	// ecosystem the scan target contains. The fields above describe the
	// primary ecosystem, the first one dependencies resolve for; a finding
	// written in another language is resolved against the entry for its own
	// ecosystem. An entry the dependency phase resolved (auto mode resolves
	// every ecosystem with a manifest) carries its Dependencies,
	// DependencyPaths and dependency-aware CallGraph; any other entry is a
	// graph of the target's own source and carries no dependencies. Entries
	// carry no additional ecosystems of their own.
	AdditionalEcosystems []*DepScanResult
}

// resolveScanRoot resolves the scan root, reaching the module roots below it
// when the root itself holds no build manifest for this ecosystem and no
// ancestor manifest its toolchain would find on its own. A scan root that
// resolves today takes the single Resolve call it always took, with the same
// typed error.
//
// It also returns the directories it resolved: the target, or each module root.
// A resolver that tells local dependencies from project code
// (dependency.ScanRootConfigurer) is given target as the scan root first, so a
// directory a module root reaches inside the scanned tree stays project code.
//
// skipPatterns are the scan's exclusions. Discovery honors them because
// resolving a root runs mvn, gradle, cargo or go in that directory, which is a
// heavier consequence than reading a file the user asked to skip.
func resolveScanRoot(
	ctx context.Context,
	resolver dependency.Resolver,
	target string,
	skipPatterns []string,
) (*dependency.ResolveResult, []string, error) {
	if r, ok := resolver.(dependency.ScanRootConfigurer); ok {
		r.SetScanRoot(target)
	}
	ecosystem := resolver.Ecosystem()
	discovery := dependency.ResolutionRoots(target, ecosystem, skipPatterns)
	logRootDiscovery(target, ecosystem, discovery)
	if len(discovery.Roots) == 0 {
		result, err := resolver.Resolve(ctx, target)
		return result, []string{target}, err
	}

	resolutions := make([]dependency.RootResolution, 0, len(discovery.Roots))
	var unsupported error
	dirs := make([]string, 0, len(discovery.Roots))
	for i, root := range discovery.Roots {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		log.Info().Str("root", root.Rel).Int("index", i+1).Int("roots", len(discovery.Roots)).Msg("Resolving module root")
		result, err := resolver.Resolve(ctx, root.Dir)
		if errors.Is(err, dependency.ErrUnsupportedNpmLock) {
			// An npm 6 lock skips its own root; the other roots resolve.
			log.Warn().Str("root", root.Rel).Err(err).Msg("Skipping a module root whose npm lock is lockfileVersion 1 (npm 6); regenerate it with npm 7 or later")
			unsupported = err
			continue
		}
		if err != nil {
			// WrapUnknown only prefixes an already-typed failure, so the root
			// keeps its own code and details and now also names which of
			// several roots failed.
			return nil, nil, failure.WrapUnknown(
				err,
				failure.CodeDependencyResolutionFailed,
				failure.StageDependency,
				"resolving module root "+root.Rel,
			)
		}
		resolutions = append(resolutions, dependency.RootResolution{Root: root, Result: result})
		dirs = append(dirs, root.Dir)
	}
	if len(resolutions) == 0 && unsupported != nil {
		// Every root's lock was unreadable: the caller skips the ecosystem.
		return nil, nil, unsupported
	}
	merged := dependency.MergeRootResolutions(resolutions)
	if ecosystem == "node" {
		dependency.KeepOneNpmVersionAcrossRoots(merged)
	}
	return merged, dirs, nil
}

func logRootDiscovery(target, ecosystem string, discovery dependency.RootDiscovery) {
	if !discovery.Searched {
		return
	}
	if discovery.Unreadable > 0 {
		log.Debug().Int("dirs", discovery.Unreadable).Msg("Module root discovery could not read some directories")
	}
	if discovery.Abandoned {
		log.Warn().Str("target", target).Msg("Module root discovery stopped at its entry cap; some module roots may be missing")
	}
	if len(discovery.Roots) == 0 {
		log.Info().Str("target", target).Str("ecosystem", ecosystem).Msg("No module root found below the scan root")
		return
	}
	paths := make([]string, 0, len(discovery.Roots))
	for _, root := range discovery.Roots {
		paths = append(paths, root.Rel)
	}
	log.Info().Str("ecosystem", ecosystem).Int("roots", len(paths)).Strs("paths", paths).Msg("Found module roots below the scan root")
	if discovery.Truncated {
		log.Warn().Int("found", discovery.Found).Int("resolving", len(paths)).Msg("More module roots qualified than the cap allows; the shallowest, then lexically first, were kept")
	}
}

// attributeDependencyAsset makes asset a finding of the dependency info names:
// source dependency, that dependency_info, and no rule package URL (the purl a
// rule names for the crypto library it detects), which only a first-party
// finding carries.
func attributeDependencyAsset(asset *entities.CryptographicAsset, info *entities.DependencyInfo) {
	asset.Source = findingSourceDependency
	asset.PURL = ""
	asset.DependencyInfo = info
}

// EnsureFindingSources normalizes finding source attribution by defaulting any
// un-attributed finding asset to direct source.
func EnsureFindingSources(report *entities.InterimReport) {
	if report == nil {
		return
	}

	for i := range report.Findings {
		finding := &report.Findings[i]
		for j := range finding.CryptographicAssets {
			if finding.CryptographicAssets[j].Source == "" {
				finding.CryptographicAssets[j].Source = findingSourceDirect
			}
		}
	}
}

// enrichDirectFindingPURLs adds a resolved version only when the rule PURL
// matches exactly one version of a direct dependency of the owning module.
// Missing graph/version evidence deliberately leaves the versionless rule URL.
func enrichDirectFindingPURLs(report *entities.InterimReport, target string, resolved *dependency.ResolveResult, ecosystem string) {
	if report == nil || resolved == nil {
		return
	}
	for i := range report.Findings {
		finding := &report.Findings[i]
		// A scan that resolves several ecosystems passes every finding so
		// far through each of them; only this ecosystem's own findings name
		// its packages.
		if own := LanguageEcosystem(finding.Language); own != "" && own != ecosystem {
			continue
		}
		parent := owningModule(target, finding.FilePath, resolved)
		refs := directDependencyRefs(resolved, parent)
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			if asset.Source == findingSourceDependency || asset.PURL == "" {
				continue
			}
			asset.PURL = enrichRulePURL(asset.PURL, refs, ecosystem)
		}
	}
}

func owningModule(target, filePath string, resolved *dependency.ResolveResult) string {
	if len(resolved.WorkspaceMembers) == 0 {
		return resolved.RootModule
	}
	fullPath := filepath.Clean(filePath)
	if !filepath.IsAbs(fullPath) {
		fullPath = filepath.Join(target, fullPath)
	}
	owner := resolved.RootModule
	longest := -1
	for _, member := range resolved.WorkspaceMembers {
		if member.Name == "" || member.Dir == "" {
			continue
		}
		if rel, err := filepath.Rel(filepath.Clean(member.Dir), fullPath); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && len(member.Dir) > longest {
			owner = member.Name
			longest = len(member.Dir)
		}
	}
	return owner
}

func directDependencyRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	if parent == "" {
		return nil
	}
	if refs := versionedDirectDependencyRefs(resolved, parent); len(refs) > 0 {
		return refs
	}
	if refs := graphDirectDependencyRefs(resolved, parent); len(refs) > 0 {
		return refs
	}
	return mavenRootAliasRefs(resolved, parent)
}

func versionedDirectDependencyRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	var refs []dependency.Ref
	for key, children := range resolved.VersionedGraph {
		if key == parent || strings.HasPrefix(key, parent+"@") {
			refs = append(refs, children...)
		}
	}
	return refs
}

func graphDirectDependencyRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	var refs []dependency.Ref
	for _, child := range resolved.Graph[parent] {
		for _, dep := range resolved.Dependencies {
			if dep.Module == child {
				refs = append(refs, dependency.Ref{Module: dep.Module, Version: dep.Version})
			}
		}
	}
	return refs
}

func mavenRootAliasRefs(resolved *dependency.ResolveResult, parent string) []dependency.Ref {
	// Maven exposes RootModule as groupId while its versioned graph keys use
	// groupId:artifactId@version. Recover that single root alias without
	// treating every same-group dependency node as a direct project edge.
	candidates := make(map[string][]dependency.Ref)
	incoming := make(map[string]bool)
	for key, children := range resolved.VersionedGraph {
		module := key
		if at := strings.LastIndexByte(module, '@'); at > 0 {
			module = module[:at]
		}
		if strings.HasPrefix(module, parent+":") {
			candidates[key] = children
		}
	}
	for _, children := range resolved.VersionedGraph {
		for _, child := range children {
			if _, ok := candidates[child.Key()]; ok {
				incoming[child.Key()] = true
			}
		}
	}
	var rootRefs []dependency.Ref
	for key, children := range candidates {
		if !incoming[key] {
			if rootRefs != nil {
				return nil
			}
			rootRefs = children
		}
	}
	return rootRefs
}

func enrichRulePURL(ruleURL string, refs []dependency.Ref, ecosystem string) string {
	want, ok := purl.Identity(ruleURL)
	if !ok {
		return ""
	}
	versions := make(map[string]struct{})
	for _, ref := range refs {
		if ref.Version == "" {
			continue
		}
		candidate := purl.Dependency(ecosystem, ref.Module, ref.Version)
		if candidate == "" {
			continue
		}
		identity, ok := purl.Identity(candidate)
		if ok && identity == want {
			versions[ref.Version] = struct{}{}
		}
	}
	if len(versions) != 1 {
		return ruleURL
	}
	for version := range versions {
		if enriched := purl.WithVersion(ruleURL, version); enriched != "" {
			return enriched
		}
	}
	return ruleURL
}

// AssignFindingIDs ensures every finding asset in the report has a stable short hash
// suitable for joining the main report to the callgraph export.
func AssignFindingIDs(report *entities.InterimReport) {
	if report == nil {
		return
	}

	MarkSyntheticVariants(report)
	for i := range report.Findings {
		assignFindingIDs(&report.Findings[i])
	}
}

// assignFindingIDs gives each asset of finding its id. The id hashes the line,
// not the columns, so two assets one rule reported on one line (two calls side
// by side, or one nested in the other's arguments) would share it. The first
// of them in source order keeps the id it always had; each later one also
// hashes its columns, and a counter when even those are shared, so every id
// in the finding names one asset.
func assignFindingIDs(finding *entities.Finding) {
	assets := finding.CryptographicAssets
	order := make([]int, len(assets))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(x, y int) bool {
		a, b := &assets[order[x]], &assets[order[y]]
		if a.StartCol != b.StartCol {
			return a.StartCol < b.StartCol
		}
		return a.EndCol < b.EndCol
	})
	taken := make(map[string]struct{}, len(assets))
	for _, j := range order {
		asset := &assets[j]
		path := findingIDPath(*finding, *asset)
		id := generateFindingID(path, asset.StartLine, asset.Rules, asset.ConditionedValue)
		for n := 0; ; n++ {
			if _, shared := taken[id]; !shared {
				break
			}
			id = generateFindingID(path, asset.StartLine, asset.Rules, findingIDSpanSalt(asset, n))
		}
		taken[id] = struct{}{}
		asset.FindingID = id
	}
}

// findingIDSpanSalt is what an asset whose line id is taken hashes in place of
// its conditioned value alone: the value, its columns and, past the first
// retry, a counter.
func findingIDSpanSalt(asset *entities.CryptographicAsset, retry int) string {
	salt := asset.ConditionedValue + "@" + strconv.Itoa(asset.StartCol) + "-" + strconv.Itoa(asset.EndCol)
	if retry > 0 {
		salt += "#" + strconv.Itoa(retry)
	}
	return salt
}

// generateFindingID produces a stable short hash for a finding.
// It hashes file_path + start_line + first_rule_id and returns the first 8 hex chars.
// A per-value asset also hashes its resolved condition, so two values of one
// rule at one call do not share an id. Every other asset passes an empty value
// and keeps the id it always had.
func generateFindingID(filePath string, startLine int, ruleInfos []entities.RuleInfo, conditionedValue string) string {
	ruleID := ""
	if len(ruleInfos) > 0 {
		ruleID = ruleInfos[0].ID
	}
	return conditioned.FindingID(filePath, startLine, ruleID, conditionedValue)
}

func findingIDPath(finding entities.Finding, asset entities.CryptographicAsset) string {
	if asset.DependencyInfo != nil && asset.DependencyInfo.Module != "" && asset.DependencyInfo.Version != "" {
		return asset.DependencyInfo.Module + "@" + asset.DependencyInfo.Version + "/" + finding.FilePath
	}
	return finding.FilePath
}

// LanguageEcosystem maps a finding's detected language to the call graph
// ecosystem that parses it, or "" when no call graph parser supports it.
func LanguageEcosystem(language string) string {
	switch language {
	case ecosystemC:
		return ecosystemC
	case ecosystemCPP, "c++":
		return ecosystemCPP
	case "go", languageJava, ecosystemPython, ecosystemRust:
		return language
	case npmEcosystem, languageJavaScript, languageTypeScript, "tsx", "jsx":
		return npmEcosystem
	default:
		return ""
	}
}

func canonicalDependencies(deps []dependency.Dependency) []dependency.Dependency {
	ordered := append([]dependency.Dependency(nil), deps...)
	sort.Slice(ordered, func(i, j int) bool {
		return dependencyLess(ordered[i], ordered[j])
	})

	unique := make(map[string]dependency.Dependency, len(ordered))
	for _, dep := range ordered {
		key := dependencyKey(dep)
		existing, ok := unique[key]
		if !ok {
			unique[key] = dep
			continue
		}
		if existing.Local != dep.Local {
			// One module@version holds one source. The registry version is
			// the one a request can name, so it wins over a local directory
			// (a fork that kept the upstream version), as before local
			// dependencies existed.
			if existing.Local {
				existing, dep = dep, existing
			}
			log.Warn().Str("dependency", key).Str("local_dir", dep.Dir).
				Msg("A module root uses a local directory for a dependency another root takes from the registry at the same version: the registry version is analyzed, not the local directory")
			unique[key] = existing
			continue
		}
		if existing.Dir == "" && dep.Dir != "" {
			unique[key] = dep
			continue
		}
		if existing.CompiledArtifactPath == "" && dep.CompiledArtifactPath != "" {
			existing.CompiledArtifactPath = dep.CompiledArtifactPath
		}
		if existing.SourceArchivePath == "" && dep.SourceArchivePath != "" {
			existing.SourceArchivePath = dep.SourceArchivePath
		}
		existing.Files = unionPaths(existing.Files, dep.Files)
		unique[key] = existing
	}

	result := make([]dependency.Dependency, 0, len(unique))
	for _, dep := range unique {
		result = append(result, dep)
	}
	sort.Slice(result, func(i, j int) bool {
		return dependencyLess(result[i], result[j])
	})
	return result
}

// unionPaths is every path of a and b, sorted, or nil, the whole
// dependency, when either is.
func unionPaths(a, b []string) []string {
	if a == nil || b == nil {
		return nil
	}
	union := slices.Concat(a, b)
	slices.Sort(union)
	return slices.Compact(union)
}

func dependencyKey(dep dependency.Dependency) string {
	return dep.Module + "@" + dep.Version
}

func dependencyLess(a, b dependency.Dependency) bool {
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.Dir < b.Dir
}
