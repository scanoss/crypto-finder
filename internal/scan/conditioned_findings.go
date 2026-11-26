// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/paramcondition"
	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/conditioned"
)

// MaterializeConditionedFindings specializes generic rule anchors after the
// call graph resolves operation-determining selector parameters. Crypto
// semantics remain rule-owned: this function only evaluates parameterCondition
// predicates and copies the applicable rule metadata onto the original source
// anchor. Ambiguous paths produce no specialized asset.
//
// result supplies the call graph, its ecosystem and the project and
// dependency roots that locate each finding's file; report is the report
// being specialized.
func MaterializeConditionedFindings(
	report *entities.InterimReport,
	result *engine.DepScanResult,
	rulePaths []string,
) int {
	if report == nil || result == nil || result.CallGraph == nil || len(rulePaths) == 0 {
		return 0
	}
	rules := engine.LoadRuleCryptoMetadata(rulePaths)
	if len(rules) == 0 {
		return 0
	}
	graph, ecosystem := result.CallGraph, result.Ecosystem
	catalog := conditionedCatalog{rules: rules, keys: newConditionedKeyMatcher(graph, ecosystem), ecosystem: ecosystem}
	scoped := *result
	scoped.Report = report
	ctx := newExportBuildContext(&scoped)
	values := newConditionedValueEnumerator(ctx)
	existing := indexExistingFindingRules(report)
	added := 0
	for findingIndex := range report.Findings {
		added += materializeConditionedFinding(ctx, values, &report.Findings[findingIndex], graph, catalog, existing)
	}
	if added > 0 {
		log.Info().Int("count", added).Str("ecosystem", ecosystem).Msg("Materialized conditioned crypto findings from selector provenance")
	}
	return added
}

func materializeConditionedFinding(
	ctx *exportBuildContext,
	values *conditionedValueEnumerator,
	finding *entities.Finding,
	graph *callgraph.CallGraph,
	catalog conditionedCatalog,
	existing map[string]struct{},
) int {
	added := 0
	// Specializing an anchor may drop it from the finding, so walk a snapshot.
	anchors := slices.Clone(finding.CryptographicAssets)
	for i := range anchors {
		added += materializeConditionedAnchor(ctx, values, finding, graph, catalog, existing, anchors[i])
	}
	return added
}

func materializeConditionedAnchor(
	ctx *exportBuildContext,
	values *conditionedValueEnumerator,
	finding *entities.Finding,
	graph *callgraph.CallGraph,
	catalog conditionedCatalog,
	existing map[string]struct{},
	anchor entities.CryptographicAsset,
) int {
	if len(anchor.ParameterConditions) > 0 {
		return 0
	}
	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, anchor.DependencyInfo, anchor.StartLine, anchor.StartCol)
	if containingFn == nil {
		return 0
	}
	terminalNode, rules := conditionedTerminalCall(graph, containingFn, anchor, catalog)
	if terminalNode == nil {
		return 0
	}
	terminal := buildCryptoCall(ctx, graph, containingFn, terminalNode)
	anchor.TerminalStartCol = terminalNode.StartCol
	anchor.TerminalEndCol = terminalNode.EndCol
	chains, _ := buildCallChains(ctx, containingFn, terminal)
	candidates := make([][]callGraphParameter, 0, len(chains))
	unresolvedRoute := false
	for _, chain := range chains {
		if len(chain) > 0 && chain[len(chain)-1].CryptoCall != nil {
			candidates = append(candidates, chain[len(chain)-1].CryptoCall.Parameters)
		} else if len(chain) > 0 {
			unresolvedRoute = true
		}
	}
	// The chains are a bounded sample: one caller's routes can fill the budget
	// and hide every other caller's value. Specialize from all of them.
	variants, truncated, dynamic := values.terminalVariants(containingFn.ID, terminal.Parameters)
	candidates = append(candidates, variants...)
	if truncated {
		// A caller value may be missing, so this anchor's specialization and
		// the chains of what it yields are incomplete. The export reads the
		// flag; the generic anchor in the report carries it too, for the case
		// where no value survived the cut.
		anchor.ConditionedValuesIncomplete = true
		markAnchorValuesIncomplete(finding, anchor)
	}
	added, unmatched := appendConditionedAssets(finding, anchor, rules, candidates, existing)
	// The blank anchor is the only report entry for a route whose value is
	// unknown, so it stays unless the per-value assets account for every route:
	// every enumerated value resolved and matched a variant, no route is
	// dynamic, and no caller value was cut off. Another anchor on the call may
	// have appended those assets first, so this one's own count does not decide.
	selectorDynamic, inputs := dynamicSelector(rules, terminal.Parameters, dynamic)
	covered := len(candidates) > 0 && !unresolvedRoute && unmatched == 0 && !truncated && !selectorDynamic
	if covered {
		dropBlankAnchor(finding, anchor)
	} else {
		noteAlgorithmSource(finding, anchor, inputs)
	}
	return added
}

// dynamicSelector reports that some route reaches a parameter a rule's
// condition reads without a resolved value, with the sorted runtime inputs
// such routes read.
func dynamicSelector(rules []engine.RuleCryptoMetadata, params []callGraphParameter, dynamic map[int][]string) (bool, []string) {
	found := false
	var inputs []string
	args := conditionArguments(params)
	for i := range rules {
		for _, condition := range rules[i].ParameterConditions {
			if routeInputs, ok := dynamic[conditioned.ArgumentIndex(condition, args)]; ok {
				found = true
				inputs = append(inputs, routeInputs...)
			}
		}
	}
	slices.Sort(inputs)
	return found, slices.Compact(inputs)
}

// algorithmSourceMetadataKey names the runtime inputs a generic anchor's
// selector argument is read from, such as "env:SIG_ALG,argv:1".
const algorithmSourceMetadataKey = "algorithmSource"

// maxAlgorithmSources bounds how many inputs one anchor lists.
const maxAlgorithmSources = 16

// noteAlgorithmSource records inputs on the generic anchor asset of finding
// that anchor was copied from. An anchor that names an algorithm is resolved,
// whatever its other routes read, and gets none.
func noteAlgorithmSource(finding *entities.Finding, anchor entities.CryptographicAsset, inputs []string) {
	if len(inputs) == 0 || anchor.Metadata["algorithmName"] != "" || anchor.Metadata["algorithmFamily"] != "" {
		return
	}
	if len(inputs) > maxAlgorithmSources {
		log.Warn().Str("file", finding.FilePath).Int("line", anchor.StartLine).Int("inputs", len(inputs)).Int("max_inputs", maxAlgorithmSources).
			Msg("Selector argument reads more runtime inputs than an anchor lists; the rest are not reported")
		inputs = inputs[:maxAlgorithmSources]
	}
	for i := range finding.CryptographicAssets {
		asset := &finding.CryptographicAssets[i]
		if len(asset.ParameterConditions) > 0 || !sameAssetSpan(*asset, anchor) || !sameRules(asset.Rules, anchor.Rules) {
			continue
		}
		asset.Metadata = maps.Clone(asset.Metadata)
		if asset.Metadata == nil {
			asset.Metadata = make(map[string]string, 1)
		}
		asset.Metadata[algorithmSourceMetadataKey] = strings.Join(inputs, ",")
	}
}

// dropBlankAnchor removes the generic anchor asset once per-value assets stand
// for its call. A dynamic-selector anchor names no algorithm, so beside the
// specialized assets it is a blank duplicate of the same call. An anchor that
// does name an algorithm is a real finding and stays, and so does an anchor of
// another kind than the per-value assets (a private key on a key generation
// call): they do not stand for it.
func dropBlankAnchor(finding *entities.Finding, anchor entities.CryptographicAsset) {
	if anchor.Metadata["algorithmName"] != "" || anchor.Metadata["algorithmFamily"] != "" {
		return
	}
	if !slices.ContainsFunc(finding.CryptographicAssets, func(asset entities.CryptographicAsset) bool {
		return len(asset.ParameterConditions) > 0 && sameAssetSpan(asset, anchor) && sameAssetKind(anchor, asset)
	}) {
		return
	}
	finding.CryptographicAssets = slices.DeleteFunc(finding.CryptographicAssets, func(asset entities.CryptographicAsset) bool {
		return len(asset.ParameterConditions) == 0 && sameAssetSpan(asset, anchor) && sameRules(asset.Rules, anchor.Rules)
	})
}

// assetKindKeys are the metadata fields that say what kind of asset a finding
// reports, as opposed to which value it names.
var assetKindKeys = []string{"assetType", "materialType"}

// sameAssetKind reports that specialized is the same kind of asset as anchor.
// A kind field the anchor leaves empty does not tell them apart.
func sameAssetKind(anchor, specialized entities.CryptographicAsset) bool {
	for _, key := range assetKindKeys {
		if kind := anchor.Metadata[key]; kind != "" && kind != specialized.Metadata[key] {
			return false
		}
	}
	return true
}

// sameAssetSpan reports that two assets cover the same source span. A span
// without columns cannot tell two calls on one line apart, so it never matches.
func sameAssetSpan(a, b entities.CryptographicAsset) bool {
	if a.StartCol <= 0 || a.EndCol <= 0 || b.StartCol <= 0 || b.EndCol <= 0 {
		return false
	}
	return a.StartLine == b.StartLine && a.StartCol == b.StartCol && a.EndLine == b.EndLine && a.EndCol == b.EndCol
}

func sameRules(a, b []entities.RuleInfo) bool {
	return slices.EqualFunc(a, b, func(x, y entities.RuleInfo) bool { return x.ID == y.ID })
}

// markAnchorValuesIncomplete flags the generic anchor asset of finding that
// anchor was copied from.
func markAnchorValuesIncomplete(finding *entities.Finding, anchor entities.CryptographicAsset) {
	for i := range finding.CryptographicAssets {
		asset := &finding.CryptographicAssets[i]
		if asset.StartLine == anchor.StartLine && asset.StartCol == anchor.StartCol &&
			asset.EndLine == anchor.EndLine && asset.EndCol == anchor.EndCol && len(asset.ParameterConditions) == 0 {
			asset.ConditionedValuesIncomplete = true
		}
	}
}

func conditionedTerminalCall(
	graph *callgraph.CallGraph,
	containingFn *callgraph.FunctionDecl,
	anchor entities.CryptographicAsset,
	catalog conditionedCatalog,
) (*callgraph.FunctionCall, []engine.RuleCryptoMetadata) {
	lineCandidates := cryptoCallLineCandidates(containingFn, anchor.StartLine, anchor.EndLine)
	selecting := make([]*callgraph.FunctionCall, 0, len(lineCandidates))
	for _, candidate := range lineCandidates {
		if callContainsAnchorSpan(candidate, anchor) && len(catalog.rulesForCall(candidate)) > 0 {
			selecting = append(selecting, candidate)
		}
	}
	terminal := pickBestCandidate(graph, cryptoCallColumnCandidates(selecting, anchor))
	if terminal == nil {
		return nil, nil
	}
	return terminal, catalog.rulesForCall(terminal)
}

func callContainsAnchorSpan(call *callgraph.FunctionCall, anchor entities.CryptographicAsset) bool {
	if call.StartCol <= 0 || call.EndCol <= 0 || anchor.StartCol <= 0 || anchor.EndCol <= 0 {
		return true
	}
	return call.StartCol <= anchor.StartCol && call.EndCol >= anchor.EndCol
}

// appendConditionedAssets emits one asset per (rule, resolved condition) over
// every candidate argument list of the terminal call. unmatched counts the
// candidates no rule matched.
func appendConditionedAssets(
	finding *entities.Finding,
	anchor entities.CryptographicAsset,
	rules []engine.RuleCryptoMetadata,
	candidates [][]callGraphParameter,
	existing map[string]struct{},
) (added, unmatched int) {
	seen := make(map[string]struct{})
	for _, params := range candidates {
		matchedAny := false
		for i := range rules {
			matched, appended := specializeAnchor(finding, anchor, rules[i], params, seen, existing)
			matchedAny = matchedAny || matched
			if appended {
				added++
			}
		}
		if !matchedAny {
			unmatched++
		}
	}
	return added, unmatched
}

// specializeAnchor appends the asset rule yields for params. matched reports
// that the rule's conditions held, whether or not the asset was new.
func specializeAnchor(
	finding *entities.Finding,
	anchor entities.CryptographicAsset,
	rule engine.RuleCryptoMetadata,
	params []callGraphParameter,
	seen, existing map[string]struct{},
) (matched, appended bool) {
	if rule.Rule.ID == "" {
		return false, false
	}
	conditionMatch, ok := conditioned.MatchConditions(rule.ParameterConditions, conditionArguments(params), rule.CaptureNames)
	if !ok {
		return false, false
	}
	key := rule.Rule.ID
	for _, condition := range conditionMatch.Conditions {
		key += "\x00" + condition.Raw
	}
	if _, duplicate := seen[key]; duplicate {
		return true, false
	}
	seen[key] = struct{}{}
	asset := cloneConditionedAsset(anchor, rule, conditionMatch)
	assetKey := conditionedAssetKey(finding.FilePath, asset, rule.Rule.ID)
	if _, duplicate := existing[assetKey]; duplicate {
		return true, false
	}
	// The specialized asset survives. A native match of a conditioned rule can
	// state a pattern that covers several values ("~=^SHA-?(256|512)$"), so its
	// call chains are those of every value the pattern accepts. The
	// specialization's chains and verdict come from the routes that carry its
	// own value, so the native asset it duplicates is dropped. A native asset
	// whose value is not specialized here is not touched.
	dropNativeDuplicates(finding, asset, rule.Rule.ID)
	finding.CryptographicAssets = append(finding.CryptographicAssets, asset)
	existing[assetKey] = struct{}{}
	return true, true
}

// dropNativeDuplicates removes the scanner-reported assets that report the
// same rule and value as specialized at the same span. The scanner names a
// rule by the dotted path of its rule file followed by the rule's own id
// ("<path>.<id>"), or by the bare id when the rule file sits at the rules root,
// while the catalog holds the bare id. The parameter condition is not
// compared: a scanner match states the rule's pattern where a specialization
// states the value it resolved. The value is what the asset names: its
// algorithm (algorithmName, algorithmFamily) or, for related crypto material,
// the material (materialType, materialAlgorithm). An asset that names neither
// is never treated as a duplicate.
func dropNativeDuplicates(finding *entities.Finding, specialized entities.CryptographicAsset, ruleID string) {
	value := conditionedValueIdentity(specialized.Metadata)
	if value == nil {
		return
	}
	finding.CryptographicAssets = slices.DeleteFunc(finding.CryptographicAssets, func(asset entities.CryptographicAsset) bool {
		return asset.StartLine == specialized.StartLine && asset.StartCol == specialized.StartCol &&
			asset.EndLine == specialized.EndLine && asset.EndCol == specialized.EndCol &&
			slices.Equal(conditionedValueIdentity(asset.Metadata), value) &&
			slices.ContainsFunc(asset.Rules, func(rule entities.RuleInfo) bool { return sameCatalogRule(rule.ID, ruleID) })
	})
}

// conditionedValueIdentityKeys are the metadata fields that say which value an
// asset reports.
var conditionedValueIdentityKeys = []string{"algorithmName", "algorithmFamily", "materialType", "materialAlgorithm"}

// conditionedValueIdentity returns the values of conditionedValueIdentityKeys
// in metadata, or nil when it names no algorithm and no material algorithm.
func conditionedValueIdentity(metadata map[string]string) []string {
	if metadata["algorithmName"] == "" && metadata["materialAlgorithm"] == "" {
		return nil
	}
	identity := make([]string, len(conditionedValueIdentityKeys))
	for i, key := range conditionedValueIdentityKeys {
		identity[i] = metadata[key]
	}
	return identity
}

// sameCatalogRule reports that the scanner's rule id reportedID names the
// catalog rule ruleID, bare or behind its rule file's dotted path.
func sameCatalogRule(reportedID, ruleID string) bool {
	return reportedID == ruleID || strings.HasSuffix(reportedID, "."+ruleID)
}

func indexExistingFindingRules(report *entities.InterimReport) map[string]struct{} {
	existing := make(map[string]struct{})
	for findingIndex := range report.Findings {
		finding := &report.Findings[findingIndex]
		for assetIndex := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[assetIndex]
			for _, rule := range asset.Rules {
				existing[conditionedAssetKey(finding.FilePath, *asset, rule.ID)] = struct{}{}
			}
		}
	}
	return existing
}

func conditionedAssetKey(filePath string, asset entities.CryptographicAsset, ruleID string) string {
	keys := make([]string, 0, len(asset.Metadata))
	for key := range asset.Metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var metadata strings.Builder
	for _, key := range keys {
		metadata.WriteString(key)
		metadata.WriteByte('=')
		metadata.WriteString(asset.Metadata[key])
		metadata.WriteByte(';')
	}
	return filePath + "\x00" + ruleID + "\x00" + strconv.Itoa(asset.StartLine) + ":" + strconv.Itoa(asset.StartCol) + ":" + strconv.Itoa(asset.EndLine) + ":" + strconv.Itoa(asset.EndCol) + "\x00" + metadata.String()
}

// conditionedCatalog is the conditioned-rule index of one scan, keyed by the
// API symbol each rule's pattern names, with the ecosystem's rules for when a
// key names a call.
type conditionedCatalog struct {
	rules     map[string][]engine.RuleCryptoMetadata
	keys      conditionedKeyMatcher
	ecosystem string
}

func (c conditionedCatalog) rulesForCall(call *callgraph.FunctionCall) []engine.RuleCryptoMetadata {
	var rules []engine.RuleCryptoMetadata
	seen := make(map[string]struct{})
	for api, candidates := range c.rules {
		if !c.keys.matches(api, call) {
			continue
		}
		for i := range candidates {
			candidate := &candidates[i]
			if _, duplicate := seen[candidate.Rule.ID]; duplicate {
				continue
			}
			if !ruleTargetsEcosystem(candidate.Languages, c.ecosystem) {
				continue
			}
			seen[candidate.Rule.ID] = struct{}{}
			rules = append(rules, *candidate)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Rule.ID < rules[j].Rule.ID })
	return rules
}

// conditionVerdict is the three-valued answer to "does this asset's
// parameterCondition hold for this call?". conditioned.MatchConditions
// collapses refuted and unknown into a single false, which is right for SELECTING
// a conditioned variant but wrong for FILTERING reachability: an unanswerable
// predicate must not remove a finding's only evidence, while a refuted one must.
type conditionVerdict int

const (
	// conditionUnknown: no condition could be answered — every selected argument
	// is missing or its value did not resolve.
	conditionUnknown conditionVerdict = iota
	// conditionMatched: every condition was answered and all held.
	conditionMatched
	// conditionRefuted: at least one condition was answered and did NOT hold.
	// Positive evidence that this asset does not describe this call.
	conditionRefuted
)

// evaluateParameterConditions answers conditions against one call's resolved
// arguments.
//
// A condition whose argument resolved is ANSWERED, and a single answered-and-
// failing condition refutes the whole predicate regardless of how many others
// stayed unknown — that is real evidence, not absence of evidence. Only when
// nothing at all could be answered is the verdict unknown. When some conditions
// were answered and held but others stayed unknown the predicate is not fully
// established, so it reports unknown rather than matched: the caller treats
// unknown as "keep unless better evidence exists", never as "select this
// variant" (conditioned.MatchConditions remains the authority for
// selection).
func evaluateParameterConditions(
	conditions []paramcondition.Condition,
	params []callGraphParameter,
) conditionVerdict {
	answered := 0
	args := conditionArguments(params)
	for _, condition := range conditions {
		index := conditioned.ArgumentIndex(condition, args)
		if index < 0 || index >= len(params) {
			continue
		}
		actual := params[index].ResolvedValue
		if condition.Match == paramcondition.MatchType {
			actual = params[index].Type
		}
		actual = conditioned.NormalizeValue(actual)
		if actual == "" {
			continue
		}
		answered++
		if !conditioned.ConditionHolds(condition, actual) {
			return conditionRefuted
		}
	}
	if answered == len(conditions) && answered > 0 {
		return conditionMatched
	}
	return conditionUnknown
}

// conditionArguments is the call's arguments as the conditions read them.
func conditionArguments(params []callGraphParameter) []conditioned.Argument {
	args := make([]conditioned.Argument, len(params))
	for i := range params {
		args[i] = conditioned.Argument{Value: params[i].ResolvedValue, Type: params[i].Type, Name: params[i].VariableName, Keyword: params[i].Keyword}
	}
	return args
}

func cloneConditionedAsset(anchor entities.CryptographicAsset, rule engine.RuleCryptoMetadata, match conditioned.Match) entities.CryptographicAsset {
	asset := anchor
	asset.FindingID = ""
	asset.OID = ""
	asset.Rules = []entities.RuleInfo{rule.Rule}
	template := maps.Clone(rule.Metadata)
	asset.PURL = purl.Rule(template[engine.RulePURLMetadataKey])
	delete(template, engine.RulePURLMetadataKey)
	asset.Metadata = match.Metadata(template, rule.CaptureBinders)
	asset.ParameterConditions = append([]paramcondition.Condition(nil), match.Conditions...)
	asset.ConditionedValue = asset.Metadata["parameterCondition"]
	return asset
}
