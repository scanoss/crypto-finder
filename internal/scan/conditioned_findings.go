// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"maps"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
	"github.com/scanoss/crypto-finder/pkg/purl"
)

// MaterializeConditionedFindings specializes generic rule anchors after the
// call graph resolves operation-determining selector parameters. Crypto
// semantics remain rule-owned: this function only evaluates parameterCondition
// predicates and copies the applicable rule metadata onto the original source
// anchor. Ambiguous paths produce no specialized asset.
func MaterializeConditionedFindings(
	report *entities.InterimReport,
	graph *callgraph.CallGraph,
	rulePaths []string,
	ecosystem string,
) int {
	if report == nil || graph == nil || len(rulePaths) == 0 {
		return 0
	}
	rules := engine.LoadRuleCryptoMetadata(rulePaths)
	if len(rules) == 0 {
		return 0
	}
	catalog := conditionedCatalog{rules: rules, keys: newConditionedKeyMatcher(graph, ecosystem), ecosystem: ecosystem}
	ctx := newExportBuildContext(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: ecosystem})
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
	originalCount := len(finding.CryptographicAssets)
	for assetIndex := 0; assetIndex < originalCount; assetIndex++ {
		added += materializeConditionedAnchor(ctx, values, finding, graph, catalog, existing, finding.CryptographicAssets[assetIndex])
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
	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, anchor.StartLine)
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
	for _, chain := range chains {
		if len(chain) > 0 && chain[len(chain)-1].CryptoCall != nil {
			candidates = append(candidates, chain[len(chain)-1].CryptoCall.Parameters)
		}
	}
	// The chains are a bounded sample: one caller's routes can fill the budget
	// and hide every other caller's value. Specialize from all of them.
	variants, truncated := values.terminalVariants(containingFn.ID, terminal.Parameters)
	candidates = append(candidates, variants...)
	if truncated {
		// A caller value may be missing, so this anchor's specialization and
		// the chains of what it yields are incomplete. The export reads the
		// flag; the generic anchor in the report carries it too, for the case
		// where no value survived the cut.
		anchor.ConditionedValuesIncomplete = true
		markAnchorValuesIncomplete(finding, anchor)
	}
	return appendConditionedAssets(finding, anchor, rules, candidates, existing)
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
	conditioned := make([]*callgraph.FunctionCall, 0, len(lineCandidates))
	for _, candidate := range lineCandidates {
		if callContainsAnchorSpan(candidate, anchor) && len(catalog.rulesForCall(candidate)) > 0 {
			conditioned = append(conditioned, candidate)
		}
	}
	terminal := pickBestCandidate(graph, cryptoCallColumnCandidates(conditioned, anchor))
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
// every candidate argument list of the terminal call.
func appendConditionedAssets(
	finding *entities.Finding,
	anchor entities.CryptographicAsset,
	rules []engine.RuleCryptoMetadata,
	candidates [][]callGraphParameter,
	existing map[string]struct{},
) int {
	seen := make(map[string]struct{})
	added := 0
	for _, params := range candidates {
		for i := range rules {
			if appendConditionedAsset(finding, anchor, rules[i], params, seen, existing) {
				added++
			}
		}
	}
	return added
}

func appendConditionedAsset(
	finding *entities.Finding,
	anchor entities.CryptographicAsset,
	rule engine.RuleCryptoMetadata,
	params []callGraphParameter,
	seen, existing map[string]struct{},
) bool {
	if rule.Rule.ID == "" {
		return false
	}
	conditionMatch, ok := matchParameterConditionsWithCaptureNames(rule.ParameterConditions, params, rule.CaptureNames)
	if !ok {
		return false
	}
	key := rule.Rule.ID
	for _, condition := range conditionMatch.conditions {
		key += "\x00" + condition.Raw
	}
	if _, duplicate := seen[key]; duplicate {
		return false
	}
	seen[key] = struct{}{}
	asset := cloneConditionedAsset(anchor, rule, conditionMatch)
	assetKey := conditionedAssetKey(finding.FilePath, asset, rule.Rule.ID)
	if _, duplicate := existing[assetKey]; duplicate {
		return false
	}
	finding.CryptographicAssets = append(finding.CryptographicAssets, asset)
	existing[assetKey] = struct{}{}
	return true
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

type parameterConditionMatch struct {
	captures   map[string]string
	conditions []paramcondition.Condition
}

// conditionVerdict is the three-valued answer to "does this asset's
// parameterCondition hold for this call?". matchParameterConditionsWithCaptureNames
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
// variant" (matchParameterConditionsWithCaptureNames remains the authority for
// selection).
func evaluateParameterConditions(
	conditions []paramcondition.Condition,
	params []callGraphParameter,
) conditionVerdict {
	answered := 0
	for _, condition := range conditions {
		index := conditionParameterIndex(condition, params)
		if index < 0 || index >= len(params) {
			continue
		}
		actual := params[index].ResolvedValue
		if condition.Match == paramcondition.MatchType {
			actual = params[index].Type
		}
		actual = normalizeSelectorValue(actual)
		if actual == "" {
			continue
		}
		answered++
		if !matchParameterCondition(condition, actual, map[string]string{}, nil) {
			return conditionRefuted
		}
	}
	if answered == len(conditions) && answered > 0 {
		return conditionMatched
	}
	return conditionUnknown
}

func matchParameterConditionsWithCaptureNames(
	conditions []paramcondition.Condition,
	params []callGraphParameter,
	captureNames []string,
) (parameterConditionMatch, bool) {
	result := parameterConditionMatch{captures: make(map[string]string)}
	for _, condition := range conditions {
		index := conditionParameterIndex(condition, params)
		if index < 0 || index >= len(params) {
			return parameterConditionMatch{}, false
		}
		actual := params[index].ResolvedValue
		if condition.Match == paramcondition.MatchType {
			actual = params[index].Type
		}
		actual = normalizeSelectorValue(actual)
		if actual == "" {
			return parameterConditionMatch{}, false
		}
		if !matchParameterCondition(condition, actual, result.captures, captureNames) {
			return parameterConditionMatch{}, false
		}
		result.conditions = append(result.conditions, exactResolvedCondition(condition, actual))
	}
	return result, true
}

func conditionParameterIndex(condition paramcondition.Condition, params []callGraphParameter) int {
	if condition.Selector.Index != nil {
		return *condition.Selector.Index
	}
	if condition.Selector.Name == nil {
		return -1
	}
	for i := range params {
		if params[i].VariableName == *condition.Selector.Name {
			return i
		}
	}
	return -1
}

func matchParameterCondition(condition paramcondition.Condition, actual string, captures map[string]string, captureNames []string) bool {
	if condition.Operator == paramcondition.OpExact {
		return actual == normalizeSelectorValue(condition.Value)
	}
	if condition.Operator != paramcondition.OpRegex {
		return false
	}
	re, err := regexp.Compile(condition.Value)
	if err != nil {
		return false
	}
	match := re.FindStringSubmatch(actual)
	if match == nil {
		return false
	}
	for i := 1; i < len(match); i++ {
		if match[i] == "" {
			continue
		}
		captures[strconv.Itoa(i)] = match[i]
		name := re.SubexpNames()[i]
		if name == "" && i-1 < len(captureNames) {
			name = captureNames[i-1]
		}
		if name != "" {
			captures[name] = match[i]
		}
	}
	return true
}

func exactResolvedCondition(condition paramcondition.Condition, actual string) paramcondition.Condition {
	resolved := condition
	resolved.Operator = paramcondition.OpExact
	resolved.Value = actual
	selector := ""
	if condition.Selector.Index != nil {
		selector = strconv.Itoa(*condition.Selector.Index)
	} else if condition.Selector.Name != nil {
		selector = *condition.Selector.Name
	}
	typeSuffix := ""
	if condition.Match == paramcondition.MatchType {
		typeSuffix = ":type"
	}
	resolved.Raw = "param[" + selector + "]" + typeSuffix + "==" + actual
	return resolved
}

func cloneConditionedAsset(anchor entities.CryptographicAsset, rule engine.RuleCryptoMetadata, match parameterConditionMatch) entities.CryptographicAsset {
	asset := anchor
	asset.FindingID = ""
	asset.OID = ""
	asset.Rules = []entities.RuleInfo{rule.Rule}
	asset.Metadata = maps.Clone(rule.Metadata)
	asset.PURL = purl.Rule(asset.Metadata[engine.RulePURLMetadataKey])
	delete(asset.Metadata, engine.RulePURLMetadataKey)
	for key, value := range asset.Metadata {
		for name, capture := range match.captures {
			value = strings.ReplaceAll(value, "$"+name, capture)
		}
		if strings.Contains(value, "$") {
			delete(asset.Metadata, key)
			continue
		}
		asset.Metadata[key] = value
	}
	if asset.Metadata["cryptoFunction"] == "" && asset.Metadata["operation"] != "" {
		asset.Metadata["cryptoFunction"] = asset.Metadata["operation"]
	}
	asset.ParameterConditions = append([]paramcondition.Condition(nil), match.conditions...)
	conditionRaws := make([]string, len(asset.ParameterConditions))
	for i := range asset.ParameterConditions {
		conditionRaws[i] = asset.ParameterConditions[i].Raw
	}
	asset.Metadata["parameterCondition"] = strings.Join(conditionRaws, ",")
	return asset
}
