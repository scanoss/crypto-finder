// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cli_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

const acceptanceCondition = `param[0]==true,param[algorithm]~=^AES,param[1|key]:type==key,param[2]:type~=^bytes?$`

type acceptanceCase struct {
	name, ecosystem, fixture, source, provider string
	pinFile                                    string
	pinTexts                                   []string
	matches                                    []acceptanceMatch
}

type acceptanceMatch struct {
	needle, ruleID, api  string
	wantSymbol           string
	wantSignature        string
	staticProvider       bool
	runtimeProvider      bool
	requiresSupport      bool
	supportingCategories []string
	supportingSignatures map[string]string
}

type acceptanceResult struct {
	report   entities.InterimReport
	fragment graphfrag.GraphFragmentExport
	live     graphfrag.CallgraphExport
	stitched graphfrag.CallgraphExport
	stitch   *graphfrag.Result
}

func TestDependencyIntelligenceExportContract(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI acceptance test")
	}
	t.Parallel()

	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	cases := []acceptanceCase{
		{
			name: "java", ecosystem: "java", fixture: "dependency_intelligence_java",
			source: "src/main/java/example/Acceptance.java", provider: "BC",
			pinFile: "pom.xml", pinTexts: []string{"<version>1.78.1</version>", "<version>1.13.0</version>", "<version>4.0.3</version>"},
			matches: []acceptanceMatch{
				{
					needle: "new JcePGPDataEncryptorBuilder(alg)", ruleID: "java.acceptance.pgp-builder",
					api:           "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.setSecureRandom",
					wantSymbol:    "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>",
					wantSignature: "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>(int): JcePGPDataEncryptorBuilder",
				},
				{needle: "new KeyParameter(key)", ruleID: "java.acceptance.key-parameter", api: "org.bouncycastle.crypto.params.KeyParameter.<init>", requiresSupport: true, supportingCategories: []string{"factory", "output"}},
				{
					needle: "new KeyParameter(data)", ruleID: "java.acceptance.nested-key-parameter",
					api:           "org.bouncycastle.crypto.modes.GCMBlockCipher.init",
					wantSymbol:    "org.bouncycastle.crypto.params.KeyParameter.<init>",
					wantSignature: "org.bouncycastle.crypto.params.KeyParameter.<init>(byte[]): KeyParameter",
				},
				{needle: "params.getKey()", ruleID: "java.acceptance.key-output", api: "org.bouncycastle.crypto.params.KeyParameter.getKey", requiresSupport: true, supportingCategories: []string{"factory", "output"}},
				{needle: "gcm.getOutputSize(16)", ruleID: "java.acceptance.gcm", api: "org.bouncycastle.crypto.modes.GCMBlockCipher.getOutputSize", requiresSupport: true, supportingCategories: []string{"config"}},
				{needle: "new AESEngine()", ruleID: "java.acceptance.engine", api: "org.bouncycastle.crypto.engines.AESEngine.<init>", requiresSupport: true, supportingCategories: []string{"operation"}},
				{
					needle: "KeysetHandle.generateNew(template)", ruleID: "java.acceptance.tink-aead",
					api: "com.google.crypto.tink.KeysetHandle.generateNew", requiresSupport: true,
					supportingCategories: []string{"operation"},
					supportingSignatures: map[string]string{
						"com.google.crypto.tink.Aead.encrypt": "com.google.crypto.tink.Aead.encrypt(byte[], byte[]): byte[]",
						"com.google.crypto.tink.Aead.decrypt": "com.google.crypto.tink.Aead.decrypt(byte[], byte[]): byte[]",
					},
				},
				{
					needle: "XMLCipher.getInstance(XMLCipher.AES_256_GCM)", ruleID: "java.acceptance.xml-cipher",
					api: "org.apache.xml.security.encryption.XMLCipher.getInstance", requiresSupport: true,
					supportingCategories: []string{"config", "operation"},
					supportingSignatures: map[string]string{
						"org.apache.xml.security.encryption.XMLCipher.init":    "org.apache.xml.security.encryption.XMLCipher.init(int, java.security.Key): void",
						"org.apache.xml.security.encryption.XMLCipher.doFinal": "org.apache.xml.security.encryption.XMLCipher.doFinal(org.w3c.dom.Document, org.w3c.dom.Element): org.w3c.dom.Document",
					},
				},
				{needle: `Cipher.getInstance("AES/GCM/NoPadding", "BC")`, ruleID: "java.acceptance.static-provider", api: "javax.crypto.Cipher.getInstance", staticProvider: true},
				{needle: `Cipher.getInstance("AES/GCM/NoPadding", runtimeProvider)`, ruleID: "java.acceptance.runtime-provider", api: "javax.crypto.Cipher.getInstance", runtimeProvider: true},
			},
		},
		{
			name: "python", ecosystem: "python", fixture: "dependency_intelligence_python",
			source: "acceptance.py", provider: "pycryptodomex",
			pinFile: "requirements.txt", pinTexts: []string{"pycryptodomex==3.20.0"},
			matches: []acceptanceMatch{
				{needle: "AES.new(key, AES.MODE_GCM)", ruleID: "python.acceptance.aes-new", api: "Cryptodome.Cipher.AES.new", requiresSupport: true},
				{needle: "cipher.encrypt(data)", ruleID: "python.acceptance.aes-encrypt", api: "Cryptodome.Cipher.AES.AESCipher.encrypt", requiresSupport: true, supportingCategories: []string{"factory"}},
				{needle: `provider_probe("pycryptodomex")`, ruleID: "python.acceptance.static-provider", api: "dependency_intelligence_python.provider_probe", staticProvider: true},
				{needle: "provider_probe(runtime_provider)", ruleID: "python.acceptance.runtime-provider", api: "dependency_intelligence_python.provider_probe", runtimeProvider: true},
			},
		},
	}

	results := make(map[string]acceptanceResult, len(cases))
	var resultsMu sync.Mutex
	t.Cleanup(func() {
		resultsMu.Lock()
		defer resultsMu.Unlock()
		require.Contains(t, results, "java")
		require.Contains(t, results, "python")
		javaResult, pythonResult := results["java"], results["python"]
		assert.Equal(t, paritySemantics(t, &javaResult), paritySemantics(t, &pythonResult),
			"equivalent fixtures must preserve the same external field semantics")
	})
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runAcceptanceCase(t, root, binary, tt)
			resultsMu.Lock()
			results[tt.name] = result
			resultsMu.Unlock()
			assertFindingContract(t, tt, result.report)
			assertFragmentContract(t, tt, &result.fragment, &result.live)
			assertForwardContract(t, tt, &result)
		})
	}
}

type externalParitySemantics struct {
	Conditions            string
	StaticProvider        bool
	UnresolvedProvider    bool
	ForwardMaxDepth       int
	ForwardTruncated      bool
	ParameterIndexes      []int
	ArgumentExpressions   []string
	ResolvedValues        []string
	ParameterTypesAligned bool
	HasFactorySupport     bool
	SupportingRefsResolve bool
}

func paritySemantics(t *testing.T, result *acceptanceResult) externalParitySemantics {
	t.Helper()
	conditions, err := json.Marshal(firstAsset(t, result.report).ParameterConditions)
	require.NoError(t, err)
	semantics := externalParitySemantics{Conditions: string(conditions), SupportingRefsResolve: true}
	assets := allAssets(result.report)
	for i := range assets {
		asset := &assets[i]
		if asset.Metadata["provider"] != "" {
			semantics.StaticProvider = true
		}
		if _, ok := asset.Metadata["provider"]; !ok {
			semantics.UnresolvedProvider = true
		}
	}
	supporting := make(map[string]bool, len(result.fragment.SupportingCalls))
	for i := range result.fragment.SupportingCalls {
		call := &result.fragment.SupportingCalls[i]
		supporting[call.SupportingID] = true
		semantics.HasFactorySupport = semantics.HasFactorySupport || call.Category == "factory"
	}
	for i := range result.fragment.CryptoAnnotations {
		for _, id := range result.fragment.CryptoAnnotations[i].SupportingCallIDs {
			semantics.SupportingRefsResolve = semantics.SupportingRefsResolve && supporting[id]
		}
	}
	for i := range result.stitched.FindingGraphs {
		forward := result.stitched.FindingGraphs[i].ForwardCalls
		if forward == nil || !strings.HasSuffix(forward.Anchor.FunctionName, ".run") {
			continue
		}
		semantics.ForwardMaxDepth = forward.MaxDepth
		semantics.ForwardTruncated = forward.Truncated
		for j := range forward.Edges {
			entry := forward.Edges[j].EntryCall
			if entry == nil || !strings.HasSuffix(entry.FunctionName, ".helper") {
				continue
			}
			semantics.ParameterTypesAligned = len(entry.ParameterTypes) == len(entry.Parameters)
			for k := range entry.Parameters {
				parameter := &entry.Parameters[k]
				semantics.ParameterIndexes = append(semantics.ParameterIndexes, parameter.ParameterIndex)
				semantics.ArgumentExpressions = append(semantics.ArgumentExpressions, parameter.ArgumentExpression)
				semantics.ResolvedValues = append(semantics.ResolvedValues, parameter.ResolvedValue)
			}
		}
		break
	}
	return semantics
}

func runAcceptanceCase(t *testing.T, root, binary string, tc acceptanceCase) acceptanceResult {
	t.Helper()
	target := filepath.Join(root, "testdata", "projects", tc.fixture)
	assertDependencyPin(t, target, tc)
	tmp := t.TempDir()
	fakeOutput := filepath.Join(tmp, "opengrep.json")
	rules := filepath.Join(tmp, "rules.yaml")
	findings := filepath.Join(tmp, "findings.json")
	callgraph := filepath.Join(tmp, "callgraph.json")
	fragmentPath := filepath.Join(tmp, "fragment.json")
	writeFakeScanner(t, tmp)
	writeRules(t, rules, tc)
	writeScannerOutput(t, fakeOutput, target, tc)

	cmd := exec.CommandContext(t.Context(), binary, "--error-format", "json", "scan", "--scanner", "opengrep", "--no-remote-rules",
		"--no-default-exclusions", "--include-tests", "--languages", tc.ecosystem, "--rules", rules,
		"--output", findings, "--export-callgraph", callgraph, "--export-graph-fragment", fragmentPath, target)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(tmp, "home"), "FAKE_OPENGREP_OUTPUT="+fakeOutput,
		"PATH="+tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "crypto-finder scan output:\n%s", output)

	var result acceptanceResult
	readJSON(t, findings, &result.report)
	readJSON(t, fragmentPath, &result.fragment)
	var live graphfrag.CallgraphExport
	readJSON(t, callgraph, &live)
	require.GreaterOrEqual(t, len(live.FindingGraphs), len(tc.matches), "live finding_graphs")
	result.live = live

	key := graphfrag.ComponentKey{Purl: "pkg:" + tc.ecosystem + "/acceptance", Version: "1.0.0"}
	fragment := result.fragment.ToFragment(key)
	stitched, err := graphfrag.StitchWithOptions(key, graphfrag.DependencyGraph{}, map[graphfrag.ComponentKey]graphfrag.Fragment{key: fragment}, graphfrag.StitchOptions{ForwardClosure: true, MaxForwardDepth: 1})
	require.NoError(t, err, "StitchWithOptions")
	result.stitch = stitched
	result.stitched = stitched.ToCallgraphExport(key, graphfrag.ScanMeta{RootModule: tc.fixture, Ecosystem: tc.ecosystem})

	envelope := graphfrag.ToFindingsEnvelope(key, graphfrag.DependencyGraph{}, map[graphfrag.ComponentKey]graphfrag.Fragment{key: fragment}, graphfrag.ScanMeta{Ecosystem: tc.ecosystem})
	require.NotEmpty(t, envelope.Findings, "graph-fragment findings")
	require.NotEmpty(t, envelope.Findings[0].CryptographicAssets, "graph-fragment cryptographic assets")
	assertNormalizedConditions(t, envelope.Findings[0].CryptographicAssets[0].ParameterConditions)
	return result
}

func assertFindingContract(t *testing.T, tc acceptanceCase, report entities.InterimReport) {
	t.Helper()
	require.NotEmpty(t, report.Findings, "findings report")
	assets := allAssets(report)
	wanted := make(map[string]acceptanceMatch, len(tc.matches))
	for i := range tc.matches {
		wanted[tc.matches[i].ruleID] = tc.matches[i]
	}
	static, unresolved := false, false
	seen := 0
	for i := range assets {
		asset := &assets[i]
		if len(asset.Rules) == 0 {
			continue
		}
		match, ok := wanted[asset.Rules[0].ID]
		if !ok {
			continue
		}
		seen++
		assertNormalizedConditions(t, asset.ParameterConditions)
		wantID := findingID(report.Findings[0].FilePath, asset.StartLine, asset.Rules[0].ID)
		assert.Equal(t, wantID, asset.FindingID, "unchanged finding_id")
		if match.staticProvider && asset.Metadata["provider"] == tc.provider {
			static = true
		}
		if match.runtimeProvider {
			_, resolved := asset.Metadata["provider"]
			unresolved = !resolved
		}
	}
	assert.Equal(t, len(tc.matches), seen, "scanner assets: %#v", assets)
	assert.True(t, static, "explicit static provider evidence must be preserved")
	assert.True(t, unresolved, "runtime-selected provider must remain unresolved")
}

func assertNormalizedConditions(t *testing.T, conditions []paramcondition.Condition) {
	t.Helper()
	require.Len(t, conditions, 4, "positional/named/combined value/regex/type conjunction")
	assert.Equal(t, "param[0]==true", conditions[0].Raw)
	require.NotNil(t, conditions[0].Selector.Index)
	assert.Equal(t, 0, *conditions[0].Selector.Index)
	assert.Nil(t, conditions[0].Selector.Name)
	assert.Equal(t, paramcondition.Operator("=="), conditions[0].Operator)
	assert.Equal(t, paramcondition.Match("value"), conditions[0].Match)
	assert.Equal(t, "true", conditions[0].Value)

	assert.Equal(t, "param[algorithm]~=^AES", conditions[1].Raw)
	assert.Nil(t, conditions[1].Selector.Index)
	require.NotNil(t, conditions[1].Selector.Name)
	assert.Equal(t, "algorithm", *conditions[1].Selector.Name)
	assert.Equal(t, paramcondition.Operator("~="), conditions[1].Operator)
	assert.Equal(t, paramcondition.Match("value"), conditions[1].Match)
	assert.Equal(t, "^AES", conditions[1].Value)

	assert.Equal(t, "param[1|key]:type==key", conditions[2].Raw)
	require.NotNil(t, conditions[2].Selector.Index)
	require.NotNil(t, conditions[2].Selector.Name)
	assert.Equal(t, 1, *conditions[2].Selector.Index)
	assert.Equal(t, "key", *conditions[2].Selector.Name)
	assert.Equal(t, paramcondition.Operator("=="), conditions[2].Operator)
	assert.Equal(t, paramcondition.Match("type"), conditions[2].Match)
	assert.Equal(t, "key", conditions[2].Value)

	assert.Equal(t, "param[2]:type~=^bytes?$", conditions[3].Raw)
	require.NotNil(t, conditions[3].Selector.Index)
	assert.Equal(t, 2, *conditions[3].Selector.Index)
	assert.Nil(t, conditions[3].Selector.Name)
	assert.Equal(t, paramcondition.Operator("~="), conditions[3].Operator)
	assert.Equal(t, paramcondition.Match("type"), conditions[3].Match)
	assert.Equal(t, "^bytes?$", conditions[3].Value)
}

func assertFragmentContract(t *testing.T, tc acceptanceCase, payload *graphfrag.GraphFragmentExport, live *graphfrag.CallgraphExport) {
	t.Helper()
	require.GreaterOrEqual(t, len(payload.CryptoAnnotations), len(tc.matches), "crypto annotations")
	linked := make(map[string]bool)
	for i := range payload.CryptoAnnotations {
		op := &payload.CryptoAnnotations[i]
		for _, id := range op.SupportingCallIDs {
			linked[id] = true
		}
	}
	categories := make(map[string]bool)
	supportByID := make(map[string]*graphfrag.GraphFragmentSupporting, len(payload.SupportingCalls))
	for i := range payload.SupportingCalls {
		call := &payload.SupportingCalls[i]
		supportByID[call.SupportingID] = call
		categories[call.Category] = true
		assert.Truef(t, linked[call.SupportingID], "supporting call %q (%s) is not linked to a finding", call.SupportingID, call.Category)
	}
	expected := make(map[string]acceptanceMatch, len(tc.matches))
	for i := range tc.matches {
		expected[tc.matches[i].ruleID] = tc.matches[i]
	}
	seen := 0
	for i := range payload.CryptoAnnotations {
		op := &payload.CryptoAnnotations[i]
		match, ok := expected[op.RuleID]
		if !ok {
			continue
		}
		seen++
		if match.requiresSupport {
			require.NotEmptyf(t, op.SupportingCallIDs, "finding %s must link its applicable supporting calls", op.RuleID)
		}
		if match.wantSymbol != "" {
			require.NotNil(t, op.MatchedOperation, "finding %s matched operation", op.RuleID)
			assert.Equal(t, match.wantSymbol, op.MatchedOperation.Symbol, "finding %s matched invocation", op.RuleID)
			require.NotNil(t, op.CryptoCall, "finding %s crypto call", op.RuleID)
			assert.Equal(t, match.wantSymbol, op.CryptoCall.FunctionName, "finding %s crypto call identity", op.RuleID)
			assert.Equal(t, match.wantSignature, op.CryptoCall.CanonicalSignature, "finding %s canonical signature", op.RuleID)
		}
		findingCategories := make(map[string]bool)
		for _, id := range op.SupportingCallIDs {
			call, exists := supportByID[id]
			require.Truef(t, exists, "finding %s references missing supporting call %s", op.RuleID, id)
			findingCategories[call.Category] = true
		}
		for _, category := range match.supportingCategories {
			assert.Truef(t, findingCategories[category], "finding %s missing applicable %s support: %#v", op.RuleID, category, op.SupportingCallIDs)
		}
		for functionName, signature := range match.supportingSignatures {
			found := false
			for _, id := range op.SupportingCallIDs {
				call := supportByID[id]
				if call.SupportingCall != nil && call.SupportingCall.FunctionName == functionName {
					found = true
					assert.Equal(t, signature, call.SupportingCall.CanonicalSignature, "finding %s supporting call %s", op.RuleID, functionName)
				}
			}
			assert.Truef(t, found, "finding %s missing supporting call %s", op.RuleID, functionName)
			externalFound := false
			for i := range payload.ExternalCalls {
				call := &payload.ExternalCalls[i]
				if call.TargetFunctionName == functionName {
					externalFound = true
					assert.Equal(t, signature, call.TargetCanonicalSignature, "external call %s", functionName)
				}
			}
			assert.Truef(t, externalFound, "missing external call %s", functionName)
		}
	}
	assert.Equal(t, len(tc.matches), seen, "expected crypto annotations by rule")
	switch tc.ecosystem {
	case "java":
		for _, category := range []string{"factory", "config", "operation", "output"} {
			assert.Truef(t, categories[category], "missing %s supporting call: %#v", category, payload.SupportingCalls)
		}
		assertJavaCallableIdentities(t, payload)
		assertNoFabricatedLifecycleEdges(t, payload)
	case "python":
		assert.True(t, categories["factory"], "python lifecycle categories = %#v, want factory", categories)
		assertPythonCallableIdentities(t, payload)
	}

	fragmentRole := false
	for i := range payload.CryptoEntryPoints {
		entry := &payload.CryptoEntryPoints[i]
		assert.NotEqual(t, "operation", entry.MethodRole, "operation supporting call duplicated as graph-fragment entry point: %#v", entry)
		for _, role := range entry.ParameterRoles {
			if role.Index == 0 && role.Role == "metadata-contributing" && role.Contributes != nil &&
				role.Contributes.Property == "keySize" && role.Contributes.Derivation == "argument_bit_length" {
				fragmentRole = true
			}
		}
	}
	liveRole := false
	for i := range live.CryptoEntryPoints {
		entry := &live.CryptoEntryPoints[i]
		assert.NotEqual(t, "operation", entry.MethodRole, "operation supporting call duplicated as live entry point: %#v", entry)
		for _, role := range entry.ParameterRoles {
			if role.Index == 0 && role.Role == "metadata-contributing" && role.Contributes != nil &&
				role.Contributes.Property == "keySize" && role.Contributes.Derivation == "argument_bit_length" {
				liveRole = true
			}
		}
	}
	if tc.ecosystem == "java" {
		assert.True(t, fragmentRole, "KeyParameter parameter role/derivation missing from fragment")
		assert.True(t, liveRole, "KeyParameter parameter role/derivation missing from live export")
	}
}

func assertForwardContract(t *testing.T, tc acceptanceCase, result *acceptanceResult) {
	t.Helper()
	var forward *graphfrag.ExportForwardClosure
	for i := range result.stitched.FindingGraphs {
		finding := &result.stitched.FindingGraphs[i]
		if finding.ForwardCalls != nil && strings.HasSuffix(finding.ForwardCalls.Anchor.FunctionName, ".run") {
			forward = finding.ForwardCalls
			break
		}
	}
	require.NotNil(t, forward, "run finding forward closure")
	assert.True(t, forward.Truncated, "forward closure must expose depth truncation")
	assert.Equal(t, 1, forward.MaxDepth, "forward closure depth budget")
	require.NotEmpty(t, forward.Edges, "real forward edges")

	var helper *graphfrag.ExportForwardEdge
	var overloads []*graphfrag.ExportForwardEdge
	for i := range forward.Edges {
		edge := &forward.Edges[i]
		require.NotNil(t, edge.EntryCall, "forward edge %s -> %s entry_call", edge.From, edge.To)
		if strings.HasSuffix(edge.EntryCall.FunctionName, ".helper") {
			helper = edge
		}
		if tc.ecosystem == "java" && strings.HasSuffix(edge.EntryCall.FunctionName, ".AESEngine.processBlock") {
			overloads = append(overloads, edge)
		}
	}
	require.NotNil(t, helper, "real helper implementation edge")
	parameters := helper.EntryCall.Parameters
	require.Len(t, parameters, 3, "helper forward-call parameters")
	assert.Equal(t, []int{0, 1, 2}, []int{parameters[0].ParameterIndex, parameters[1].ParameterIndex, parameters[2].ParameterIndex})
	assert.Equal(t, []string{"data", "key", "16"}, []string{parameters[0].ArgumentExpression, parameters[1].ArgumentExpression, parameters[2].ArgumentExpression})
	assert.Equal(t, "16", parameters[2].ResolvedValue)
	assert.Equal(t, helper.EntryCall.ParameterTypes[0], parameters[0].Type, "argument type aligns with callee parameter index 0")
	assert.Equal(t, helper.EntryCall.ParameterTypes[2], parameters[2].Type, "argument type aligns with callee parameter index 2")

	switch tc.ecosystem {
	case "java":
		assert.Equal(t, "example.Acceptance.helper(byte[], byte[], int): byte[]", helper.EntryCall.CanonicalSignature)
		assert.Equal(t, "byte[]", helper.EntryCall.ReturnType)
		assert.Equal(t, []string{"byte[]", "byte[]", "int"}, helper.EntryCall.ParameterTypes)
		assert.NotEmpty(t, parameters[0].SourceNodes, "Java parameter provenance")
		require.Len(t, overloads, 2, "ambiguous same-call-site overload candidates")
		assert.Equal(t, overloads[0].EntryCall.Line, overloads[1].EntryCall.Line, "overload candidates share one call site")
		assert.ElementsMatch(t,
			[]string{
				"org.bouncycastle.crypto.engines.AESEngine.processBlock(String, int, String, int): int",
				"org.bouncycastle.crypto.engines.AESEngine.processBlock(byte[], int, byte[], int): int",
			},
			[]string{overloads[0].EntryCall.CanonicalSignature, overloads[1].EntryCall.CanonicalSignature},
			"ambiguity remains candidate identities with parameter-type evidence",
		)
		assertSuppressedAmbiguity(t, result.stitch)
		assertSerializedAmbiguity(t, result.stitched)
	case "python":
		assert.Equal(t, "dependency_intelligence_python.helper(bytes, bytes, int): bytes", helper.EntryCall.CanonicalSignature)
		assert.Equal(t, "bytes", helper.EntryCall.ReturnType)
		assert.Equal(t, []string{"bytes", "bytes", "int"}, helper.EntryCall.ParameterTypes)
	}
}

func assertSerializedAmbiguity(t *testing.T, export graphfrag.CallgraphExport) {
	t.Helper()
	raw, err := json.Marshal(export)
	require.NoError(t, err)
	var payload struct {
		FindingGraphs []struct {
			ForwardCalls *struct {
				Anchor struct {
					FunctionName string `json:"function_name"`
				} `json:"anchor"`
				Truncated      bool `json:"truncated"`
				AmbiguousCalls []struct {
					GroupID      string `json:"group_id"`
					Reason       string `json:"reason"`
					Completeness string `json:"completeness"`
					CallSite     struct {
						MethodName string `json:"method_name"`
						Line       int    `json:"line"`
						StartCol   int    `json:"start_col"`
						EndCol     int    `json:"end_col"`
					} `json:"call_site"`
					Candidates []struct {
						CandidateID        string   `json:"candidate_id"`
						CanonicalSignature string   `json:"canonical_signature"`
						ParameterTypes     []string `json:"parameter_types"`
						EntryCall          any      `json:"entry_call"`
					} `json:"candidates"`
				} `json:"ambiguous_calls"`
			} `json:"forward_calls"`
		} `json:"finding_graphs"`
	}
	require.NoError(t, json.Unmarshal(raw, &payload), "serialized callgraph JSON")
	for _, finding := range payload.FindingGraphs {
		if finding.ForwardCalls == nil || !strings.HasSuffix(finding.ForwardCalls.Anchor.FunctionName, ".run") {
			continue
		}
		for _, group := range finding.ForwardCalls.AmbiguousCalls {
			if group.CallSite.MethodName != "apply" {
				continue
			}
			assert.NotEmpty(t, group.GroupID)
			assert.Equal(t, graphfrag.SuppressReasonAmbiguousDispatch, group.Reason)
			assert.Equal(t, graphfrag.AmbiguityComplete, group.Completeness)
			assert.NotZero(t, group.CallSite.Line)
			assert.NotZero(t, group.CallSite.StartCol)
			assert.Greater(t, group.CallSite.EndCol, group.CallSite.StartCol)
			require.Len(t, group.Candidates, 2)
			for _, candidate := range group.Candidates {
				assert.NotEmpty(t, candidate.CandidateID)
				assert.NotEmpty(t, candidate.CanonicalSignature)
				assert.Equal(t, []string{"byte[]"}, candidate.ParameterTypes)
				assert.NotNil(t, candidate.EntryCall)
			}
			return
		}
	}
	assert.Fail(t, "serialized JSON lacks ambiguous apply dispatch", "payload: %s", raw)
}

func assertSuppressedAmbiguity(t *testing.T, result *graphfrag.Result) {
	t.Helper()
	require.NotNil(t, result)
	for i := range result.Suppressed {
		suppressed := &result.Suppressed[i]
		if suppressed.Reason == graphfrag.SuppressReasonAmbiguousDispatch {
			assert.GreaterOrEqual(t, len(suppressed.Candidates), 2, "ambiguous dispatch candidates")
			return
		}
	}
	assert.Fail(t, "missing explicit interface-dispatch ambiguity state", "suppressed edges: %#v", result.Suppressed)
}

func assertNoFabricatedLifecycleEdges(t *testing.T, payload *graphfrag.GraphFragmentExport) {
	t.Helper()
	supporting := make(map[string]bool, len(payload.SupportingCalls))
	for i := range payload.SupportingCalls {
		supporting[payload.SupportingCalls[i].FunctionKey] = true
	}
	for i := range payload.InternalEdges {
		edge := &payload.InternalEdges[i]
		assert.Falsef(t, supporting[edge.CallerKey] && supporting[edge.CalleeKey],
			"fabricated lifecycle edge %s -> %s", edge.CallerKey, edge.CalleeKey)
	}
}

func assertJavaCallableIdentities(t *testing.T, payload *graphfrag.GraphFragmentExport) {
	t.Helper()
	var signatures []string
	for i := range payload.Functions {
		fn := &payload.Functions[i]
		if strings.Contains(fn.FunctionName, "processBlock") {
			signatures = append(signatures, fn.CanonicalSignature)
		}
	}
	assert.ElementsMatch(t, []string{
		"org.bouncycastle.crypto.BlockCipher.processBlock(byte[], int, byte[], int): int",
		"org.bouncycastle.crypto.engines.AESEngine.processBlock(String, int, String, int): int",
		"org.bouncycastle.crypto.engines.AESEngine.processBlock(byte[], int, byte[], int): int",
	}, signatures, "canonical signatures include declaring type, parameter types, and return type")
}

func assertPythonCallableIdentities(t *testing.T, payload *graphfrag.GraphFragmentExport) {
	t.Helper()
	var signatures []string
	for i := range payload.Functions {
		fn := &payload.Functions[i]
		if strings.HasSuffix(fn.FunctionName, "BaseRunner.run") || strings.HasSuffix(fn.FunctionName, "Runner.run") {
			signatures = append(signatures, fn.CanonicalSignature)
		}
	}
	assert.ElementsMatch(t, []string{
		"dependency_intelligence_python.BaseRunner.run(?, bytes, bytes, str): bytes",
		"dependency_intelligence_python.Runner.run(?, bytes, bytes, str): bytes",
	}, signatures, "base/override identities include declaring type, parameter types, and return type")
}

func writeScannerOutput(t *testing.T, path, target string, tc acceptanceCase) {
	t.Helper()
	sourcePath := filepath.Join(target, filepath.FromSlash(tc.source))
	source, err := os.ReadFile(sourcePath)
	require.NoError(t, err)
	results := make([]map[string]any, 0, len(tc.matches))
	for _, match := range tc.matches {
		line, col := location(string(source), match.needle)
		require.NotZerof(t, line, "fixture %s does not contain %q", sourcePath, match.needle)
		crypto := map[string]any{"assetType": "algorithm", "algorithmFamily": "AES", "algorithmPrimitive": "block-cipher", "api": match.api, "parameterCondition": acceptanceCondition}
		metavars := map[string]any{}
		if match.staticProvider || match.runtimeProvider {
			crypto["provider"] = "$PROVIDER"
		}
		if match.staticProvider {
			require.Contains(t, match.needle, `"`+tc.provider+`"`, "static provider must be literal evidence in the matched expression")
			metavars["$PROVIDER"] = map[string]any{"abstract_content": tc.provider}
		}
		if match.runtimeProvider {
			require.Contains(t, strings.ToLower(match.needle), "runtime", "runtime provider must be selected in the matched expression")
		}
		results = append(results, map[string]any{
			"check_id": match.ruleID, "path": sourcePath,
			"start": map[string]int{"line": line, "col": col}, "end": map[string]int{"line": line, "col": col + len(match.needle)},
			"extra": map[string]any{
				"message": "dependency intelligence acceptance", "severity": "INFO", "lines": match.needle,
				"metadata": map[string]any{"crypto": crypto}, "metavars": metavars,
			},
		})
	}
	writeJSON(t, path, map[string]any{"results": results, "errors": []any{}})
}

func writeRules(t *testing.T, path string, tc acceptanceCase) {
	t.Helper()
	var b strings.Builder
	b.WriteString("rules:\n")
	for _, match := range tc.matches {
		fmt.Fprintf(&b, "  - id: %s\n    message: dependency intelligence acceptance\n    severity: INFO\n    languages: [%s]\n    pattern: $X\n    metadata:\n      crypto:\n        assetType: algorithm\n        api: %s\n        parameterCondition: %q\n", match.ruleID, tc.ecosystem, match.api, acceptanceCondition)
	}
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
}

func writeFakeScanner(t *testing.T, dir string) {
	t.Helper()
	shellScript := `#!/bin/sh
case "$1" in
  --version) echo 1.12.1 ;;
  scan) echo --x-ignore-semgrepignore-files ;;
  --help) echo --x-ignore-semgrepignore-files ;;
  *) cat "$FAKE_OPENGREP_OUTPUT" ;;
esac
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "opengrep"), []byte(shellScript), 0o700))
	batchScript := `@echo off
if "%1"=="--version" (echo 1.12.1& exit /b 0)
if "%1"=="scan" (echo --x-ignore-semgrepignore-files& exit /b 0)
if "%1"=="--help" (echo --x-ignore-semgrepignore-files& exit /b 0)
type "%FAKE_OPENGREP_OUTPUT%"
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "opengrep.bat"), []byte(batchScript), 0o700))
}

func buildCryptoFinder(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crypto-finder")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", path, "./cmd/crypto-finder")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build output:\n%s", output)
	return path
}

func assertDependencyPin(t *testing.T, target string, tc acceptanceCase) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(target, tc.pinFile))
	require.NoError(t, err)
	for _, pin := range tc.pinTexts {
		require.Contains(t, string(data), pin, "fixture dependency pin")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller")
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func location(source, needle string) (line, col int) {
	index := strings.Index(source, needle)
	if index < 0 {
		return 0, 0
	}
	line = strings.Count(source[:index], "\n") + 1
	lastNewline := strings.LastIndex(source[:index], "\n")
	return line, index - lastNewline
}

func findingID(path string, line int, ruleID string) string {
	sum := sha256.Sum256([]byte(path + ":" + strconv.Itoa(line) + ":" + ruleID))
	return hex.EncodeToString(sum[:])[:8]
}

func allAssets(report entities.InterimReport) []entities.CryptographicAsset {
	count := 0
	for i := range report.Findings {
		count += len(report.Findings[i].CryptographicAssets)
	}
	assets := make([]entities.CryptographicAsset, 0, count)
	for _, finding := range report.Findings {
		assets = append(assets, finding.CryptographicAssets...)
	}
	return assets
}

func firstAsset(t *testing.T, report entities.InterimReport) entities.CryptographicAsset {
	t.Helper()
	assets := allAssets(report)
	require.NotEmpty(t, assets)
	return assets[0]
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoErrorf(t, json.Unmarshal(data, value), "decode %s:\n%s", path, data)
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}
