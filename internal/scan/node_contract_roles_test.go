// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// Every import form below binds the same elliptic API. A Node consumer holds
// the library object in a variable: `new EC(curve)` makes the curve context,
// `ec.genKeyPair()` makes the key pair, and the key pair signs and verifies.
// Each finding is the one the detection rules report on that file, at the
// lines and columns a scan reports.
const nodeEllipticRequireMember = `const EC = require('elliptic').ec;

function sign(msgHash) {
  const ec = new EC('secp256k1');
  const key = ec.genKeyPair();
  const sig = key.sign(msgHash);
  return key.verify(msgHash, sig);
}

module.exports = { sign };
`

const nodeEllipticESMImport = `import { ec as EC } from 'elliptic';

export function sign(msgHash) {
  const ec = new EC('secp256k1');
  const key = ec.genKeyPair();
  const sig = key.sign(msgHash);
  return key.verify(msgHash, sig);
}
`

const nodeEllipticDestructuredRequire = `const { ec: EC } = require('elliptic');

function sign(msgHash) {
  const ec = new EC('secp256k1');
  const key = ec.genKeyPair();
  const sig = key.sign(msgHash);
  return key.verify(msgHash, sig);
}

module.exports = { sign };
`

// What tsc emits for `import * as elliptic from 'elliptic'` and
// `import { sha256 } from 'hash.js'`. The namespace goes through __importStar
// and a named import is called as (0, ns.fn)(..).
const nodeTSCompiledOutput = `"use strict";
var __importStar = (this && this.__importStar) || function (mod) { return mod; };
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = sign;
exports.digest = digest;
const elliptic = __importStar(require("elliptic"));
const hash_js_1 = require("hash.js");
function sign(msgHash) {
    const ec = new elliptic.ec('secp256k1');
    const key = ec.genKeyPair();
    const sig = key.sign(msgHash);
    return key.verify(msgHash, sig);
}
function digest(data) {
    const h = (0, hash_js_1.sha256)();
    h.update(data);
    return h.digest('hex');
}
`

// hash.js is written as one fluent chain, and only its first link names the
// algorithm.
const nodeHashJSChain = `const hash = require('hash.js');

function digest(msg) {
  return hash.sha256().update(msg).digest('hex');
}

module.exports = { digest };
`

func nodeSignAsset(line, startCol, endCol int) entities.CryptographicAsset {
	return cAsset(line, line, startCol, endCol, "const sig = key.sign(msgHash);",
		"javascript.elliptic.algorithm.signature.sign",
		map[string]string{"assetType": "algorithm", "api": "elliptic.KeyPair.sign"})
}

var nodeEllipticSignLifecycle = map[string]string{
	"elliptic.ec.<init>":      "factory",
	"elliptic.ec.genKeyPair":  "factory",
	"elliptic.KeyPair.verify": "operation",
}

func TestNodeSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, file, src string
		asset           entities.CryptographicAsset
		want            map[string]string
	}{
		{
			name:  "plain require of a member",
			file:  "plain.js",
			src:   nodeEllipticRequireMember,
			asset: nodeSignAsset(6, 15, 32),
			want:  nodeEllipticSignLifecycle,
		},
		{
			name:  "esm named import with an alias",
			file:  "esm.mjs",
			src:   nodeEllipticESMImport,
			asset: nodeSignAsset(6, 15, 32),
			want:  nodeEllipticSignLifecycle,
		},
		{
			name:  "destructured require with an alias",
			file:  "destructured.js",
			src:   nodeEllipticDestructuredRequire,
			asset: nodeSignAsset(6, 15, 32),
			want:  nodeEllipticSignLifecycle,
		},
		{
			name:  "typescript __importStar namespace",
			file:  "compiled.js",
			src:   nodeTSCompiledOutput,
			asset: nodeSignAsset(11, 17, 34),
			want:  nodeEllipticSignLifecycle,
		},
		{
			name: "typescript (0, ns.fn) call of a contracted factory",
			file: "compiled.js",
			src:  nodeTSCompiledOutput,
			asset: cAsset(15, 15, 15, 38, "const h = (0, hash_js_1.sha256)();",
				"javascript.hash-js.algorithm.hash.sha-256",
				map[string]string{"assetType": "algorithm", "api": "hash.js.sha256"}),
			want: map[string]string{
				"hash.js.SHA256.update": "operation",
				"hash.js.SHA256.digest": "output",
			},
		},
		{
			name: "fluent chain rooted at a contracted factory",
			file: "chain.js",
			src:  nodeHashJSChain,
			asset: cAsset(4, 4, 10, 23, "return hash.sha256().update(msg).digest('hex');",
				"javascript.hash-js.algorithm.hash.sha256",
				map[string]string{"assetType": "algorithm", "api": "hash.js.sha256"}),
			// A chain's terminal is its outermost link, so the other links are
			// its supporting calls.
			want: map[string]string{
				"hash.js.sha256":        "factory",
				"hash.js.SHA256.update": "operation",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNodeSupportingRoles(t, tc.file, tc.src, tc.asset, tc.want)
		})
	}
}

// assertNodeSupportingRoles scans src as file with one finding and checks that
// its supporting calls carry the wanted contract roles, identically in the
// graph fragment, the call graph export and the annotate path.
func assertNodeSupportingRoles(t *testing.T, file, src string, asset entities.CryptographicAsset, want map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath:            file,
			Language:            "javascript",
			CryptographicAssets: []entities.CryptographicAsset{asset},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	result := &engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: "node"}

	fragment := buildGraphFragmentExport(result)
	got := map[string]string{}
	fragmentIDs := make([]string, 0, len(fragment.SupportingCalls))
	for i := range fragment.SupportingCalls {
		s := &fragment.SupportingCalls[i]
		if s.SupportingCall != nil {
			got[s.SupportingCall.FunctionName] = s.Category
		}
		fragmentIDs = append(fragmentIDs, s.SupportingID)
	}
	if !equalStringMaps(got, want) {
		t.Errorf("graph fragment supporting calls = %v, want %v", got, want)
	}

	callgraphExport := buildCallGraphExportV2(result)
	fromCallgraph := map[string]string{}
	for i := range callgraphExport.SupportingCalls {
		s := &callgraphExport.SupportingCalls[i]
		fromCallgraph[s.SupportingCall.FunctionName] = s.Category
	}
	if !equalStringMaps(fromCallgraph, got) {
		t.Errorf("callgraph export supporting calls = %v, graph fragment = %v", fromCallgraph, got)
	}

	cached := decodeFragmentForTest(t, marshalSorted(t, fragment))
	annotate := buildAnnotateExport(prepareOIDFixtureReport(t, report), cached)
	annotateIDs := make([]string, 0, len(annotate.SupportingCalls))
	for i := range annotate.SupportingCalls {
		annotateIDs = append(annotateIDs, annotate.SupportingCalls[i].SupportingID)
	}
	sort.Strings(fragmentIDs)
	sort.Strings(annotateIDs)
	if len(annotateIDs) != len(fragmentIDs) {
		t.Fatalf("annotate supporting ids = %v, full export = %v", annotateIDs, fragmentIDs)
	}
	for i := range annotateIDs {
		if annotateIDs[i] != fragmentIDs[i] {
			t.Fatalf("annotate supporting ids = %v, full export = %v", annotateIDs, fragmentIDs)
		}
	}
}
