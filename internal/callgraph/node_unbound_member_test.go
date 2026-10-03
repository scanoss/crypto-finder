// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

const unboundMemberUtils = `export function digest(v) { return v }
`

const unboundMemberModule = `import crypto from 'crypto'
import * as utils from './utils'

function digest(v) { return v }
function getThing() { return { digest() {} } }

export class Box {
  digest() { return 1 }
  viaThis() { return this.digest() }
}

export function chained(data) {
  return crypto.createHash('md5').update(data).digest('hex')
}
export function callResultReceiver() { return getThing().digest() }
export function paramReceiver(someParam) { return someParam.digest() }
export function plainCall(v) { return digest(v) }
export function namespaceCall(v) { return utils.digest(v) }
export function typedReceiver() { const b = new Box(); return b.digest() }
`

func TestNodeMemberCallOnUnresolvedReceiverBindsNoModuleFunction(t *testing.T) {
	t.Parallel()
	for _, ext := range []string{"js", "ts"} {
		graph := buildNodeFiles(t, map[string]string{
			"m." + ext:     unboundMemberModule,
			"utils." + ext: unboundMemberUtils,
		})
		digest, _ := graphFunction(t, graph, "app/m", "", "digest")
		utilsDigest, _ := graphFunction(t, graph, "app/utils", "", "digest")
		boxDigest, _ := graphFunction(t, graph, "app/m", "Box", "digest")

		for _, name := range []string{"chained", "callResultReceiver", "paramReceiver"} {
			caller, _ := graphFunction(t, graph, "app/m", "", name)
			for _, target := range []string{digest, utilsDigest} {
				if hasCaller(graph, target, caller) {
					t.Errorf("%s: %s must not call %s", ext, name, target)
				}
			}
		}

		controls := []struct{ caller, target string }{
			{"plainCall", digest},
			{"namespaceCall", utilsDigest},
		}
		for _, c := range controls {
			caller, _ := graphFunction(t, graph, "app/m", "", c.caller)
			if !hasCaller(graph, c.target, caller) {
				t.Errorf("%s: Callers[%s] = %v, want %s", ext, c.target, graph.Callers[c.target], caller)
			}
		}
		typed, _ := graphFunction(t, graph, "app/m", "", "typedReceiver")
		if !hasCaller(graph, boxDigest, typed) {
			t.Errorf("%s: typed receiver: Callers[%s] = %v, want %s", ext, boxDigest, graph.Callers[boxDigest], typed)
		}
		viaThis, _ := graphFunction(t, graph, "app/m", "Box", "viaThis")
		if !hasCaller(graph, boxDigest, viaThis) {
			t.Errorf("%s: this call: Callers[%s] = %v, want %s", ext, boxDigest, graph.Callers[boxDigest], viaThis)
		}
	}
}

const requireReceiverModule = `const crypto = require('crypto')

function digest(v) { return v }

function viaRequire(v) { return require('./utils').digest(v) }
function viaRequireMissing() { return require('./utils').missing() }
function viaInterop(v) { return __importStar(require('./utils')).digest(v) }
function stillUnbound(data) { return crypto.createHash('md5').update(data).digest('hex') }
function stillUnboundCall() { return getThing().digest() }

module.exports = { viaRequire, viaRequireMissing, viaInterop, stillUnbound, stillUnboundCall }
`

func TestNodeMemberCallOnInlineRequireBindsTheRequiredModule(t *testing.T) {
	t.Parallel()
	for _, ext := range []string{"js", "ts"} {
		graph := buildNodeFiles(t, map[string]string{
			"m." + ext:     requireReceiverModule,
			"utils." + ext: unboundMemberUtils,
		})
		local, _ := graphFunction(t, graph, "app/m", "", "digest")
		utilsDigest, _ := graphFunction(t, graph, "app/utils", "", "digest")

		for _, name := range []string{"viaRequire", "viaInterop"} {
			caller, _ := graphFunction(t, graph, "app/m", "", name)
			if !hasCaller(graph, utilsDigest, caller) {
				t.Errorf("%s: Callers[%s] = %v, want %s", ext, utilsDigest, graph.Callers[utilsDigest], caller)
			}
			if hasCaller(graph, local, caller) {
				t.Errorf("%s: %s must not call the same-file digest", ext, name)
			}
		}
		for _, name := range []string{"viaRequireMissing", "stillUnbound", "stillUnboundCall"} {
			caller, _ := graphFunction(t, graph, "app/m", "", name)
			for _, target := range []string{local, utilsDigest} {
				if hasCaller(graph, target, caller) {
					t.Errorf("%s: %s must not call %s", ext, name, target)
				}
			}
		}
	}
}
