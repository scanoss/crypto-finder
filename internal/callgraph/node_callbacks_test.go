// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

func TestBuilder_NodeCallbackReferences(t *testing.T) {
	t.Parallel()
	const header = `import { ipcMain } from 'electron';
import * as util from './util';
import _ from 'lodash';

function a() {}
function b() {}
function c() {}
function d() {}

`
	tests := []callbackCase{
		{
			name: "timers and microtasks",
			source: `function start() {
  setTimeout(a, 1);
  setInterval(b, 1);
  setImmediate(c);
  queueMicrotask(a);
  process.nextTick(b);
}
`,
			want: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b", "app/main.start -> app/main.c"},
		},
		{
			name: "array methods by name, with a type assertion",
			source: `function start(xs: number[]) {
  xs.map(a);
  xs.forEach(b);
  xs.filter(c as any);
  xs.flatMap(a);
}
`,
			want: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b", "app/main.start -> app/main.c"},
		},
		{
			name: "promise methods and constructor",
			source: `function start(p: Promise<number>) {
  p.then(a).catch(b).finally(c);
  new Promise(a);
}
`,
			want: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b", "app/main.start -> app/main.c"},
		},
		{
			name: "event emitters, listeners and electron ipc",
			source: `function start(emitter: any, el: any) {
  emitter.on('x', a);
  emitter.once('x', b);
  el.addEventListener('click', c);
  ipcMain.handle('ch', a);
}
`,
			want: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b", "app/main.start -> app/main.c"},
		},
		{
			name: "this method and imported module function",
			source: `export class K {
  work() {}
  run(emitter: any) {
    emitter.on('x', this.work);
    [1].forEach(util.helper);
  }
}
`,
			want: []string{"app/main.(K).run -> app/main.(K).work", "app/main.(K).run -> app/util.helper"},
		},
		{
			name: "module level registration",
			source: `setTimeout(a, 1);
`,
			want: []string{"app/main.<module> -> app/main.a"},
		},
		{
			name: "unknown registrar",
			source: `function reg(f: any, g: any) { f(); }

function start(api: any) {
  reg(a, 1);
  api.handle('x', b);
  api.register(c);
}
`,
			not: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b", "app/main.start -> app/main.c"},
		},
		{
			name: "ipcMain that is not electron's",
			source: `function start(ipcMain: any) {
  ipcMain.handle('ch', a);
}
`,
			not: []string{"app/main.start -> app/main.a"},
		},
		{
			name: "call result and inline function arguments",
			source: `function make() { return a; }

function start(xs: number[]) {
  setTimeout(make(), 1);
  xs.map(() => 1);
}
`,
			not: []string{"app/main.start -> app/main.a"},
		},
		{
			name: "parameter and local shadow a function",
			source: `function viaParam(a: () => void) {
  setTimeout(a, 1);
}

function viaLocal(get: any) {
  const b = get();
  setTimeout(b, 1);
}
`,
			not: []string{"app/main.viaParam -> app/main.a", "app/main.viaLocal -> app/main.b"},
		},
		{
			name: "methods too likely a domain method to match",
			source: `function start(repo: any) {
  repo.find(a);
  repo.findIndex(a);
  repo.findLast(a);
  repo.findLastIndex(a);
  repo.some(b);
  repo.every(b);
  repo.sort(c);
}
`,
			not: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b", "app/main.start -> app/main.c"},
		},
		{
			name: "name bound by an enclosing function",
			source: `function viaClosure(a: () => void, items: number[]) {
  items.forEach(() => setTimeout(a, 1));
}

function viaOuterLocal(items: number[]) {
  const b = items.length;
  items.forEach(function () { setTimeout(b, 1); });
}

function viaArrowParam() {
  return (c: any) => setTimeout(c, 1);
}

function viaOuterDestructure(x: any, items: number[]) {
  const { d } = x;
  items.forEach(() => setTimeout(d, 1));
}
`,
			not: []string{"* -> app/main.a", "* -> app/main.b", "* -> app/main.c", "* -> app/main.d"},
		},
		{
			name: "destructured names shadow a function",
			source: `function viaConst(x: any) {
  const { a } = x;
  const [b] = x;
  setTimeout(a, 1);
  setTimeout(b, 1);
}

function viaParam({ c }: any) {
  setTimeout(c, 1);
}

function viaRenamed(x: any) {
  const { y: a } = x;
  setTimeout(a, 1);
}
`,
			not: []string{"app/main.viaConst -> app/main.a", "app/main.viaConst -> app/main.b", "app/main.viaParam -> app/main.c", "app/main.viaRenamed -> app/main.a"},
		},
		{
			name: "loop and catch bindings shadow a function",
			source: `function start(xs: any[]) {
  for (const a of xs) { setTimeout(a, 1); }
  try { xs.length; } catch (b) { setTimeout(b, 1); }
}
`,
			not: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b"},
		},
		{
			name: "imported object and shadowed global",
			source: `function start(xs: number[]) {
  _.map(xs, a);
  util.map(a);
}

function shadow(setTimeout: any) {
  setTimeout(b, 1);
}
`,
			not: []string{"app/main.start -> app/main.a", "app/main.shadow -> app/main.b"},
		},
		{
			name: "name that resolves to nothing",
			source: `function start() {
  setTimeout(ghost, 1);
  setTimeout(missing.attr, 1);
}
`,
			not: []string{"app/main.start -> app/main.ghost"},
		},
		{
			name: "argument position that takes no callback",
			source: `function start(emitter: any) {
  emitter.on(a, 1);
  setTimeout(1, b);
}
`,
			not: []string{"app/main.start -> app/main.a", "app/main.start -> app/main.b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := writePythonTree(t, map[string]string{
				"main.ts": header + tc.source,
				"util.ts": "export function helper() {}\n",
			})
			graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			checkCallbackEdges(t, graph, tc)
		})
	}
}
