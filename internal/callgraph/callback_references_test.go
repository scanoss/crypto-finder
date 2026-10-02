// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"slices"
	"testing"
)

// callbackCase is one source file and the reference edges it must, and must
// not, produce: each edge reads "registrar -> callee" in function keys.
type callbackCase struct {
	name   string
	source string
	want   []string
	not    []string
}

// hasEdge reports an edge; a registrar of "*" stands for any caller, for a
// registration made inside an anonymous function.
func hasEdge(graph *CallGraph, edge [2]string) bool {
	if edge[0] == "*" {
		return len(graph.Callers[edge[1]]) > 0
	}
	return slices.Contains(graph.Callers[edge[1]], edge[0])
}

func splitEdge(t *testing.T, edge string) [2]string {
	t.Helper()
	for i := 0; i+4 <= len(edge); i++ {
		if edge[i:i+4] == " -> " {
			return [2]string{edge[:i], edge[i+4:]}
		}
	}
	t.Fatalf("bad edge %q", edge)
	return [2]string{}
}

func checkCallbackEdges(t *testing.T, graph *CallGraph, tc callbackCase) {
	t.Helper()
	for _, edge := range tc.want {
		if !hasEdge(graph, splitEdge(t, edge)) {
			t.Errorf("missing edge %s; callers of the callee: %v", edge, graph.Callers[splitEdge(t, edge)[1]])
		}
	}
	for _, edge := range tc.not {
		if hasEdge(graph, splitEdge(t, edge)) {
			t.Errorf("unexpected edge %s", edge)
		}
	}
	for _, edge := range tc.want {
		callee := graph.Functions[splitEdge(t, edge)[1]]
		if callee != nil && callee.EntryKind != "" {
			t.Errorf("%s is an entry point (%q); a callback is reached through its registrar, never rooted", callee.ID, callee.EntryKind)
		}
	}
}

func TestBuilder_PythonCallbackReferences(t *testing.T) {
	t.Parallel()
	const prelude = "import atexit\nimport signal\nimport threading\nimport multiprocessing\nimport functools\nfrom concurrent.futures import ThreadPoolExecutor\nfrom django.db import migrations\n\n" +
		"def fn(*a):\n    pass\n\ndef other(*a):\n    pass\n\n"
	tests := []callbackCase{
		{
			name:   "thread target keyword",
			source: "def start():\n    threading.Thread(target=fn).start()\n",
			want:   []string{"app.mod.start -> app.mod.fn"},
		},
		{
			name:   "thread target positional and process",
			source: "def start():\n    threading.Thread(None, fn)\n    multiprocessing.Process(target=other)\n",
			want:   []string{"app.mod.start -> app.mod.fn", "app.mod.start -> app.mod.other"},
		},
		{
			name:   "from-imported thread and executor classes",
			source: "from threading import Thread\nfrom concurrent.futures import ProcessPoolExecutor as Pool\n\ndef start():\n    Thread(target=fn).start()\n    p = Pool()\n    p.submit(other)\n",
			want:   []string{"app.mod.start -> app.mod.fn", "app.mod.start -> app.mod.other"},
		},
		{
			name:   "builtins",
			source: "def start(xs):\n    list(map(fn, xs))\n    sorted(xs, key=other)\n",
			want:   []string{"app.mod.start -> app.mod.fn", "app.mod.start -> app.mod.other"},
		},
		{
			name:   "atexit signal reduce",
			source: "def start(xs):\n    atexit.register(fn)\n    signal.signal(signal.SIGINT, other)\n    functools.reduce(fn, xs)\n",
			want:   []string{"app.mod.start -> app.mod.fn", "app.mod.start -> app.mod.other"},
		},
		{
			name:   "executor from with and from assignment",
			source: "def start(xs):\n    with ThreadPoolExecutor() as ex:\n        ex.submit(fn, 1)\n    pool = ThreadPoolExecutor()\n    pool.map(other, xs)\n",
			want:   []string{"app.mod.start -> app.mod.fn", "app.mod.start -> app.mod.other"},
		},
		{
			name:   "django RunPython in a class body",
			source: "class Migration(migrations.Migration):\n    operations = [migrations.RunPython(fn, reverse_code=other)]\n",
			want:   []string{"app.mod.(Migration).<clinit> -> app.mod.fn", "app.mod.(Migration).<clinit> -> app.mod.other"},
		},
		{
			name:   "module level registration",
			source: "atexit.register(fn)\n",
			want:   []string{"app.mod.<module> -> app.mod.fn"},
		},
		{
			name:   "self method",
			source: "class K:\n    def run(self):\n        threading.Thread(target=self.work).start()\n    def work(self):\n        pass\n",
			want:   []string{"app.mod.(K).run -> app.mod.(K).work"},
		},
		{
			name:   "unknown registrar",
			source: "def reg(f):\n    f()\n\ndef start():\n    reg(fn)\n    reg(target=other)\n",
			not:    []string{"app.mod.start -> app.mod.fn", "app.mod.start -> app.mod.other"},
		},
		{
			name:   "call result",
			source: "def make():\n    return fn\n\ndef start():\n    threading.Thread(target=make()).start()\n    map(make(), [])\n",
			not:    []string{"app.mod.start -> app.mod.fn"},
		},
		{
			name:   "variable holding an unknown value",
			source: "def start(get):\n    f = get()\n    threading.Thread(target=f).start()\n",
			not:    []string{"app.mod.start -> app.mod.f"},
		},
		{
			name:   "name that resolves to nothing",
			source: "def start():\n    threading.Thread(target=ghost).start()\n    atexit.register(missing.attr)\n",
			not:    []string{"app.mod.start -> app.mod.ghost"},
		},
		{
			name:   "parameter shadows a module function",
			source: "def start(fn):\n    threading.Thread(target=fn).start()\n",
			not:    []string{"app.mod.start -> app.mod.fn"},
		},
		{
			name: "names bound inside the function shadow a module function",
			source: "def viaNested(items):\n    def inner(fn):\n        threading.Thread(target=fn).start()\n\n" +
				"def viaLambda(items):\n    return lambda fn: threading.Thread(target=fn)\n\n" +
				"def viaComprehension(fs):\n    return [threading.Thread(target=fn) for fn in fs]\n\n" +
				"def viaLoop(fs):\n    for fn in fs:\n        threading.Thread(target=fn).start()\n\n" +
				"def viaWith(open_it):\n    with open_it() as fn:\n        threading.Thread(target=fn).start()\n\n" +
				"def viaDef():\n    def fn():\n        pass\n    threading.Thread(target=fn).start()\n\n" +
				"def viaAssign(get):\n    fn, rest = get()\n    threading.Thread(target=fn).start()\n\n" +
				"def viaWalrus(get):\n    if (fn := get()):\n        threading.Thread(target=fn).start()\n",
			not: []string{
				"app.mod.viaNested -> app.mod.fn", "app.mod.viaLambda -> app.mod.fn", "app.mod.viaComprehension -> app.mod.fn",
				"app.mod.viaLoop -> app.mod.fn", "app.mod.viaWith -> app.mod.fn", "app.mod.viaDef -> app.mod.fn",
				"app.mod.viaAssign -> app.mod.fn", "app.mod.viaWalrus -> app.mod.fn",
			},
		},
		{
			name:   "a local named like a builtin is not the builtin",
			source: "def start(get, xs):\n    map = get()\n    map(fn, xs)\n",
			not:    []string{"app.mod.start -> app.mod.fn"},
		},
		{
			name:   "a function may register itself",
			source: "def retry():\n    threading.Timer(1, retry).start()\n",
			want:   []string{"app.mod.retry -> app.mod.retry"},
		},
		{
			name:   "module declares its own map",
			source: "def map(f, xs):\n    return xs\n\ndef start():\n    map(fn, [])\n",
			not:    []string{"app.mod.start -> app.mod.fn"},
		},
		{
			name:   "function argument in a position that takes no callback",
			source: "def start():\n    threading.Thread(args=(fn,)).start()\n    sorted([fn], key=None)\n    atexit.register(print, fn)\n",
			not:    []string{"app.mod.start -> app.mod.fn"},
		},
		{
			name:   "executor that is not an executor",
			source: "class Q:\n    def submit(self, f):\n        pass\n\ndef start():\n    q = Q()\n    q.submit(fn)\n",
			not:    []string{"app.mod.start -> app.mod.fn"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := writePythonTree(t, map[string]string{"app/__init__.py": "", "app/mod.py": prelude + tc.source})
			graph, err := NewBuilderForEcosystem("python", NewPythonParser()).BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			checkCallbackEdges(t, graph, tc)
		})
	}
}

// A callback imported from another module is referenced through the import,
// by its name or as module.fn.
func TestBuilder_PythonCallbackReferencesAcrossModules(t *testing.T) {
	t.Parallel()
	root := writePythonTree(t, map[string]string{
		"app/__init__.py": "",
		"app/lib.py":      "def job():\n    pass\n\ndef task():\n    pass\n",
		"app/main.py":     "import threading\nimport atexit\nfrom app import lib\nfrom app.lib import job\n\ndef start():\n    threading.Thread(target=job).start()\n    atexit.register(lib.task)\n",
	})
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	checkCallbackEdges(t, graph, callbackCase{want: []string{"app.main.start -> app.lib.job", "app.main.start -> app.lib.task"}})
}
