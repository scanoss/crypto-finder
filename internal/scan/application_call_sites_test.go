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

package scan

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// callSiteCallers builds the project at files the way a dependency scan does
// and returns the short names of the functions whose calls into a dependency
// the application reachability request carries.
func callSiteCallers(t *testing.T, ecosystem string, parser callgraph.Parser, files map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystem, parser).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	project := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, Ecosystem: ecosystem, ProjectRoot: dir}
	fragment := BuildGraphFragmentExport(project, &oid.ResolvedReport{})
	sites := engine.CallSites(&fragment, UnreachableCallers(project, &fragment))

	var callers []string
	for _, call := range sites.ExternalCalls {
		if !strings.Contains(call.TargetKey, "fingerprint") {
			continue
		}
		name := graph.Functions[call.CallerKey].ID.Name
		if !slices.Contains(callers, name) {
			callers = append(callers, name)
		}
	}
	for _, call := range sites.ExternalCalls {
		if !slices.ContainsFunc(sites.Functions, func(fn graphfrag.GraphFragmentFunction) bool { return fn.Key == call.CallerKey }) {
			t.Errorf("call site of %s has no function", call.CallerKey)
		}
	}
	slices.Sort(callers)
	return callers
}

const nodeManifest = `{"name": "app", "version": "1.0.0", "main": "index.js", "dependencies": {"liba": "1.0.0"}}`

// A call into a dependency is a call site of the request only when the
// function making it is reachable, as a finding in that function would be.
func TestUnreachableCallers_NodeDeadCallerSendsNoCallSite(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		main string
		want []string
	}{
		"dead caller":      {main: `console.log('hello');`, want: nil},
		"reachable caller": {main: `console.log(run('hello'));`, want: []string{"run"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := callSiteCallers(t, ecosystemNode, callgraph.NewNodeParser(), map[string]string{
				"package.json": nodeManifest,
				"index.js": `const liba = require('liba');

function run(data) {
  return liba.fingerprint(data);
}

function main() {
  ` + tc.main + `
}

main();
`,
			})
			if !slices.Equal(got, tc.want) {
				t.Errorf("callers into the dependency = %v, want %v", got, tc.want)
			}
		})
	}
}

// A function handed out as a value has no call edge, and a project with no
// entry point is a library whose every function may be called: both keep
// their call sites.
func TestUnreachableCallers_KeepsWhatProjectReachabilityKeeps(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		files map[string]string
		want  []string
	}{
		"handler passed as a value": {
			files: map[string]string{
				"package.json": nodeManifest,
				"index.js": `const liba = require('liba');
const bus = require('bus');

function onMessage(data) {
  return liba.fingerprint(data);
}

function main() {
  bus.subscribe(onMessage);
}

main();
`,
			},
			want: []string{"onMessage"},
		},
		"library without an entry point": {
			files: map[string]string{
				"lib/hash.py": `import liba


def digest(data):
    return liba.fingerprint(data)
`,
			},
			want: []string{"digest"},
		},
		"python dead caller": {
			files: map[string]string{
				"main.py": `import liba


def run(data):
    return liba.fingerprint(data)


def main():
    print("hello")


if __name__ == "__main__":
    main()
`,
			},
			want: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ecosystem, parser := ecosystemNode, callgraph.Parser(callgraph.NewNodeParser())
			if _, python := tc.files["main.py"]; python || tc.files["lib/hash.py"] != "" {
				ecosystem, parser = ecosystemPython, callgraph.NewPythonParser()
			}
			got := callSiteCallers(t, ecosystem, parser, tc.files)
			if !slices.Equal(got, tc.want) {
				t.Errorf("callers into the dependency = %v, want %v", got, tc.want)
			}
		})
	}
}

// requestReceiverProducers builds the project at source the way a dependency
// scan does and returns, by the method each call site calls, the producer
// its receiver carries in the application reachability request.
func requestReceiverProducers(t *testing.T, ecosystem string, parser callgraph.Parser, name, source string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystem, parser).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	project := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, Ecosystem: ecosystem, ProjectRoot: dir}
	fragment := BuildGraphFragmentExport(project, &oid.ResolvedReport{})
	for _, call := range fragment.ExternalCalls {
		if call.ReceiverProducer != "" {
			t.Errorf("the fragment of a scan names a receiver producer on %s; only a request does", call.TargetKey)
		}
	}
	AddReceiverProducers(project, &fragment)
	out := make(map[string]string)
	for _, call := range engine.CallSites(&fragment, nil).ExternalCalls {
		out[call.MethodName] = call.ReceiverProducer
	}
	return out
}

// The dependency's factory is not in the project's graph, so the project
// cannot say which class it builds. The request names the factory on the
// call made on its result, for the API to read the class in the
// dependency's graph: only for a local bound once, by that one call.
func TestApplicationRequestNamesTheFactoryOfAReceiver(t *testing.T) {
	got := requestReceiverProducers(t, "java", callgraph.NewJavaParser(), "src/main/java/org/acme/app/Main.java", `package org.acme.app;

import org.acme.liba.Hasher;
import org.acme.liba.Hashers;

public final class Main {
    public static void main(String[] args) {
        Hasher h = Hashers.standard();
        h.sum(new byte[0]);

        Hasher rebound = Hashers.standard();
        if (args.length > 0) {
            rebound = Hashers.plain();
        }
        rebound.reset();
    }
}
`)
	if want := "org.acme.liba.(Hashers).standard#0"; got["sum"] != want {
		t.Errorf("sum: receiver producer %q, want %q", got["sum"], want)
	}
	if got["reset"] != "" {
		t.Errorf("reset: receiver producer %q, want none: its receiver is assigned twice", got["reset"])
	}
	if _, sent := got["standard"]; !sent {
		t.Errorf("the request holds no call of the factory; call sites by method: %v", got)
	}
}

// The API reads what a factory builds only in a Java dependency's graph, so
// a request of another ecosystem stays as it was.
func TestApplicationRequestNamesNoFactoryOutsideJava(t *testing.T) {
	got := requestReceiverProducers(t, "go", callgraph.NewGoParser(), "main.go", `package main

import "example.com/liba"

func main() {
	h := liba.Standard()
	h.Sum(nil)
}
`)
	for method, producer := range got {
		if producer != "" {
			t.Errorf("%s: receiver producer %q, want none", method, producer)
		}
	}
	if len(got) == 0 {
		t.Error("the request holds no call site")
	}
}
