// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// assertOnlyCallee checks that caller reaches want and none of the others.
func assertOnlyCallee(t *testing.T, graph *CallGraph, caller, want string, not ...string) {
	t.Helper()
	if !hasCaller(graph, want, caller) {
		t.Errorf("%s does not reach %s; callers of it: %v", caller, want, graph.Callers[want])
	}
	for _, other := range not {
		if hasCaller(graph, other, caller) {
			t.Errorf("%s reaches %s, but its object is never one", caller, other)
		}
	}
}

// A factory declares an interface result and builds one implementation. A
// call on the value it returns reaches that implementation's method only:
// h := liba.Standard(); h.Sum(..) reaches standard.Sum and never plain.Sum.
func TestConstructedReceiver_GoFactoryReturningInterface(t *testing.T) {
	t.Parallel()
	g := buildGoTree(t, map[string]string{
		"liba/liba.go": `package liba

type Hasher interface{ Sum(data []byte) []byte }

type standard struct{}

func (standard) Sum(data []byte) []byte { return data }

type plain struct{}

func (*plain) Sum(data []byte) []byte { return data }

func Standard() Hasher { return standard{} }

func Plain() Hasher { return &plain{} }
`,
		"app/main.go": `package main

import "example.com/m/liba"

func useStandard() []byte {
	h := liba.Standard()
	return h.Sum(nil)
}

func usePlain() []byte {
	h := liba.Plain()
	return h.Sum(nil)
}
`,
	})
	standard := "example.com/m/liba.(standard).Sum"
	plain := "example.com/m/liba.(*plain).Sum"
	assertOnlyCallee(t, g, "example.com/m/app.useStandard", standard, plain)
	assertOnlyCallee(t, g, "example.com/m/app.usePlain", plain, standard)
}

func TestConstructedReceiver_PythonFactoryReturningSubclass(t *testing.T) {
	t.Parallel()
	g := buildPythonProject(t, map[string]string{
		"main.py": `import liba


def use_standard():
    h = liba.standard()
    return h.sum(b"x")


def use_plain():
    h = liba.plain()
    return h.sum(b"x")


def use_shared(h):
    h = liba.standard()
    return h.sum(b"x")
`,
		"liba/__init__.py": `class Hasher:
    def sum(self, data):
        raise NotImplementedError


class _Standard(Hasher):
    def sum(self, data):
        return data


class _Plain(Hasher):
    def sum(self, data):
        return bytes(data)


def standard():
    return _Standard()


def plain():
    if not _Plain:
        return None
    return _Plain()
`,
	})
	standard := "probe.liba.(_Standard).sum"
	plain := "probe.liba.(_Plain).sum"
	assertOnlyCallee(t, g, "probe.main.use_standard", standard, plain)
	assertOnlyCallee(t, g, "probe.main.use_plain", plain, standard)
	// A parameter may hold the caller's object instead, so it stays untyped.
	if hasCaller(g, standard, "probe.main.use_shared") {
		t.Errorf("use_shared reaches %s through its parameter h", standard)
	}
}

func TestConstructedReceiver_NodeFactoryReturningSubclass(t *testing.T) {
	t.Parallel()
	g := buildNodeAppWithDependency(t, "dispatch-liba", map[string]string{
		"package.json": `{"name":"dispatch-liba","main":"index.js"}`,
		"index.js": `class Hasher { sum(data) { throw new Error('abstract') } }
class Standard extends Hasher { sum(data) { return data } }
class Plain extends Hasher { sum(data) { return data } }
function standard() { return new Standard(); }
const plain = () => new Plain();
module.exports = { Hasher, standard, plain };
`,
	}, `const liba = require('dispatch-liba');
function useStandard() { const h = liba.standard(); return h.sum('x'); }
function usePlain() { const h = liba.plain(); return h.sum('x'); }
module.exports = { useStandard, usePlain };
`)
	standard := "dispatch-liba/index.(Standard).sum"
	plain := "dispatch-liba/index.(Plain).sum"
	assertOnlyCallee(t, g, "app/index.useStandard", standard, plain)
	assertOnlyCallee(t, g, "app/index.usePlain", plain, standard)
}

const javaHashersSource = `package org.example.liba;

public final class Hashers {
    public static Hasher standard() {
        return new Standard();
    }

    public static Hasher plain() {
        return new Plain();
    }

    public static Hasher anonymous() {
        return new Hasher() {
            @Override
            public byte[] sum(byte[] data) {
                return data;
            }
        };
    }

    private static final class Standard implements Hasher {
        @Override
        public byte[] sum(byte[] data) {
            return data;
        }
    }

    private static final class Plain implements Hasher {
        @Override
        public byte[] sum(byte[] data) {
            return data.clone();
        }
    }
}
`

// The Java shape of the same factory: the interface call no longer fans out
// to every implementation, so the factory that builds the harmless one does
// not reach the other. An anonymous class is not the interface, so a call on
// what such a factory returns keeps the fan-out.
func TestConstructedReceiver_JavaFactoryReturningImplementation(t *testing.T) {
	t.Parallel()
	g := buildJavaGraph(t, map[string]string{
		"org/example/liba/Hasher.java":  "package org.example.liba;\n\npublic interface Hasher {\n    byte[] sum(byte[] data);\n}\n",
		"org/example/liba/Hashers.java": javaHashersSource,
		"org/example/app/Main.java": `package org.example.app;

import org.example.liba.Hasher;
import org.example.liba.Hashers;

public final class Main {
    static byte[] useStandard() {
        Hasher h = Hashers.standard();
        return h.sum(new byte[0]);
    }

    static byte[] usePlain() {
        Hasher h = Hashers.plain();
        return h.sum(new byte[0]);
    }

    static byte[] useAnonymous() {
        Hasher h = Hashers.anonymous();
        return h.sum(new byte[0]);
    }
}
`,
	})
	standard := "org.example.liba.(Hashers.Standard).sum#1"
	plain := "org.example.liba.(Hashers.Plain).sum#1"
	assertOnlyCallee(t, g, "org.example.app.(Main).useStandard#0", standard, plain)
	assertOnlyCallee(t, g, "org.example.app.(Main).usePlain#0", plain, standard)
	anonymous := "org.example.app.(Main).useAnonymous#0"
	if !hasCaller(g, standard, anonymous) || !hasCaller(g, plain, anonymous) {
		t.Errorf("useAnonymous must keep the interface fan-out; callers of Standard.sum %v, of Plain.sum %v", g.Callers[standard], g.Callers[plain])
	}
}

// A function returning `Box<dyn Trait>` built from one struct: the trait
// method call on its result reaches that struct's impl.
func TestConstructedReceiver_RustBoxedTraitObject(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `pub trait Hasher {
    fn sum(&self, data: &[u8]) -> Vec<u8>;
}

struct Standard;

impl Hasher for Standard {
    fn sum(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
}

struct Plain { level: u8 }

impl Hasher for Plain {
    fn sum(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
}

pub fn standard() -> Box<dyn Hasher> {
    Box::new(Standard)
}

pub fn plain() -> Box<dyn Hasher> {
    return Box::new(Plain { level: 1 });
}

pub fn use_standard() -> Vec<u8> {
    let h = standard();
    h.sum(b"x")
}

pub fn use_plain() -> Vec<u8> {
    let h = plain();
    h.sum(b"x")
}
`
	if err := os.WriteFile(filepath.Join(dir, "lib.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := NewBuilderForEcosystem("rust", NewRustParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "hashers"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	standard := "hashers.(Standard).sum"
	plain := "hashers.(Plain).sum"
	assertOnlyCallee(t, g, "hashers.use_standard", standard, plain)
	assertOnlyCallee(t, g, "hashers.use_plain", plain, standard)
}
