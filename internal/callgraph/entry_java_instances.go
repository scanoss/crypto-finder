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

package callgraph

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"
)

// entry_java_instances.go decides whether an uncalled instance method of an
// application Java class may stop being a root (entry_scope.go).
//
// An instance method runs only on an instance. When nothing can create an
// instance of its class, nothing can call it, whatever interface or
// framework sits between. So, in a module with an entry point, an uncalled
// instance method is dead code when its class is not live. A class is live
// when any of these hold, and the rule keeps its methods roots:
//
//   - it is not a plain class or record: an enum has its constants as
//     instances, an interface its implementations, so their methods stay
//     roots;
//   - the application creates or names it: new C(..) (with or without a
//     class body, and C anywhere in the created type, so the type argument of
//     new TypeReference<C>() {} counts), C::new, C.class, or C as a word of
//     any string literal (Class.forName("app.C"), a bean name) or of a
//     configuration file of its module (Spring XML, META-INF/services,
//     spring.factories);
//   - an annotation sits on it other than an inert java.lang one
//     (entry_markers.go): @Component, @RestController, @Path, @Named or any
//     annotation this file does not know may make a framework instantiate it;
//   - it extends or implements, directly or through application supertypes,
//     a type that is not an application class (a framework base, Runnable,
//     Serializable, or a supertype that does not resolve to one): code
//     outside the application may create or receive it, and the method may
//     override a method of that type;
//   - a subclass of it is live, since the subclass's instances run its
//     inherited methods.
//
// The Java files read are every .java file under the application's modules,
// test sources included. Creations and names are read by simple name, so a
// name shared by two classes makes both live: when unsure, the method stays
// a root.

// javaKeywordNew is the last token of a constructor reference, C::new.
const javaKeywordNew = "new"

// javaClassInfo is what the source declares about one application class.
type javaClassInfo struct {
	simple      string
	kind        string
	annotations []string
	// supertypes holds, for each type the class extends or implements, the
	// fully qualified names it may resolve to.
	supertypes [][]string
	// duplicate is set when two files declare the same fully qualified name
	// (two modules of a monorepo): which one a method belongs to is unknown,
	// so the class is live.
	duplicate bool
}

// javaClassFacts is what the application's Java source says about its
// classes and how it creates them.
type javaClassFacts struct {
	// classes maps a fully qualified name (package.Outer.Inner) to its class.
	classes map[string]*javaClassInfo
	// named holds the simple names the application creates, takes the class
	// of, or writes in a string or a configuration file.
	named map[string]bool
	// subclasses maps a class to the application classes that extend or
	// implement it.
	subclasses map[string][]string
	liveness   map[string]bool
	// incomplete is set when a source file could not be read or parsed: a
	// creation in it could make any class live.
	incomplete bool
}

// newJavaClassFacts reads the Java source files and configuration files.
func newJavaClassFacts(sources, configs []string) *javaClassFacts {
	facts := &javaClassFacts{
		classes: map[string]*javaClassInfo{}, named: map[string]bool{},
		subclasses: map[string][]string{}, liveness: map[string]bool{},
	}
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(java.GetLanguage())
	for _, file := range sources {
		src, err := os.ReadFile(file)
		if err != nil {
			facts.incomplete = true
			continue
		}
		tree, err := parser.ParseCtx(context.Background(), nil, src)
		if err != nil || tree == nil {
			facts.incomplete = true
			continue
		}
		root := tree.RootNode()
		pkg := javaPackageName(root, src)
		reader := javaFileReader{facts: facts, src: src, pkg: pkg, imports: javaImportBindings(root, src)}
		reader.read(root, nil)
		tree.Close()
	}
	for _, file := range configs {
		if src, err := os.ReadFile(file); err == nil {
			facts.nameWords(src)
		}
	}
	for fqn, info := range facts.classes {
		for _, candidates := range info.supertypes {
			for _, super := range candidates {
				if facts.classes[super] != nil {
					facts.subclasses[super] = append(facts.subclasses[super], fqn)
				}
			}
		}
	}
	return facts
}

// addUnliveInstanceMethods adds to candidates the Java instance methods
// whose class is not live. stop is the directory standing for code in no
// module.
func (s *rootScope) addUnliveInstanceMethods(candidates map[string][]*FunctionDecl, methods []*FunctionDecl, stop string) {
	if len(methods) == 0 {
		return
	}
	sources, complete := javaSourceFiles(s.moduleRoots(stop))
	if !complete {
		return // a creation in a file not read could make any class live
	}
	facts := newJavaClassFacts(sources, configFiles(s.entryModuleDirs()))
	if facts.incomplete {
		return
	}
	for _, decl := range methods {
		if !facts.live(javaOwner(decl)) {
			candidates[decl.FilePath] = append(candidates[decl.FilePath], decl)
		}
	}
}

// javaSourceFiles lists the .java files under roots, each once, skipping
// hidden directories and the dependency and build output directories at a
// module's top (javaSkipDir).
// complete is false when a directory could not be read.
func javaSourceFiles(roots []string) (files []string, complete bool) {
	seen := map[string]bool{}
	var out []string
	complete = true
	for _, root := range roots {
		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				complete = false
				return nil //nolint:nilerr // recorded: the facts are incomplete
			}
			if entry.IsDir() {
				if javaSkipDir(root, path, entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".java") && !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
			return nil
		})
		if walkErr != nil {
			complete = false
		}
	}
	return out, complete
}

// javaSkipDir reports a directory the Java walk leaves out: a hidden one, or
// a dependency or build output directory directly under the module root. A
// source package may be named build, out or target (com.app.build), so the
// names are skipped only there: the walk errs toward reading too much.
func javaSkipDir(root, path, name string) bool {
	if path == root {
		return false
	}
	return strings.HasPrefix(name, ".") || (configSkipDirs[name] && filepath.Dir(path) == root)
}

// moduleRoots lists the directories of the application's modules, sorted,
// stop for code in no module.
func (s *rootScope) moduleRoots(stop string) []string {
	seen := map[string]bool{}
	var out []string
	for _, module := range s.moduleOf {
		if module == "" {
			module = stop
		}
		if module != "" && !seen[module] {
			seen[module] = true
			out = append(out, module)
		}
	}
	sort.Strings(out)
	return out
}

func javaPackageName(root *sitter.Node, src []byte) string {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		child := root.NamedChild(i)
		if child.Type() != "package_declaration" {
			continue
		}
		for j := 0; j < int(child.NamedChildCount()); j++ {
			if name := child.NamedChild(j); name.Type() == javaNodeScopedIdentifier || name.Type() == javaNodeIdentifier {
				return name.Content(src)
			}
		}
	}
	return ""
}

func (f *javaClassFacts) nameWords(src []byte) {
	for _, word := range identifierPattern.FindAll(src, -1) {
		f.named[string(word)] = true
	}
}

// javaFileReader records what one file declares and creates.
type javaFileReader struct {
	facts   *javaClassFacts
	src     []byte
	pkg     string
	imports map[string]string
}

// read walks node; enclosing holds the fully qualified names of the types
// around it, innermost last.
func (r *javaFileReader) read(node *sitter.Node, enclosing []string) {
	switch node.Type() {
	case javaNodeClassDeclaration, javaNodeRecordDeclaration, javaNodeEnumDeclaration,
		javaNodeInterfaceDeclaration, javaNodeAnnotationTypeDecl:
		if name := node.ChildByFieldName("name"); name != nil {
			simple := name.Content(r.src)
			fqn := r.qualify(simple, enclosing)
			if existing := r.facts.classes[fqn]; existing != nil {
				existing.duplicate = true
			} else {
				r.facts.classes[fqn] = &javaClassInfo{
					simple: simple, kind: node.Type(),
					annotations: javaWrittenAnnotations(node, r.src),
					supertypes:  r.supertypes(node, append(enclosing[:len(enclosing):len(enclosing)], fqn)),
				}
			}
			enclosing = append(enclosing[:len(enclosing):len(enclosing)], fqn)
		}
	case javaNodeObjectCreation:
		if created := node.ChildByFieldName("type"); created != nil {
			r.nameTypes(created)
		}
	case javaNodeMethodReference:
		if count := node.ChildCount(); count >= 2 && node.Child(int(count)-1).Type() == javaKeywordNew {
			r.nameTypes(node.NamedChild(0))
		}
	case "class_literal":
		r.nameTypes(node.NamedChild(0))
	case cNodeStringLiteral, "text_block":
		r.facts.nameWords([]byte(node.Content(r.src)))
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		r.read(node.NamedChild(i), enclosing)
	}
}

func (r *javaFileReader) qualify(simple string, enclosing []string) string {
	switch {
	case len(enclosing) > 0:
		return enclosing[len(enclosing)-1] + "." + simple
	case r.pkg != "":
		return r.pkg + "." + simple
	default:
		return simple
	}
}

// nameTypes records every type name inside a type: its own and its type
// arguments'.
func (r *javaFileReader) nameTypes(node *sitter.Node) {
	if node == nil {
		return
	}
	if node.Type() == javaNodeTypeIdentifier || node.Type() == javaNodeIdentifier {
		r.facts.named[node.Content(r.src)] = true
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		r.nameTypes(node.NamedChild(i))
	}
}

// supertypes returns, for each type a declaration extends or implements,
// the fully qualified names it may resolve to: through a single-type import,
// else as a member of an enclosing type, else in the file's package, and a
// qualified name as written.
func (r *javaFileReader) supertypes(node *sitter.Node, scopes []string) [][]string {
	var out [][]string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case javaNodeSuperclass, javaNodeSuperInterfaces, "extends_interfaces":
			for _, typ := range javaListedTypes(child) {
				if written := javaTypePath(typ, r.src); written != "" {
					out = append(out, r.resolve(written, scopes))
				}
			}
		}
	}
	return out
}

func (r *javaFileReader) resolve(written string, scopes []string) []string {
	head, rest, qualified := strings.Cut(written, ".")
	if imported, ok := r.imports[head]; ok {
		if qualified {
			return []string{imported + "." + rest}
		}
		return []string{imported}
	}
	candidates := make([]string, 0, len(scopes)+2)
	for i := len(scopes) - 1; i >= 0; i-- {
		candidates = append(candidates, scopes[i]+"."+written)
	}
	if r.pkg != "" {
		candidates = append(candidates, r.pkg+"."+written)
	}
	return append(candidates, written)
}

// javaListedTypes returns the types of a superclass, super_interfaces or
// extends_interfaces clause.
func javaListedTypes(clause *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	for i := 0; i < int(clause.NamedChildCount()); i++ {
		child := clause.NamedChild(i)
		if child.Type() == javaNodeTypeList {
			for j := 0; j < int(child.NamedChildCount()); j++ {
				out = append(out, child.NamedChild(j))
			}
			continue
		}
		out = append(out, child)
	}
	return out
}

// javaTypePath is a written type without its type arguments: Base,
// a.b.Base, Outer.Base.
func javaTypePath(node *sitter.Node, src []byte) string {
	switch node.Type() {
	case javaNodeTypeIdentifier:
		return node.Content(src)
	case javaNodeGenericType:
		if node.NamedChildCount() > 0 {
			return javaTypePath(node.NamedChild(0), src)
		}
	case javaNodeScopedTypeIdentifier:
		parts := make([]string, 0, node.NamedChildCount())
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if part := javaTypePath(node.NamedChild(i), src); part != "" {
				parts = append(parts, part)
			}
		}
		return strings.Join(parts, ".")
	}
	return ""
}

// live reports whether the class fqn may have instances: see the file
// comment.
func (f *javaClassFacts) live(fqn string) bool {
	if known, ok := f.liveness[fqn]; ok {
		return known
	}
	// A cycle through the hierarchy, which Java rejects, reads not live
	// while it is being decided.
	f.liveness[fqn] = false
	live := f.decideLive(fqn)
	f.liveness[fqn] = live
	return live
}

func (f *javaClassFacts) decideLive(fqn string) bool {
	info := f.classes[fqn]
	if info == nil || info.duplicate || (info.kind != javaNodeClassDeclaration && info.kind != javaNodeRecordDeclaration) {
		return true
	}
	if f.named[info.simple] {
		return true
	}
	for _, annotation := range info.annotations {
		if !inertAnnotations[annotation] {
			return true
		}
	}
	if f.externalSupertype(info, map[string]bool{}) {
		return true
	}
	for _, sub := range f.subclasses[fqn] {
		if f.live(sub) {
			return true
		}
	}
	return false
}

// externalSupertype reports whether info extends or implements, directly or
// through application supertypes, a type that resolves to no application
// class.
func (f *javaClassFacts) externalSupertype(info *javaClassInfo, seen map[string]bool) bool {
	for _, candidates := range info.supertypes {
		super := ""
		for _, candidate := range candidates {
			if f.classes[candidate] != nil {
				super = candidate
				break
			}
		}
		if super == "" {
			return true
		}
		if seen[super] {
			continue
		}
		seen[super] = true
		if f.externalSupertype(f.classes[super], seen) {
			return true
		}
	}
	return false
}

// javaInstanceShape reports an instance method of a Java class: the shape
// that may stop being a root only when its class is not live.
func javaInstanceShape(decl *FunctionDecl) bool {
	return strings.HasSuffix(decl.FilePath, ".java") && decl.ID.Type != "" && !decl.Static &&
		decl.OwnerType == "class" && !implicitRoot(decl) && !isTestDeclaration(decl)
}

// javaOwner is the fully qualified name of decl's class as the facts key it.
func javaOwner(decl *FunctionDecl) string {
	if decl.ID.Package == "" {
		return decl.ID.Type
	}
	return decl.ID.Package + "." + decl.ID.Type
}
