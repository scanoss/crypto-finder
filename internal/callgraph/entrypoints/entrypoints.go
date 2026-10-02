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

// Package entrypoints loads the framework entry-point catalog: which
// functions a web framework, task queue, CLI library or container calls, so
// that no call edge in the application leads to them. The catalog is data,
// one YAML file per framework under <language>/<framework>.yaml. Each entry
// names the package that brings the framework into scope, the names it
// declares, and the shape the callgraph parsers recognize (a decorator, a
// handler registration call, ...). The parsers own the shapes and the
// language semantics that belong to no library (main, a __main__ guard, Go
// init functions); this package owns only the names.
package entrypoints

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed */*.yaml
var catalogFS embed.FS

// SchemaVersion is the only schema_version a catalog file may declare.
const SchemaVersion = "1"

// Shape is how source code hands a function to a framework. A parser
// recognizes each shape in its own language.
type Shape string

const (
	// ShapeDecorator is a Java annotation or a Python or TypeScript decorator
	// on the function: @GetMapping, @app.route("/x"), @Post().
	ShapeDecorator Shape = "decorator"
	// ShapeRegistrationCall is a call that passes the function to the
	// framework: app.get("/x", handler), http.HandleFunc("/x", h),
	// path("x/", views.index).
	ShapeRegistrationCall Shape = "registration_call"
	// ShapeHandlerField is a struct literal of a framework type whose field
	// holds the function: &cobra.Command{RunE: run}.
	ShapeHandlerField Shape = "handler_field"
	// ShapeSupertype is a method of a type that extends, implements or embeds
	// a framework type: HttpServlet.doPost, a Django View's get, the methods
	// of a type embedding a generated gRPC Unimplemented...Server.
	ShapeSupertype Shape = "supertype"
	// ShapeServerRegistration is a call that registers a service
	// implementation with a generated Register<Service>Server function, as
	// pb.RegisterKeysServer(grpcServer, impl). Names are patterns with "*".
	// The parser roots the methods of the registered value that belong to the
	// service.
	ShapeServerRegistration Shape = "server_registration"
	// ShapeInterfaceMethod is a method that implements a framework interface
	// by signature: ServeHTTP(http.ResponseWriter, *http.Request).
	ShapeInterfaceMethod Shape = "interface_method"
	// ShapeFileConvention is an export the framework finds by the file's
	// location: the POST of a Next.js app/**/route.ts.
	ShapeFileConvention Shape = "file_convention"
)

// Root kinds an entry may give, as the callgraph spells them.
const (
	RootKindFrameworkEntry = "framework_entry"
	RootKindMain           = "main"
)

// Path rules of a registration call.
const (
	// PathRequired asks for a path (or method) argument before the handler,
	// so a call such as cache.get(fn) is not a route.
	PathRequired = "required"
	// PathOptional accepts a registration without a path: app.use(fn).
	PathOptional = "optional"
)

// AnyName in names matches every method a supertype entry's type declares
// (every exported one, in Go). AnyPackage in from matches a type from any
// imported package, for generated code such as gRPC servers.
const (
	AnyName    = "*"
	AnyPackage = "*"
)

// shapesByLanguage lists the shapes each language's parser recognizes. A
// catalog entry in any other shape would be silently ignored, so the loader
// rejects it.
var shapesByLanguage = map[string][]Shape{
	"java":   {ShapeDecorator, ShapeSupertype},
	"node":   {ShapeDecorator, ShapeRegistrationCall, ShapeFileConvention},
	"python": {ShapeDecorator, ShapeRegistrationCall, ShapeSupertype},
	"go":     {ShapeRegistrationCall, ShapeHandlerField, ShapeSupertype, ShapeInterfaceMethod, ShapeServerRegistration},
}

// packageSeparator is how each language spells a subpackage, for matching
// from: "flask" covers "flask.views", "github.com/go-chi/chi" covers
// "github.com/go-chi/chi/v5".
var packageSeparator = map[string]string{"java": ".", "python": ".", "node": "/", "go": "/"}

// Entry is one catalog entry.
type Entry struct {
	// Language and Framework name the catalog file the entry comes from; File
	// is its path in the catalog.
	Language, Framework, File string
	Shape                     Shape
	// From lists the packages or modules that bring the framework into
	// scope: a Java package, a Python module, an npm package, a Go import
	// path. A subpackage matches too. For a file convention it is the
	// dependency the nearest manifest must declare.
	From []string
	// Names are the decorator, method, field or export names the shape
	// matches.
	Names []string
	// Types restricts a supertype, handler field or registration to these
	// type names of From ("HttpServlet", "Command"); a pattern may hold one
	// "*". Empty means any type of From (supertype only).
	Types []string
	// Path is PathRequired or PathOptional (registration_call only).
	Path string
	// ParameterTypes are the parameter types an interface method has, each
	// a type of From, as "ResponseWriter" or "*Request" (interface_method
	// only).
	ParameterTypes []string
	// Directory is a path segment the file must be under, and Files the file
	// names without extension it may have (file_convention only; either may
	// be empty). A Python supertype entry may also set Directory.
	Directory string
	Files     []string
	// RootKind is the root kind a matched function gets.
	RootKind string
}

// HasName reports whether the entry names name, or every name. The names of a
// server registration are patterns ("Register*Server").
func (e *Entry) HasName(name string) bool {
	if slices.Contains(e.Names, name) || slices.Contains(e.Names, AnyName) {
		return true
	}
	if e.Shape != ShapeServerRegistration {
		return false
	}
	for _, pattern := range e.Names {
		if ok, err := path.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

// Covers reports whether pkg is one of From or a subpackage of one.
func (e *Entry) Covers(pkg string) bool {
	if pkg == "" {
		return false
	}
	sep := packageSeparator[e.Language]
	for _, from := range e.From {
		if from == AnyPackage || pkg == from || strings.HasPrefix(pkg, from+sep) {
			return true
		}
	}
	return false
}

// HasType reports whether typeName is one of Types, or Types is empty.
func (e *Entry) HasType(typeName string) bool {
	if len(e.Types) == 0 {
		return true
	}
	for _, pattern := range e.Types {
		if ok, err := path.Match(pattern, typeName); err == nil && ok {
			return true
		}
	}
	return false
}

// Catalog is the loaded, validated entry-point catalog.
type Catalog struct {
	entries map[string]map[Shape][]Entry
}

// Entries returns the language's entries of one shape.
func (c *Catalog) Entries(language string, shape Shape) []Entry {
	if c == nil {
		return nil
	}
	return c.entries[language][shape]
}

// Named reports whether any entry of the shape names name. Parsers use it to
// skip the binding work for a call or decorator no framework declares.
func (c *Catalog) Named(language string, shape Shape, name string) bool {
	entries := c.Entries(language, shape)
	for i := range entries {
		if entries[i].HasName(name) {
			return true
		}
	}
	return false
}

// Match returns the first entry of the shape that covers pkg and names name
// (and typeName, when the entry lists types).
func (c *Catalog) Match(language string, shape Shape, pkg, typeName, name string) (Entry, bool) {
	entries := c.Entries(language, shape)
	for i := range entries {
		e := &entries[i]
		if e.HasName(name) && e.Covers(pkg) && e.HasType(typeName) {
			return *e, true
		}
	}
	return Entry{}, false
}

// InDirectory reports whether filePath lies under a directory named Directory,
// or Directory is empty. filePath should be relative to the scanned tree, so
// a directory above the scan root never counts.
func (e *Entry) InDirectory(filePath string) bool {
	if e.Directory == "" {
		return true
	}
	return strings.Contains("/"+filepath.ToSlash(filePath)+"/", "/"+e.Directory+"/")
}

// MatchInFile is Match for an entry that may be restricted to a directory: it
// also requires filePath to lie under the entry's Directory.
func (c *Catalog) MatchInFile(language string, shape Shape, pkg, typeName, name, filePath string) (Entry, bool) {
	entries := c.Entries(language, shape)
	for i := range entries {
		e := &entries[i]
		if e.HasName(name) && e.Covers(pkg) && e.HasType(typeName) && e.InDirectory(filePath) {
			return *e, true
		}
	}
	return Entry{}, false
}

// yamlFile is a catalog file as written.
type yamlFile struct {
	SchemaVersion string        `yaml:"schema_version"`
	Language      string        `yaml:"language"`
	Framework     yamlFramework `yaml:"framework"`
	Entries       []yamlEntry   `yaml:"entries"`
}

type yamlFramework struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type yamlEntry struct {
	Shape          Shape    `yaml:"shape"`
	From           []string `yaml:"from"`
	Names          []string `yaml:"names"`
	Types          []string `yaml:"types"`
	Path           string   `yaml:"path"`
	ParameterTypes []string `yaml:"parameter_types"`
	Directory      string   `yaml:"directory"`
	Files          []string `yaml:"files"`
	RootKind       string   `yaml:"root_kind"`
}

// LoadEmbedded loads the catalog built into the binary.
func LoadEmbedded() (*Catalog, error) {
	return LoadFS(catalogFS)
}

// LoadFS loads every <language>/<framework>.yaml of fsys. A file must be
// valid on its own, its language must match its directory, and no two files
// may declare the same framework or claim the same name: every entry has one
// owner.
func LoadFS(fsys fs.FS) (*Catalog, error) {
	paths, err := fs.Glob(fsys, "*/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("entrypoints: %w", err)
	}
	sort.Strings(paths)
	catalog := &Catalog{entries: make(map[string]map[Shape][]Entry)}
	frameworks := make(map[string]string) // language/framework -> file
	claims := make(map[string]string)     // claim key -> file
	for _, file := range paths {
		data, readErr := fs.ReadFile(fsys, file)
		if readErr != nil {
			return nil, fmt.Errorf("entrypoints: read %s: %w", file, readErr)
		}
		entries, loadErr := Load(file, data)
		if loadErr != nil {
			return nil, loadErr
		}
		if dir := path.Dir(file); len(entries) > 0 && entries[0].Language != dir {
			return nil, fmt.Errorf("entrypoints: %s: language %q does not match its directory %q", file, entries[0].Language, dir)
		}
		if len(entries) > 0 {
			id := entries[0].Language + "/" + entries[0].Framework
			if other, dup := frameworks[id]; dup {
				return nil, fmt.Errorf("entrypoints: framework %q is declared by both %s and %s", id, other, file)
			}
			frameworks[id] = file
		}
		for i := range entries {
			if claimErr := claim(claims, &entries[i]); claimErr != nil {
				return nil, claimErr
			}
			catalog.add(entries[i])
		}
	}
	return catalog, nil
}

func (c *Catalog) add(e Entry) {
	if c.entries[e.Language] == nil {
		c.entries[e.Language] = make(map[Shape][]Entry)
	}
	c.entries[e.Language][e.Shape] = append(c.entries[e.Language][e.Shape], e)
}

// claim records every (shape, package, type, name) an entry matches and
// fails when another entry, in this file or another, already claims one.
func claim(claims map[string]string, e *Entry) error {
	types := e.Types
	if len(types) == 0 {
		types = []string{""}
	}
	scope := e.Directory + "/" + strings.Join(e.Files, ",")
	for _, from := range e.From {
		for _, typeName := range types {
			for _, name := range e.Names {
				key := strings.Join([]string{e.Language, string(e.Shape), from, typeName, scope, name}, "|")
				if other, dup := claims[key]; dup {
					return fmt.Errorf("entrypoints: %s and %s both claim %s %s %q from %q", other, e.File, e.Language, e.Shape, name, from)
				}
				claims[key] = e.File
			}
		}
	}
	return nil
}

// Load parses and validates one catalog file. file names it in errors and in
// the entries.
func Load(file string, data []byte) ([]Entry, error) {
	var raw yamlFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("entrypoints: %s: %w", file, err)
	}
	if err := validateHeader(&raw); err != nil {
		return nil, fmt.Errorf("entrypoints: %s: %w", file, err)
	}
	entries := make([]Entry, 0, len(raw.Entries))
	for i := range raw.Entries {
		entry, err := validateEntry(raw.Language, &raw.Entries[i])
		if err != nil {
			return nil, fmt.Errorf("entrypoints: %s: entries[%d]: %w", file, i, err)
		}
		entry.Framework = raw.Framework.Name
		entry.File = file
		entries = append(entries, entry)
	}
	return entries, nil
}

func validateHeader(raw *yamlFile) error {
	switch {
	case raw.SchemaVersion != SchemaVersion:
		return fmt.Errorf("schema_version must be %q, got %q", SchemaVersion, raw.SchemaVersion)
	case shapesByLanguage[raw.Language] == nil:
		return fmt.Errorf("unsupported language %q", raw.Language)
	case raw.Framework.Name == "":
		return errors.New("framework.name is required")
	case len(raw.Entries) == 0:
		return errors.New("entries must not be empty")
	}
	return nil
}

func validateEntry(language string, raw *yamlEntry) (Entry, error) {
	if !slices.Contains(shapesByLanguage[language], raw.Shape) {
		return Entry{}, fmt.Errorf("shape %q is not recognized for %s", raw.Shape, language)
	}
	if err := validateLists(raw); err != nil {
		return Entry{}, err
	}
	if raw.RootKind != RootKindFrameworkEntry && raw.RootKind != RootKindMain {
		return Entry{}, fmt.Errorf("root_kind must be %q or %q, got %q", RootKindFrameworkEntry, RootKindMain, raw.RootKind)
	}
	if err := validateShapeFields(raw); err != nil {
		return Entry{}, err
	}
	if raw.Shape == ShapeSupertype && raw.Directory != "" && language != "python" {
		return Entry{}, fmt.Errorf("field directory is not read by a %s supertype entry", language)
	}
	entry := Entry{
		Language: language, Shape: raw.Shape, From: raw.From, Names: raw.Names, Types: raw.Types,
		Path: raw.Path, ParameterTypes: raw.ParameterTypes, Directory: raw.Directory, Files: raw.Files,
		RootKind: raw.RootKind,
	}
	if entry.Shape == ShapeRegistrationCall && entry.Path == "" {
		entry.Path = PathRequired
	}
	return entry, nil
}

func validateLists(raw *yamlEntry) error {
	if len(raw.From) == 0 {
		return errors.New("from must name at least one package")
	}
	if len(raw.Names) == 0 {
		return errors.New("names must not be empty")
	}
	for _, list := range [][]string{raw.From, raw.Names, raw.Types, raw.ParameterTypes, raw.Files} {
		for _, value := range list {
			if strings.TrimSpace(value) == "" {
				return errors.New("a list holds an empty value")
			}
		}
	}
	if raw.Shape != ShapeSupertype && raw.Shape != ShapeServerRegistration && (slices.Contains(raw.From, AnyPackage) || slices.Contains(raw.Names, AnyName)) {
		return fmt.Errorf("%q in from or names is only valid for shape %q", AnyName, ShapeSupertype)
	}
	if err := validateNamePatterns(raw); err != nil {
		return err
	}
	for _, pattern := range raw.Types {
		if _, err := path.Match(pattern, ""); err != nil {
			return fmt.Errorf("types pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// validateNamePatterns keeps patterns in the names of a server registration
// only, which must keep a prefix: no other shape matches a name as a pattern.
func validateNamePatterns(raw *yamlEntry) error {
	for _, name := range raw.Names {
		switch {
		case raw.Shape == ShapeServerRegistration && name == AnyName:
			return fmt.Errorf("names of shape %q must be patterns that keep a prefix, not %q", ShapeServerRegistration, AnyName)
		case raw.Shape != ShapeServerRegistration && name != AnyName && strings.ContainsAny(name, "*?["):
			return fmt.Errorf("name %q is a pattern, which only shape %q reads", name, ShapeServerRegistration)
		}
	}
	return nil
}

// validateShapeFields rejects a field the entry's shape does not read, so a
// typo cannot pass as data that silently does nothing.
func validateShapeFields(raw *yamlEntry) error {
	unused := func(field string, set bool, readers ...Shape) error {
		if set && !slices.Contains(readers, raw.Shape) {
			return fmt.Errorf("field %s is not read by shape %q", field, raw.Shape)
		}
		return nil
	}
	return errors.Join(
		unused("path", raw.Path != "", ShapeRegistrationCall),
		unused("parameter_types", len(raw.ParameterTypes) > 0, ShapeInterfaceMethod),
		unused("directory", raw.Directory != "", ShapeFileConvention, ShapeSupertype),
		unused("files", len(raw.Files) > 0, ShapeFileConvention),
		unused("types", len(raw.Types) > 0, ShapeSupertype, ShapeHandlerField),
		validateShapeRequirements(raw),
	)
}

// validateShapeRequirements checks the fields a shape cannot do without.
func validateShapeRequirements(raw *yamlEntry) error {
	var errs []error
	switch {
	case raw.Path != "" && raw.Path != PathRequired && raw.Path != PathOptional:
		errs = append(errs, fmt.Errorf("path must be %q or %q, got %q", PathRequired, PathOptional, raw.Path))
	case raw.Shape == ShapeHandlerField && len(raw.Types) == 0:
		errs = append(errs, errors.New("a handler_field entry must list types"))
	case raw.Shape == ShapeInterfaceMethod && len(raw.ParameterTypes) == 0:
		errs = append(errs, errors.New("an interface_method entry must list parameter_types"))
	case raw.Shape == ShapeFileConvention && raw.Directory == "" && len(raw.Files) == 0:
		errs = append(errs, errors.New("a file_convention entry must set directory or files"))
	}
	return errors.Join(errs...)
}
