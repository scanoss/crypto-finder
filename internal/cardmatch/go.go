// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"regexp"
	"strings"
)

// Go mode of the matcher. A Go fragment keys a function `pkg/path.Func` and a
// method `pkg/path.(T).M` or `pkg/path.(*T).M`, with no arity. A site's class
// is the package of a function and the qualified type of a method, so a
// compiled callee type (an import path, or a path and a type) is compared
// with it exactly: `crypto/cipher` never matches `golang.org/x/crypto/cipher`.

const ecosystemGo = "go"

// golang: the fragment is read in Go mode.
func (f *FragmentJSON) golang() bool {
	return f.ScanMetadata.Ecosystem == ecosystemGo
}

// goParseKey splits a Go function key into its class and method.
func goParseKey(key string) (string, string, bool) {
	if i := strings.LastIndex(key, ")."); i > 0 {
		open := strings.LastIndex(key[:i], ".(")
		if open <= 0 {
			return "", "", false
		}
		typ := strings.TrimLeft(key[open+2:i], "*")
		return key[:open] + "." + typ, key[i+2:], true
	}
	slash := strings.LastIndexByte(key, '/')
	dot := strings.LastIndexByte(key, '.')
	if dot <= slash || dot == len(key)-1 {
		return "", "", false
	}
	return key[:dot], key[dot+1:], true
}

// goSite fills a Go site's class, method and arguments from its target key
// and call-site entry. A Go edge carries no arity: the arguments count it.
func goSite(s *Site, key string, entry *CallSiteJSON) {
	s.Go, s.GoCallee = true, key
	if cls, method, ok := goParseKey(key); ok {
		s.Class = cls
		if s.Method == "" {
			s.Method = method
		}
	}
	s.Params, s.ParamIdx, s.ParamOrder = paramMap(entry)
	if s.Arity == 0 && len(s.ParamIdx) > 0 {
		s.Arity = s.ParamIdx[len(s.ParamIdx)-1] + 1
	}
}

// goShortClass writes a Go class with its package's name instead of its path
// (`crypto/rsa` -> `rsa`, `crypto/tls.Config` -> `tls.Config`), as a rule
// that names no import spells it.
func goShortClass(cls string) string {
	slash := strings.LastIndexByte(cls, '/')
	last := cls[slash+1:]
	skip := 0
	if strings.HasPrefix(cls, "gopkg.in/") {
		// The element itself may hold a dot: `lib.v2`, `lib.v2.Type`.
		if m := rxGopkgVersion.FindStringIndex(last); m != nil {
			skip = m[1]
		}
	}
	pkg, typ := cls, ""
	if dot := strings.IndexByte(last[skip:], '.'); dot >= 0 {
		pkg, typ = cls[:slash+1+skip+dot], cls[slash+1+skip+dot:]
	}
	return goImplicitImportName(pkg) + typ
}

var rxGopkgVersion = regexp.MustCompile(`\.v\d+`)

// goConstMatch matches a Go constant reference, written with its import path
// (`crypto/tls.VersionTLS13`), exactly as pyConstMatch does a Python one: the
// card's const is the package path, member a regex on the name.
func goConstMatch(pat *OMap, text string) Groups {
	i := strings.LastIndexByte(text, '.')
	if i <= 0 {
		return nil
	}
	owner, name := text[:i], text[i+1:]
	consts := asList(pat.GetOr("const"))
	if member, ok := pat.Get("member"); ok {
		g := memoMatch(mustStr(member, "member"), name)
		if g == nil {
			return nil
		}
		for _, c := range consts {
			if mustStr(c, "const") == owner {
				return g
			}
		}
		return nil
	}
	for _, c := range consts {
		if mustStr(c, "const") == text {
			return Groups{}
		}
	}
	return nil
}

// goQualifiedRef writes a value as written (`dsa.L2048N256`) with its import
// path, read from the constant reference the fragment records for it on the
// value's line (`crypto/dsa.L2048N256`); the text itself when there is not
// exactly one.
func (fr *Frag) goQualifiedRef(val Val, text string) string {
	text = norm(text)
	dot := strings.LastIndexByte(text, '.')
	if dot <= 0 || !val.LineOK {
		return text
	}
	suffix := text[dot:]
	found := ""
	for _, r := range fr.RefsByCaller[val.Caller] {
		if r.Line != val.Line || !strings.HasSuffix(r.Raw, suffix) || goShortClass(r.Raw[:len(r.Raw)-len(suffix)])+suffix != text {
			continue
		}
		if found != "" && found != r.Raw {
			return text
		}
		found = r.Raw
	}
	if found == "" {
		return text
	}
	return found
}

// goImportAliases reads a Go fragment's import specs (graph-fragment-1.32)
// into the names each file's aliased imports bind; ok is false for an older
// fragment, which lists none.
func goImportAliases(frag *FragmentJSON) (bool, map[string]map[string]string) {
	if frag.schemaMinor() < 32 {
		return false, nil
	}
	out := make(map[string]map[string]string, len(frag.Imports))
	for file, imports := range frag.Imports {
		for _, imp := range imports {
			if imp.Alias == "" || imp.Alias == "." || imp.Alias == "_" {
				continue
			}
			if out[file] == nil {
				out[file] = map[string]string{}
			}
			out[file][imp.Alias] = imp.Module
		}
	}
	return true, out
}

// goAliasedCall: the call's qualifier (`x` of `x.New(..)`) is an alias the
// call's file binds to the entry's path, as OpenGrep's `import $P "p"`
// requires. A fragment without import specs cannot tell, and keeps the call.
func goAliasedCall(e *Entry, s *Site, fr *Frag) bool {
	if fr == nil || !fr.GoImports {
		return true
	}
	dot := strings.IndexByte(s.Src, '.')
	if dot <= 0 {
		return false
	}
	return fr.GoAliases[s.File][strings.TrimSpace(s.Src[:dot])] == e.GoAliasOf
}

// goImportPaths is, by file, the paths a Go fragment's files import
// (graph-fragment-1.32); nil for an older fragment.
func goImportPaths(frag *FragmentJSON) map[string]map[string]bool {
	if frag.schemaMinor() < 32 {
		return nil
	}
	out := make(map[string]map[string]bool, len(frag.Imports))
	for file, imports := range frag.Imports {
		for _, imp := range imports {
			addSet(out, file, imp.Module)
		}
	}
	return out
}

// goFileImports: the site's file imports the entry's path. A fragment without
// import specs cannot tell, and keeps the site.
func goFileImports(e *Entry, s *Site, fr *Frag) bool {
	if fr == nil || !fr.GoImports {
		return true
	}
	return fr.GoImportPaths[s.File][e.GoFileImports]
}
