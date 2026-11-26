// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"regexp"
	"sort"
	"strings"

	"github.com/scanoss/reach/graphfrag"
)

// Go values (graph-fragment-1.34, go-port audit E3): a rule written as a
// composite literal (`tls.Config{..., MinVersion: $V, ...}`, `&T{...}`), a
// `new(T)` or a field store (`$C.CipherSuites = $V`) matches the fragment's
// go_values. Each value is read as a call of a pseudo-method on its type, its
// fields as keyword arguments, so the rule compiles and matches as a call
// pattern does: metavariables, regexes and metadata work unchanged.

// Pseudo-methods of Go value sites and entries.
const (
	goValueComposite = "{}"  // T{...}
	goValueNew       = "new" // new(T)
	goValueStorePfx  = "="   // x.F = v is method "=F"
	siteGoValue      = "go_value"
	// Kinds of a go_values fact.
	goFactComposite = "composite"
	goFactNew       = "new"
	goFactStore     = "store"
	goFactAssign    = "assign" // graph-fragment-1.36: read by go_flow.go, no site
)

var (
	rxGoComposite = regexp.MustCompile(`(?s)^(&)?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\{(.*)\}$`)
	rxGoNew       = regexp.MustCompile(`^new\(\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\)$`)
	rxGoStore     = regexp.MustCompile(`^(\$[A-Z_0-9]+|\(\s*\$[A-Z_0-9]+\s*:\s*\*?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\))\.([A-Za-z_]\w*)\s*=\s*(.+)$`)
)

// parseGoValuePattern compiles a Go value pattern into a call-shaped sink;
// ok is false for any other pattern.
func parseGoValuePattern(text string) (*OMap, bool, error) {
	text = strings.TrimSpace(text)
	if m := rxGoNew.FindStringSubmatch(text); m != nil {
		call := goValueCall(strType, m[1], goValueNew)
		call.Set("args", []any{})
		call.Set("min_arity", int64(0))
		call.Set("max_arity", int64(0))
		return call, true, nil
	}
	if m := rxGoStore.FindStringSubmatch(text); m != nil {
		call, err := parseGoStore(m)
		return call, true, err
	}
	if m := rxGoComposite.FindStringSubmatch(text); m != nil {
		call, err := parseGoComposite(m)
		return call, true, err
	}
	return nil, false, nil
}

// parseGoStore compiles `$C.F = v` or `($C : *T).F = v` (rxGoStore groups).
func parseGoStore(m []string) (*OMap, error) {
	receiver, typ := strAny, any(nil)
	if m[2] != "" {
		receiver, typ = strTypedMetavar, m[2]
	}
	call := goValueCall(receiver, typ, goValueStorePfx+m[3])
	a, err := parseArg(strings.TrimSpace(m[4]))
	if err != nil {
		return nil, err
	}
	if getString(a, "kind") == strEllipsis {
		return nil, skip("Go store of `...`")
	}
	a.Set("index", int64(0))
	call.Set("args", []any{a})
	call.Set("min_arity", int64(1))
	call.Set("max_arity", int64(1))
	return call, nil
}

// parseGoComposite compiles `T{...}` or `&T{...}` (rxGoComposite groups): a
// `Name: v` element is a keyword argument, a bare one positional.
func parseGoComposite(m []string) (*OMap, error) {
	call := goValueCall(strType, m[2], goValueComposite)
	if m[1] != "" {
		call.Set("go_addr", true)
	}
	args := []any{}
	ellipsis, positional := false, 0
	for _, item := range splitArgs(m[3]) {
		item = strings.TrimSpace(item)
		switch item {
		case "":
			continue
		case jsEllipsis:
			ellipsis = true
			continue
		}
		var index any = int64(positional)
		value := item
		if k, v, ok := strings.Cut(item, ":"); ok && rxGoFieldName.MatchString(strings.TrimSpace(k)) {
			index, value = pyKeywordIndex(strings.TrimSpace(k)), strings.TrimSpace(v)
		} else {
			if ellipsis {
				return nil, skip("argument after an ellipsis (index not fixed)")
			}
			positional++
		}
		a, err := parseArg(value)
		if err != nil {
			return nil, err
		}
		a.Set("index", index)
		args = append(args, a)
	}
	call.Set("args", args)
	call.Set("min_arity", int64(len(args)))
	if ellipsis {
		call.Set("max_arity", nil)
	} else {
		call.Set("max_arity", int64(len(args)))
	}
	return call, nil
}

var rxGoFieldName = regexp.MustCompile(`^[A-Za-z_]\w*$`)

func goValueCall(receiver string, typ any, method string) *OMap {
	call := omap("receiver", receiver, strType, typ, "method", method)
	call.Set("method_regex", nil)
	return call
}

// goValueSites reads a Go fragment's go_values as sites, numbered from first.
func goValueSites(frag *FragmentJSON, first int) []*Site {
	files := make([]string, 0, len(frag.GoValues))
	for file := range frag.GoValues {
		files = append(files, file)
	}
	sort.Strings(files)
	var out []*Site
	for _, file := range files {
		for i := range frag.GoValues[file] {
			if frag.GoValues[file][i].Kind == goFactAssign {
				continue
			}
			s := goValueSite(file, &frag.GoValues[file][i])
			s.ID = first + len(out)
			out = append(out, s)
		}
	}
	return out
}

func goValueSite(file string, v *graphfrag.GraphFragmentGoValue) *Site {
	s := &Site{
		File: file, Line: v.Line, LineOK: true, Col: v.StartCol, ColOK: true, EndCol: v.EndCol, EndLine: v.EndLine,
		Caller: v.Function, Kind: siteGoValue, Go: true, GoValue: true, GoAddrCol: v.AddrCol,
		Raw: v.TypeText, Params: map[int]*Param{},
	}
	if v.Package != "" {
		s.Class = v.Package + "." + strings.TrimPrefix(v.Type, "*")
	}
	switch v.Kind {
	case goFactComposite:
		s.Method = goValueComposite
	case goFactNew:
		// OpenGrep reports `new(T)` from its parenthesis.
		s.Method, s.Col = goValueNew, v.StartCol+len(goValueNew)
	case goFactStore:
		s.ReceiverVar = v.Receiver
		if len(v.Fields) == 1 {
			s.Method = goValueStorePfx + v.Fields[0].Name
		}
	}
	positional := 0
	for _, f := range v.Fields {
		p := &Param{ArgumentExpression: f.Value}
		idx := positional
		switch {
		case v.Kind == goFactStore:
			idx = 0
		case f.Name != "":
			idx, p.Keyword = kwKey(f.Name), f.Name
		default:
			positional++
		}
		p.ParameterIndex = idx
		s.Params[idx] = p
		s.ParamOrder = append(s.ParamOrder, idx)
	}
	s.ParamIdx = append([]int(nil), s.ParamOrder...)
	sort.Ints(s.ParamIdx)
	s.Arity = len(v.Fields)
	return s
}

// goValueHolds is the Go value checks of an entry on a site: a value entry
// matches value sites of its kind only, a `&T{...}` entry a literal written
// with its `&`, and a field the entry names must be written.
func goValueHolds(e *Entry, s *Site) bool {
	if !s.GoValue {
		return true
	}
	if e.GoAddr && s.GoAddrCol == 0 {
		return false
	}
	for i := range e.Args {
		if a := &e.Args[i]; a.Kind != strEllipsis && a.param(s.Params) == nil {
			return false
		}
	}
	return true
}
