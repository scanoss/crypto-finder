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

package rules

import (
	"crypto/sha256"
	"reflect"
	"slices"
	"sync"

	"go.yaml.in/yaml/v3"
)

// Documents lets several passes over one ruleset share one YAML parse per rule
// file. It is created with the views its consumers decode: the first Decode of
// a file's bytes parses them once and decodes every view, and later Decodes of
// the same bytes reuse the decoded views. Only the views are kept, never the
// YAML node tree, so a whole ruleset costs little memory.
//
// A consumer must treat a decoded view as read-only: the next consumer of the
// same file receives the same slices and maps. A nil *Documents, or a view
// that was not registered, parses on every call.
type Documents struct {
	views []reflect.Type
	mu    sync.Mutex
	files map[string]*parsedRuleFile
}

type parsedRuleFile struct {
	digest [sha256.Size]byte
	// parseErr is the YAML syntax error; views are not decoded then.
	parseErr error
	values   []reflect.Value
	errs     []error
}

// NewDocuments returns a Documents that decodes the given views. Each view is
// a pointer to the zero value of the type a consumer decodes into, for example
// new(ruleFile).
func NewDocuments(views ...any) *Documents {
	types := make([]reflect.Type, 0, len(views))
	for _, view := range views {
		types = append(types, reflect.TypeOf(view))
	}
	return &Documents{views: types, files: make(map[string]*parsedRuleFile)}
}

// Decode decodes data, the current bytes of the rule file at path, into out,
// which must point to a zero value. The result and the error are those of
// yaml.Unmarshal(data, out): a parse error leaves out unchanged, and a type
// error still fills what decoded.
func (d *Documents) Decode(path string, data []byte, out any) error {
	view := -1
	if d != nil {
		view = slices.Index(d.views, reflect.TypeOf(out))
	}
	if view < 0 {
		return yaml.Unmarshal(data, out)
	}
	digest := sha256.Sum256(data)
	d.mu.Lock()
	parsed := d.files[path]
	d.mu.Unlock()
	if parsed == nil || parsed.digest != digest {
		parsed = d.parse(data, digest)
		d.mu.Lock()
		d.files[path] = parsed
		d.mu.Unlock()
	}
	if parsed.parseErr != nil {
		return parsed.parseErr
	}
	reflect.ValueOf(out).Elem().Set(parsed.values[view])
	return parsed.errs[view]
}

// parse parses data once and decodes every view from the node tree, with the
// same decoder yaml.Unmarshal runs after its own parse.
func (d *Documents) parse(data []byte, digest [sha256.Size]byte) *parsedRuleFile {
	parsed := &parsedRuleFile{digest: digest}
	var document yaml.Node
	if parsed.parseErr = yaml.Unmarshal(data, &document); parsed.parseErr != nil {
		return parsed
	}
	parsed.values = make([]reflect.Value, len(d.views))
	parsed.errs = make([]error, len(d.views))
	for i, view := range d.views {
		value := reflect.New(view.Elem())
		// An empty stream has no document: yaml.Unmarshal leaves out zero.
		if document.Kind != 0 {
			parsed.errs[i] = document.Decode(value.Interface())
		}
		parsed.values[i] = value.Elem()
	}
	return parsed
}
