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

// Package rulejson encodes Semgrep/OpenGrep rule files as JSON with the
// meaning OpenGrep's YAML loader gives them. The rules materializer merges
// rule files through it, and the OpenGrep adapter reads rule files through it
// when it feeds opengrep-core directly or prefilters rules.
package rulejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// jsonNumber matches the numbers JSON can spell. A YAML number written any
// other way (0x10, 0o17, 017, 1_000, +5, .5, 1.) has no literal JSON form
// with the value OpenGrep reads, so its file is not encodable.
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$`)

const yamlStrTag = "!!str"

// AppendRuleJSON writes node as JSON with the meaning OpenGrep's YAML parser
// gives it, and reports false for anything it cannot write that way: aliases,
// merge keys, repeated or non-string keys, and tags other than the core ones.
// Numbers keep their literal text, so metadata such as 2.0 reaches OpenGrep
// as written.
func AppendRuleJSON(out *bytes.Buffer, node *yaml.Node) bool {
	switch node.Kind {
	case yaml.MappingNode:
		return appendMappingJSON(out, node)
	case yaml.SequenceNode:
		return appendSequenceJSON(out, node)
	case yaml.ScalarNode:
		return appendScalarJSON(out, node)
	case yaml.DocumentNode, yaml.AliasNode:
		return false
	default:
		return false
	}
}

func appendMappingJSON(out *bytes.Buffer, node *yaml.Node) bool {
	out.WriteByte('{')
	seen := make(map[string]struct{}, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag {
			return false
		}
		if _, dup := seen[key.Value]; dup {
			return false
		}
		seen[key.Value] = struct{}{}
		if i > 0 {
			out.WriteByte(',')
		}
		if !appendJSONString(out, key.Value) {
			return false
		}
		out.WriteByte(':')
		if !AppendRuleJSON(out, node.Content[i+1]) {
			return false
		}
	}
	out.WriteByte('}')
	return true
}

func appendSequenceJSON(out *bytes.Buffer, node *yaml.Node) bool {
	out.WriteByte('[')
	for i, item := range node.Content {
		if i > 0 {
			out.WriteByte(',')
		}
		if !AppendRuleJSON(out, item) {
			return false
		}
	}
	out.WriteByte(']')
	return true
}

func appendScalarJSON(out *bytes.Buffer, node *yaml.Node) bool {
	switch node.ShortTag() {
	case yamlStrTag, "!!timestamp":
		return appendJSONString(out, node.Value)
	case "!!int", "!!float":
		if !jsonNumber.MatchString(node.Value) {
			return false
		}
		out.WriteString(node.Value)
		return true
	case "!!bool":
		switch node.Value {
		case "true", "True", "TRUE":
			out.WriteString("true")
		case "false", "False", "FALSE":
			out.WriteString("false")
		default:
			return false
		}
		return true
	default:
		return false
	}
}

func appendJSONString(out *bytes.Buffer, value string) bool {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return false
	}
	out.Truncate(out.Len() - 1) // Encode ends each value with a newline.
	return true
}

// PlainRulesSequence returns the rules sequence of a file that is one YAML
// document holding nothing but a top-level rules sequence, or nil.
func PlainRulesSequence(data []byte) *yaml.Node {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if decoder.Decode(&doc) != nil || !errors.Is(decoder.Decode(new(yaml.Node)), io.EOF) || len(doc.Content) != 1 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "rules" || root.Content[1].Kind != yaml.SequenceNode {
		return nil
	}
	return root.Content[1]
}

// LoadsAsPlainRuleFile reports whether a scanner walking a rules directory
// loads this file like any other. OpenGrep 1.29 only loads lowercase
// .yaml/.yml names there and skips *.test.* and *.fixed.* fixtures; hidden
// paths are excluded too, so each scanner keeps its own treatment of them.
func LoadsAsPlainRuleFile(relPath string) bool {
	name := filepath.Base(relPath)
	if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
		return false
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	if strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".fixed") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(relPath), "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// MappingValue returns the value of key in a mapping node, or nil when the
// node is not a mapping or the key is absent or repeated.
func MappingValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var value *yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			if value != nil {
				return nil
			}
			value = node.Content[i+1]
		}
	}
	return value
}

// EncodeRules returns one JSON object per rule of a plain rules file, with
// each string id prefixed by idPrefix, or false when the file is not a plain
// rules file or some rule has no JSON spelling OpenGrep reads the same way.
func EncodeRules(data []byte, idPrefix string) ([][]byte, bool) {
	if rules, ok := encodeJSONRules(data, idPrefix); ok {
		return rules, true
	}
	return EncodeYAMLRules(data, idPrefix)
}

// EncodeYAMLRules is EncodeRules without the JSON fast path: every rule is
// re-encoded from its YAML node.
func EncodeYAMLRules(data []byte, idPrefix string) ([][]byte, bool) {
	sequence := PlainRulesSequence(data)
	if sequence == nil {
		return nil, false
	}
	encoded := make([][]byte, 0, len(sequence.Content))
	for _, rule := range sequence.Content {
		id := MappingValue(rule, "id")
		if id == nil || id.Kind != yaml.ScalarNode || id.ShortTag() != yamlStrTag {
			return nil, false
		}
		original := id.Value
		id.Value = idPrefix + original
		var out bytes.Buffer
		ok := AppendRuleJSON(&out, rule)
		id.Value = original
		if !ok {
			return nil, false
		}
		encoded = append(encoded, out.Bytes())
	}
	return encoded, true
}

// encodeJSONRules is the fast path for a file that is already a JSON object
// holding only a rules array of objects with string ids, the shape the
// materializer writes. YAML reads such JSON text the same way, so the rules
// pass through verbatim apart from the id prefix.
func encodeJSONRules(data []byte, idPrefix string) ([][]byte, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var file map[string]json.RawMessage
	if json.Unmarshal(trimmed, &file) != nil || len(file) != 1 {
		return nil, false
	}
	var raw []json.RawMessage
	if json.Unmarshal(file["rules"], &raw) != nil {
		return nil, false
	}
	encoded := make([][]byte, 0, len(raw))
	for _, rule := range raw {
		out, ok := prefixRuleID(rule, idPrefix)
		if !ok {
			return nil, false
		}
		encoded = append(encoded, out)
	}
	return encoded, true
}

// PrefixRuleID returns one JSON rule object with idPrefix put before its
// id, or false for an object with a repeated key or a missing or non-string
// id.
func PrefixRuleID(rule []byte, idPrefix string) ([]byte, bool) {
	return prefixRuleID(rule, idPrefix)
}

// prefixRuleID rewrites the id of one JSON rule object, rejecting objects
// with a repeated key or a missing or non-string id.
func prefixRuleID(rule json.RawMessage, idPrefix string) ([]byte, bool) {
	decoder := json.NewDecoder(bytes.NewReader(rule))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	var out bytes.Buffer
	out.WriteByte('{')
	seen := make(map[string]bool)
	hasID := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return nil, false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		appendJSONString(&out, key)
		out.WriteByte(':')
		if key == "id" {
			var id string
			if json.Unmarshal(value, &id) != nil {
				return nil, false
			}
			hasID = true
			appendJSONString(&out, idPrefix+id)
			continue
		}
		out.Write(value)
	}
	if !hasID {
		return nil, false
	}
	out.WriteByte('}')
	return out.Bytes(), true
}
