// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "strings"

// RuntimeSourceKind names the kind of input a program reads when it runs.
type RuntimeSourceKind string

// The runtime inputs a value can be read from.
const (
	// RuntimeSourceEnv is an environment variable, keyed by its name.
	RuntimeSourceEnv RuntimeSourceKind = "env"
	// RuntimeSourceArgv is a program argument, keyed by the index the program
	// reads it at, as written in source.
	RuntimeSourceArgv RuntimeSourceKind = "argv"
	// RuntimeSourceProperty is a system or configuration property, keyed by
	// its name.
	RuntimeSourceProperty RuntimeSourceKind = "property"
)

// RuntimeSource is the input a source node's value is read from at run time.
// Key is empty when the source does not pin it.
type RuntimeSource struct {
	Kind RuntimeSourceKind
	Key  string
}

// runtimeRef marks a source node whose value is a runtime input. Its value is
// unknown however literal the node's children look: they are the key, or a
// default that the input overrides. keyRef names a constant the key may be,
// for the post-parse fold.
type runtimeRef struct {
	kind   RuntimeSourceKind
	key    string
	keyRef *nameRef
}

// RuntimeSource reports whether the node's value is read from a runtime input,
// and which one.
func (n *SourceNode) RuntimeSource() (RuntimeSource, bool) {
	if n.runtime == nil {
		return RuntimeSource{}, false
	}
	return RuntimeSource{Kind: n.runtime.kind, Key: n.runtime.key}, true
}

// newRuntimeRef marks a read of kind keyed by the value keySources pin: a
// literal, a local or constant bound to one, or a name the fold may resolve.
func newRuntimeRef(kind RuntimeSourceKind, keySources []SourceNode) *runtimeRef {
	ref := &runtimeRef{kind: kind}
	for len(keySources) == 1 {
		node := keySources[0]
		if node.nameRef != nil {
			ref.keyRef = node.nameRef
			return ref
		}
		if node.Type == sourceNodeValue {
			ref.key = runtimeKey(kind, node.Value)
			return ref
		}
		if node.Type != sourceNodeVariable && node.Type != sourceNodeField {
			return ref
		}
		keySources = node.SourceNodes
	}
	return ref
}

// runtimeKey is the key literal denotes for kind: the text of a plain string
// for a name, a decimal integer for an argument index, and "" otherwise.
func runtimeKey(kind RuntimeSourceKind, literal string) string {
	literal = strings.TrimSpace(literal)
	if kind == RuntimeSourceArgv {
		if literal == "" || strings.Trim(literal, "0123456789") != "" {
			return ""
		}
		return literal
	}
	if len(literal) < 2 || literal[0] != literal[len(literal)-1] || !strings.ContainsRune("\"'`", rune(literal[0])) {
		return ""
	}
	key := literal[1 : len(literal)-1]
	if strings.ContainsAny(key, "\\\"'`") || strings.Contains(key, "${") {
		return ""
	}
	return key
}

// resolveKey settles a key left to a constant of another file.
func (r *runtimeRef) resolveKey(values map[string]NamedValue) {
	if r == nil || r.keyRef == nil {
		return
	}
	if value, ok := resolveNamedValue(values, r.keyRef, 0, nil); ok {
		r.key = runtimeKey(r.kind, value.Value)
	}
	r.keyRef = nil
}
