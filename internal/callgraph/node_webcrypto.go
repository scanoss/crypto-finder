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
	sitter "github.com/smacker/go-tree-sitter"
)

// WebCrypto is a runtime API, not a module: browsers and Node expose it as the
// global `crypto`, and Node also as `require('crypto').webcrypto` and, for
// `subtle` and `getRandomValues`, on the crypto module itself. Every spelling
// names one of two WebIDL interfaces, and calls on them are recorded against
// the interface (`SubtleCrypto.encrypt`, `Crypto.getRandomValues`) so rules
// and contracts key on one name whatever the spelling.
const (
	nodeSubtleCryptoType = "SubtleCrypto"
	nodeCryptoType       = "Crypto"
	// nodeCryptoGlobalName is the global object's name, and the Node module's.
	nodeCryptoGlobalName = "crypto"
	// webCryptoGlobalRoute and webCryptoModuleRoute head the route a receiver
	// takes to WebCrypto: the global crypto object or the Node crypto module.
	webCryptoGlobalRoute = "global"
	webCryptoModuleRoute = "module"
)

// nodeGlobalObjects are the names a script reaches the global object through.
var nodeGlobalObjects = map[string]bool{"globalThis": true, "window": true, "self": true, webCryptoGlobalRoute: true}

// nodeCryptoMethods are the Crypto methods. On the Node crypto module only
// getRandomValues is the WebCrypto one: randomUUID there is the module's own.
var nodeCryptoMethods = map[string]bool{"getRandomValues": true, "randomUUID": true}

// webCryptoScope says how a receiver's root name is bound: through an import,
// or as a declaration of the code being parsed.
type webCryptoScope struct {
	bound    func(name string) (nodeBinding, bool)
	declared func(name string) bool
}

// nodeWebCryptoInterface returns the WebCrypto interface an expression
// evaluates to: SubtleCrypto for `crypto.subtle` and its spellings, Crypto
// for the crypto object.
func nodeWebCryptoInterface(expr *sitter.Node, src []byte, scope webCryptoScope) (string, bool) {
	path, ok := nodeWebCryptoPath(expr, src, scope)
	if !ok {
		return "", false
	}
	switch path {
	case webCryptoGlobalRoute, "global.webcrypto", "module.webcrypto":
		return nodeCryptoType, true
	case "global.subtle", "module.subtle", "module.webcrypto.subtle":
		return nodeSubtleCryptoType, true
	}
	return "", false
}

// nodeWebCryptoCallInterface returns the interface a call `<object>.<method>(..)`
// is made on, when it is a WebCrypto call.
func nodeWebCryptoCallInterface(object *sitter.Node, src []byte, method string, scope webCryptoScope) (string, bool) {
	if iface, ok := nodeWebCryptoInterface(object, src, scope); ok {
		if iface == nodeCryptoType && !nodeCryptoMethods[method] {
			return "", false
		}
		return iface, true
	}
	if path, ok := nodeWebCryptoPath(object, src, scope); ok && path == webCryptoModuleRoute && method == "getRandomValues" {
		return nodeCryptoType, true
	}
	return "", false
}

// nodeWebCryptoPath spells a receiver as the route it takes to WebCrypto:
// "global" for the global crypto object, "module" for the Node crypto module,
// each followed by the properties read from it.
func nodeWebCryptoPath(expr *sitter.Node, src []byte, scope webCryptoScope) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch expr.Type() {
	case goNodeIdentifier:
		return nodeWebCryptoRoot(expr.Content(src), scope)
	case nodeMemberExpression:
		return nodeWebCryptoMemberPath(expr, src, scope)
	}
	return "", false
}

// nodeWebCryptoRoot spells a bare name: an import of the Node crypto module
// or one of its members, or the global crypto object when nothing in scope
// declares the name.
func nodeWebCryptoRoot(name string, scope webCryptoScope) (string, bool) {
	if binding, ok := scope.bound(name); ok {
		if !nodeIsCryptoModule(binding.module) || binding.isDefault && binding.member != "" {
			return "", false
		}
		if binding.member == "" || binding.member == nodeDefaultKeyword {
			return webCryptoModuleRoute, true
		}
		return webCryptoModuleRoute + "." + binding.member, true
	}
	if name == nodeCryptoGlobalName && !scope.declared(name) {
		return webCryptoGlobalRoute, true
	}
	return "", false
}

// nodeWebCryptoMemberPath spells `<object>.<property>`: the global crypto
// object read off globalThis, window, self or global, a member of an inline
// require('crypto'), or a property read from a WebCrypto route.
func nodeWebCryptoMemberPath(expr *sitter.Node, src []byte, scope webCryptoScope) (string, bool) {
	object := expr.ChildByFieldName("object")
	property := expr.ChildByFieldName("property")
	if object == nil || property == nil {
		return "", false
	}
	name := property.Content(src)
	switch object.Type() {
	case goNodeIdentifier:
		if global := object.Content(src); nodeGlobalObjects[global] && !scope.declared(global) {
			if _, bound := scope.bound(global); bound || name != nodeCryptoGlobalName {
				return "", false
			}
			return webCryptoGlobalRoute, true
		}
	case nodeCallExpression:
		binding, ok := nodeRequireBinding(object, src)
		if !ok || binding.member != "" || !nodeIsCryptoModule(binding.module) {
			return "", false
		}
		return webCryptoModuleRoute + "." + name, true
	}
	base, ok := nodeWebCryptoPath(object, src, scope)
	if !ok {
		return "", false
	}
	return base + "." + name, true
}

func nodeIsCryptoModule(module string) bool {
	return module == nodeCryptoGlobalName || module == "node:crypto"
}
