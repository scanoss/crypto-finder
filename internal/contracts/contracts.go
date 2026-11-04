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

// Package contracts embeds crypto-finder's contracts knowledge base (KB): the
// per-ecosystem YAML files that tell the static-engine call graph which
// library calls produce crypto objects and what they return. The engine ships
// no contracts; RegisterAll hands these to it.
package contracts

import (
	"embed"
	"sync"

	secontracts "github.com/scanoss/static-engine/callgraph/contracts"
)

//go:embed c/*.yaml cpp/*.yaml go/*.yaml java/*.yaml node/*.yaml python/*.yaml rust/*.yaml
var kbFS embed.FS

// Ecosystems lists the ecosystems the embedded KB covers. Each one's YAML
// files live in the directory of the same name.
var Ecosystems = []string{"c", "cpp", "go", "java", "node", "python", "rust"}

var registerOnce sync.Once

// RegisterAll registers the embedded KB of every ecosystem with the engine.
// It runs once per process; later calls do nothing.
func RegisterAll() {
	registerOnce.Do(func() {
		for _, eco := range Ecosystems {
			secontracts.Register(eco, kbFS, eco)
		}
	})
}
