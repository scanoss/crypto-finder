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
	"fmt"
	"sync"

	"github.com/scanoss/crypto-finder/internal/callgraph/entrypoints"
)

// Catalog languages, as the entry-point catalog directories name them.
const (
	entryLanguageJava   = "java"
	entryLanguageNode   = "node"
	entryLanguagePython = "python"
	entryLanguageGo     = "go"
)

// entryCatalog is the framework entry-point catalog built into the binary
// (internal/callgraph/entrypoints). It is validated by that package's tests,
// so a failure to load is a build defect, not an input error.
var entryCatalog = sync.OnceValue(func() *entrypoints.Catalog {
	catalog, err := entrypoints.LoadEmbedded()
	if err != nil {
		panic(fmt.Sprintf("callgraph: embedded entry-point catalog: %v", err))
	}
	return catalog
})

// catalogEntryKind is the root kind a matched catalog entry gives.
func catalogEntryKind(entry *entrypoints.Entry) RootKind {
	return RootKind(entry.RootKind)
}
