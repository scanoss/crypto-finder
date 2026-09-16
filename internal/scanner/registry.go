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

//revive:disable:var-naming // scanner is a domain package name and intentionally matches CLI/config terminology.
package scanner

import (
	"fmt"
	"sort"
	"sync"
)

// Registry manages available scanners and provides a factory for retrieving
// scanner instances by name.
//
// The registry is thread-safe and allows dynamic registration of scanners.
// Use RegisterFactory for adapters with invocation-specific initialization state.
type Registry struct {
	mu        sync.RWMutex
	scanners  map[string]Scanner
	factories map[string]func() Scanner
}

// NewRegistry creates a new scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners:  make(map[string]Scanner),
		factories: make(map[string]func() Scanner),
	}
}

// Register adds a scanner to the registry with the given name.
// If a scanner with the same name already exists, it will be replaced.
//
// Example:
//
//	registry := NewRegistry()
//	registry.Register("semgrep", semgrep.NewScanner())
func (r *Registry) Register(name string, scanner Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[name] = scanner
	delete(r.factories, name)
}

// RegisterFactory adds a constructor that Get invokes for each scanner invocation.
// The constructor must return a fresh adapter. Replaces any registration of name.
// Use Register instead for callers that explicitly manage a shared adapter's lifetime.
func (r *Registry) RegisterFactory(name string, factory func() Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[name] = nil
	r.factories[name] = factory
}

// Get retrieves a scanner by name. Factory registrations return a fresh adapter.
// Returns an error if the scanner is not found.
//
// Example:
//
//	scanner, err := registry.Get("semgrep")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (r *Registry) Get(name string) (Scanner, error) {
	r.mu.RLock()

	scanner, exists := r.scanners[name]
	if !exists {
		names := r.available()
		r.mu.RUnlock()
		return nil, fmt.Errorf("scanner '%s' not found (available scanners: %v)", name, names)
	}

	factory := r.factories[name]
	r.mu.RUnlock()
	if factory != nil {
		return factory(), nil
	}
	return scanner, nil
}

// available is an internal helper that returns available scanner names.
// Caller must hold read lock.
func (r *Registry) available() []string {
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
