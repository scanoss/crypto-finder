// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"hash/maphash"
	"sync"
)

const exportMemoShards = 64

// exportMemo memoizes a pure function of a string key. The forks of an export
// context that build edges concurrently (forEachFragmentEdges) share their
// memos, so a lookup or a store locks only the shard of its key. A nil
// exportMemo memoizes nothing.
type exportMemo[V any] struct {
	seed   maphash.Seed
	shards [exportMemoShards]exportMemoShard[V]
}

type exportMemoShard[V any] struct {
	mu     sync.Mutex
	values map[string]V
}

func newExportMemo[V any]() *exportMemo[V] {
	return &exportMemo[V]{seed: maphash.MakeSeed()}
}

func (m *exportMemo[V]) shard(key string) *exportMemoShard[V] {
	return &m.shards[maphash.String(m.seed, key)%exportMemoShards]
}

// lookup returns the value memoized for key.
func (m *exportMemo[V]) lookup(key string) (V, bool) {
	if m == nil {
		var zero V
		return zero, false
	}
	s := m.shard(key)
	s.mu.Lock()
	value, ok := s.values[key]
	s.mu.Unlock()
	return value, ok
}

// store memoizes value for key and returns the value memoized for key: value,
// or the one another goroutine stored first, which is equal since the
// memoized function is pure.
func (m *exportMemo[V]) store(key string, value V) V {
	if m == nil {
		return value
	}
	s := m.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.values[key]; ok {
		return stored
	}
	if s.values == nil {
		s.values = make(map[string]V)
	}
	s.values[key] = value
	return value
}
