// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package offline

import (
	"context"
	"sync"
)

// budget is a memory budget shared by the dependencies mined at once: a
// dependency waits until its estimate fits beside the others'. One estimate
// larger than the whole budget is capped by the caller, so it runs alone.
type budget struct {
	mu    sync.Mutex
	cond  *sync.Cond
	free  int64
	total int64
}

func newBudget(total int64) *budget {
	b := &budget{free: total, total: total}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// acquire takes n bytes of the budget, waiting for them; it fails when ctx
// ends first.
func (b *budget) acquire(ctx context.Context, n int64) error {
	stop := context.AfterFunc(ctx, func() {
		b.mu.Lock()
		b.cond.Broadcast()
		b.mu.Unlock()
	})
	defer stop()
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.free < n {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.cond.Wait()
	}
	b.free -= n
	return nil
}

func (b *budget) release(n int64) {
	b.mu.Lock()
	b.free += n
	b.mu.Unlock()
	b.cond.Broadcast()
}
