// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"sync"
)

// hub wakes long-polling nodes when the global version changes.
type hub struct {
	mu      sync.Mutex
	version int64
	changed chan struct{}
}

func newHub(v int64) *hub { return &hub{version: v, changed: make(chan struct{})} }

func (h *hub) set(v int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if v > h.version {
		h.version = v
		close(h.changed)
		h.changed = make(chan struct{})
	}
}

// wait blocks until the version is above since or ctx ends.
func (h *hub) wait(ctx context.Context, since int64) {
	h.mu.Lock()
	// Newer data, or a node ahead of us (controller restored from a backup):
	// answer at once.
	if h.version != since {
		h.mu.Unlock()
		return
	}
	ch := h.changed
	h.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
	}
}
