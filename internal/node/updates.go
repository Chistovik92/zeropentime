// SPDX-License-Identifier: MPL-2.0

package node

import (
	"context"
	"time"

	"github.com/Chistovik92/zeropentime/internal/update"
)

const (
	updateFirst = time.Minute
	updateEvery = 12 * time.Hour
)

// updateLoop looks for a newer signed release of the update channel and
// tells about it in the log and the status ("zpt update" installs it).
func (n *Node) updateLoop(ctx context.Context) {
	ch := n.opts.Config.UpdateChannelName()
	if ch == "off" {
		return
	}
	t := time.NewTimer(updateFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		r, err := update.Check(cctx, n.opts.Version, ch)
		cancel()
		switch {
		case err != nil:
			n.log.Debug("update check failed", "err", err)
		case r != nil:
			n.mu.Lock()
			seen := n.updateAvail == r.Version
			n.updateAvail = r.Version
			n.mu.Unlock()
			if !seen {
				n.log.Info("a new version is available: zpt update", "version", r.Version, "channel", ch)
			}
		}
		t.Reset(updateEvery)
	}
}
