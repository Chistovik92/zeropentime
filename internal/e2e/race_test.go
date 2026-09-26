// SPDX-License-Identifier: AGPL-3.0-only

//go:build race

package e2e

// raceSlowdown stretches waits: the race detector slows everything down
// several times, more on small CI machines.
const raceSlowdown = 3
