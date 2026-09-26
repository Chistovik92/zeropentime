// SPDX-License-Identifier: MPL-2.0

//go:build !linux && !windows

package room

import (
	"errors"
	"net/netip"
)

// SetKillSwitch is not available on this OS yet.
func SetKillSwitch(on bool, _ []*Room, _ []netip.Prefix) error {
	if on {
		return errors.New("kill switch is supported on Linux and Windows only for now")
	}
	return nil
}

// DisableKillSwitch does nothing on this OS.
func DisableKillSwitch() {}
