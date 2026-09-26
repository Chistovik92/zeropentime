// SPDX-License-Identifier: MPL-2.0

package room

import (
	"errors"
	"net/netip"
)

var errNoRouter = errors.New("subnet router mode is supported on Linux only for now (an exit node works everywhere)")

func enableRouter(string, netip.Prefix, []netip.Prefix, bool, int, int) error { return errNoRouter }
func disableRouter(string)                                                    {}
