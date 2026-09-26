// SPDX-License-Identifier: MPL-2.0

package room

import (
	"errors"
	"net/netip"
)

var errNoRouter = errors.New("subnet router and exit node modes are supported on Linux only for now")

func enableRouter(string, netip.Prefix, []netip.Prefix, bool) error { return errNoRouter }
func disableRouter(string)                                          {}
