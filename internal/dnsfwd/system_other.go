// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package dnsfwd

import "net/netip"

// SystemResolvers are the name servers of /etc/resolv.conf.
func SystemResolvers() []netip.AddrPort { return SystemUpstreams("/etc/resolv.conf") }
