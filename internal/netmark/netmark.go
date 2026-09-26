// SPDX-License-Identifier: MPL-2.0

// Package netmark marks the node's own sockets (the tunnel socket, the
// controller connection, VLESS, DNS lookups) so that they keep using the
// ordinary routes while the rest of the machine's traffic goes into a room
// through an exit node. Only Linux uses marks; elsewhere this is a no-op.
package netmark

import (
	"net"
	"syscall"
)

// Mark is the firewall mark of the node's own packets ("zp").
const Mark = 0x7a70

// Control is a net.Dialer / net.ListenConfig Control function that marks
// the socket. Failing to mark (no CAP_NET_ADMIN) is not an error: such a
// node cannot route through an exit anyway.
func Control(_, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) { mark(fd) })
}

// Dialer returns a dialer whose connections and DNS lookups are marked.
func Dialer() *net.Dialer {
	return &net.Dialer{Control: Control, Resolver: resolver}
}

var resolver = &net.Resolver{PreferGo: true, Dial: (&net.Dialer{Control: Control}).DialContext}

// Install makes the default resolver's DNS lookups marked as well, so
// names resolve without going through the exit.
func Install() {
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = (&net.Dialer{Control: Control}).DialContext
}
