// SPDX-License-Identifier: MPL-2.0

// Package netcheck finds out how this node is seen from the internet: its
// external address and the kind of NAT in front of it.
package netcheck

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// NAT types, as reported to the controller and shown in the panel.
const (
	// NATNone: the node has a public address, nothing is translated.
	NATNone = "none"
	// NATCone: the external address is the same for every destination
	// (endpoint-independent mapping); hole punching works.
	NATCone = "cone"
	// NATSymmetric: every destination gets a different external port;
	// direct connections usually need a relay.
	NATSymmetric = "symmetric"
	// NATBlocked: no STUN server answered — outgoing UDP seems blocked.
	NATBlocked = "udp-blocked"
	// NATUnknown: not enough answers to tell.
	NATUnknown = "unknown"
)

// STUNer asks a STUN server for this node's external address.
type STUNer interface {
	STUN(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error)
}

// Report is the result of a check.
type Report struct {
	NAT string
	// Mapped are the distinct external addresses seen by STUN servers.
	Mapped []netip.AddrPort
}

// Timeout bounds one check.
var Timeout = 3 * time.Second

// Resolve turns "host:port" strings into addresses, skipping bad ones.
func Resolve(ctx context.Context, servers []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range servers {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap)
			continue
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			continue
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			continue
		}
		if ap, err := netip.ParseAddrPort(net.JoinHostPort(ips[0].Unmap().String(), port)); err == nil {
			out = append(out, ap)
		}
	}
	return out
}

// Check asks every server in parallel and classifies the NAT. localPort is
// the port of the socket the STUNer uses; localAddrs are this machine's IPs.
func Check(ctx context.Context, s STUNer, servers []netip.AddrPort, localPort uint16, localAddrs []netip.Addr) Report {
	if len(servers) == 0 {
		return Report{NAT: NATUnknown}
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	type answer struct {
		server, mapped netip.AddrPort
	}
	var mu sync.Mutex
	var answers []answer
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m, err := s.STUN(ctx, srv); err == nil {
				mu.Lock()
				answers = append(answers, answer{srv, m})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	r := Report{NAT: NATUnknown}
	if len(answers) == 0 {
		r.NAT = NATBlocked
		return r
	}
	for _, a := range answers {
		if !slices.Contains(r.Mapped, a.mapped) {
			r.Mapped = append(r.Mapped, a.mapped)
		}
	}
	slices.SortFunc(r.Mapped, func(a, b netip.AddrPort) int { return a.Compare(b) })

	first := answers[0].mapped
	if first.Port() == localPort && slices.Contains(localAddrs, first.Addr()) {
		r.NAT = NATNone
		return r
	}
	if len(r.Mapped) > 1 {
		r.NAT = NATSymmetric
		return r
	}
	distinctServers := map[netip.AddrPort]bool{}
	for _, a := range answers {
		distinctServers[a.server] = true
	}
	if len(distinctServers) > 1 {
		r.NAT = NATCone
	}
	return r
}

// LocalAddrs lists the IP addresses of this machine's interfaces.
func LocalAddrs() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}
