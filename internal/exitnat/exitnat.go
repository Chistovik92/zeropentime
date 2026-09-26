// SPDX-License-Identifier: MPL-2.0

// Package exitnat is an exit node without the OS doing NAT: the room's
// packets to the internet enter a gVisor network stack, which terminates
// their TCP connections and UDP flows, and the exit opens ordinary sockets
// to the real destinations. It works wherever Go runs (Windows has no
// usable NAT for this), and it enforces speed limits per client and in
// total. ICMP (ping) through such an exit is not supported.
package exitnat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID       = 1
	dialTimeout = 10 * time.Second
	udpIdle     = time.Minute
	maxConns    = 4096
	chunk       = 16 << 10
)

// Options configure a NAT.
type Options struct {
	MTU int
	// Allow decides whether a destination may be reached (nil: all).
	Allow func(netip.Addr) bool
	// PerClient and Total limit throughput in bytes per second, in each
	// direction separately (0: no limit).
	PerClient, Total int
	Dial             func(ctx context.Context, network, addr string) (net.Conn, error)
	Log              *slog.Logger
}

// NAT forwards a room's internet traffic through this machine's sockets.
type NAT struct {
	o     Options
	out   func([]byte)
	stack *stack.Stack
	ep    *channel.Endpoint
	total [2]*rate.Limiter // up (to the internet), down

	mu      sync.Mutex
	clients map[netip.Addr]*[2]*rate.Limiter
	conns   map[io.Closer]struct{}
	closed  bool
}

// New starts a NAT; out receives the packets for the room.
func New(out func(pkt []byte), o Options) (*NAT, error) {
	if o.MTU == 0 {
		o.MTU = 1280
	}
	if o.Dial == nil {
		var d net.Dialer
		o.Dial = d.DialContext
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	n := &NAT{
		o: o, out: out,
		ep: channel.New(1024, uint32(o.MTU), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		}),
		clients: map[netip.Addr]*[2]*rate.Limiter{},
		conns:   map[io.Closer]struct{}{},
	}
	if o.Total > 0 {
		n.total = [2]*rate.Limiter{newLimiter(o.Total), newLimiter(o.Total)}
	}
	sack := tcpip.TCPSACKEnabled(true)
	n.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	n.ep.AddNotify(n)
	if err := n.stack.CreateNIC(nicID, n.ep); err != nil {
		return nil, errors.New(err.String())
	}
	n.stack.SetPromiscuousMode(nicID, true)
	n.stack.SetSpoofing(nicID, true)
	n.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	n.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(n.stack, 0, 256, n.handleTCP).HandlePacket)
	n.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(n.stack, n.handleUDP).HandlePacket)
	return n, nil
}

// Inbound takes an IPv4 packet from the room addressed to the internet.
func (n *NAT) Inbound(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), pkt...))})
	n.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

// WriteNotify hands packets from the stack to the room (channel.Notification).
func (n *NAT) WriteNotify() {
	for {
		pkt := n.ep.Read()
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		pkt.DecRef()
		n.out(v.AsSlice())
		v.Release()
	}
}

// Close stops the NAT and all its connections.
func (n *NAT) Close() {
	n.mu.Lock()
	n.closed = true
	for c := range n.conns {
		c.Close()
	}
	n.mu.Unlock()
	n.stack.Close()
	n.ep.Close()
}

func (n *NAT) track(c io.Closer) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || len(n.conns) >= maxConns {
		return false
	}
	n.conns[c] = struct{}{}
	return true
}

func (n *NAT) untrack(c io.Closer) {
	n.mu.Lock()
	delete(n.conns, c)
	n.mu.Unlock()
	c.Close()
}

func newLimiter(bps int) *rate.Limiter { return rate.NewLimiter(rate.Limit(bps), max(bps/10, chunk)) }

const (
	up   = 0
	down = 1
)

// limits are the limiters of a client's traffic in one direction.
func (n *NAT) limits(client netip.Addr, dir int) []*rate.Limiter {
	var out []*rate.Limiter
	if n.o.PerClient > 0 {
		n.mu.Lock()
		l, ok := n.clients[client]
		if !ok {
			l = &[2]*rate.Limiter{newLimiter(n.o.PerClient), newLimiter(n.o.PerClient)}
			n.clients[client] = l
		}
		n.mu.Unlock()
		out = append(out, l[dir])
	}
	if n.total[dir] != nil {
		out = append(out, n.total[dir])
	}
	return out
}

func addr(a tcpip.Address) netip.Addr { return netip.AddrFrom4(a.As4()) }

func (n *NAT) allowed(dst netip.Addr) bool { return n.o.Allow == nil || n.o.Allow(dst) }

func (n *NAT) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(addr(id.LocalAddress), id.LocalPort)
	client := addr(id.RemoteAddress)
	if !n.allowed(dst.Addr()) {
		r.Complete(true)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		c, err := n.o.Dial(ctx, "tcp4", dst.String())
		cancel()
		if err != nil {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			c.Close()
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetKeepAlive(true)
		in := gonet.NewTCPConn(&wq, ep)
		if !n.track(in) {
			in.Close()
			c.Close()
			return
		}
		defer n.untrack(in)
		defer c.Close()
		done := make(chan struct{}, 2)
		go func() { n.copy(c, in, n.limits(client, up)); c.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
		go func() { n.copy(in, c, n.limits(client, down)); in.CloseWrite(); done <- struct{}{} }()
		<-done
		<-done
	}()
}

func (n *NAT) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(addr(id.LocalAddress), id.LocalPort)
	client := addr(id.RemoteAddress)
	if !n.allowed(dst.Addr()) {
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	in := gonet.NewUDPConn(&wq, ep)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		c, err := n.o.Dial(ctx, "udp4", dst.String())
		cancel()
		if err != nil || !n.track(in) {
			in.Close()
			if c != nil {
				c.Close()
			}
			return
		}
		defer n.untrack(in)
		defer c.Close()
		done := make(chan struct{}, 2)
		relay := func(to, from net.Conn, lim []*rate.Limiter) {
			buf := make([]byte, 65535)
			for {
				from.SetReadDeadline(time.Now().Add(udpIdle))
				k, err := from.Read(buf)
				if err != nil {
					break
				}
				n.wait(lim, k)
				if _, err := to.Write(buf[:k]); err != nil {
					break
				}
			}
			done <- struct{}{}
		}
		go relay(c, in, n.limits(client, up))
		go relay(in, c, n.limits(client, down))
		<-done // one side idle or closed: end the flow
		in.Close()
		c.Close()
		<-done
	}()
}

func (n *NAT) wait(lim []*rate.Limiter, k int) {
	for _, l := range lim {
		for left := k; left > 0; {
			step := min(left, l.Burst())
			l.WaitN(context.Background(), step)
			left -= step
		}
	}
}

// copy moves data with the speed limits.
func (n *NAT) copy(dst io.Writer, src io.Reader, lim []*rate.Limiter) {
	buf := make([]byte, chunk)
	for {
		k, err := src.Read(buf)
		if k > 0 {
			n.wait(lim, k)
			if _, werr := dst.Write(buf[:k]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
