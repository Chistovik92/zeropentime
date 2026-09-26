// SPDX-License-Identifier: MPL-2.0

// Package magicsock multiplexes all rooms of a node over a single UDP socket.
//
// Every datagram is
//
//	room tag (8 bytes, random-looking, see obfs.Tagger) || AmneziaWG packet
//
// The tag tells the receiver which room the packet belongs to without putting
// any plaintext marker on the wire, so the AmneziaWG camouflage stays intact.
// Packets whose tag matches no room are dropped before touching AmneziaWG,
// which also cheaply filters out scanners.
//
// One socket means one NAT mapping between two nodes serves all the rooms they
// share. Each room gets its own conn.Bind for its AmneziaWG device.
//
// The same socket also sends STUN requests, so the external address a STUN
// server reports is exactly the one peers can use. STUN messages are told
// apart by their magic cookie; a room tag can never look like one.
package magicsock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"

	"github.com/Chistovik92/zeropentime/internal/netmark"
	"github.com/Chistovik92/zeropentime/internal/obfs"
	"github.com/Chistovik92/zeropentime/internal/stun"
)

const (
	maxPacket = 65535
	queueLen  = 1024
	batchSize = 64
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, maxPacket); return &b }}

// Conn is the node-wide UDP socket.
type Conn struct {
	pc   *net.UDPConn
	port uint16
	log  *slog.Logger

	mu    sync.Mutex
	rooms atomic.Pointer[[]*roomBind] // copy-on-write list for the read loop

	stunMu      sync.Mutex
	stunPending map[stun.TxID]stunWait

	disco atomic.Pointer[discoHandler]
	relay atomic.Pointer[relayHook]

	dropDirect   atomic.Bool
	dropRelayUDP atomic.Bool

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// Listen opens the shared UDP socket on port (0 = random), dual-stack.
func Listen(port int, log *slog.Logger) (*Conn, error) {
	lc := net.ListenConfig{Control: netmark.Control}
	p, err := lc.ListenPacket(context.Background(), "udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("listen udp :%d: %w", port, err)
	}
	pc := p.(*net.UDPConn)
	c := &Conn{
		pc:   pc,
		port: uint16(pc.LocalAddr().(*net.UDPAddr).Port),
		log:  log,
		done: make(chan struct{}),

		stunPending: map[stun.TxID]stunWait{},
	}
	c.rooms.Store(&[]*roomBind{})
	c.wg.Add(1)
	go c.readLoop()
	return c, nil
}

// Port returns the local UDP port.
func (c *Conn) Port() uint16 { return c.port }

// Bind returns the conn.Bind for the room with the given tag key.
func (c *Conn) Bind(tagKey [16]byte) (conn.Bind, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := *c.rooms.Load()
	for _, b := range old {
		if b.key == tagKey {
			return nil, errors.New("magicsock: room already bound")
		}
	}
	b := &roomBind{c: c, key: tagKey, tagger: obfs.NewTagger(tagKey)}
	rooms := append(append([]*roomBind(nil), old...), b)
	c.rooms.Store(&rooms)
	return b, nil
}

// Unbind removes a room. Its bind stops receiving packets.
func (c *Conn) Unbind(tagKey [16]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := *c.rooms.Load()
	rooms := make([]*roomBind, 0, len(old))
	for _, b := range old {
		if b.key == tagKey {
			b.Close()
			continue
		}
		rooms = append(rooms, b)
	}
	c.rooms.Store(&rooms)
}

// Close closes the socket and all room binds.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.pc.Close()
		c.wg.Wait()
		for _, b := range *c.rooms.Load() {
			b.Close()
		}
	})
	return err
}

func (c *Conn) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, maxPacket)
	for {
		n, addr, err := c.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// ICMP-induced errors (e.g. port unreachable on Windows) are not fatal.
			c.log.Debug("udp read", "err", err)
			continue
		}
		pkt := buf[:n]
		from := netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		if stun.Is(pkt) {
			c.handleSTUN(pkt, from)
			continue
		}
		if r := c.relay.Load(); r != nil && from == r.addr {
			if !c.dropRelayUDP.Load() {
				r.handle(bytes.Clone(pkt))
			}
			continue
		}
		if c.dropDirect.Load() {
			continue
		}
		c.dispatch(pkt, from)
	}
}

// dispatch hands a packet (tunnel or disco) to its receiver. from is the
// real sender address, or a relay endpoint for relayed packets.
func (c *Conn) dispatch(pkt []byte, from netip.AddrPort) {
	for _, b := range *c.rooms.Load() {
		if b.tagger.Match(pkt) {
			b.deliver(pkt[obfs.TagLen:], from)
			return
		}
	}
	if d := c.disco.Load(); d != nil && d.tagger.Match(pkt) {
		d.fn(bytes.Clone(pkt), from)
	}
}

// DropDirectForTests makes the socket ignore tunnel and disco packets that
// do not come through the relay, emulating a NAT no hole can be punched in.
// Tests only.
func (c *Conn) DropDirectForTests(v bool) { c.dropDirect.Store(v) }

// DropRelayUDPForTests makes the socket ignore the relay over UDP, as if
// UDP were blocked on the way (tests only).
func (c *Conn) DropRelayUDPForTests(v bool) { c.dropRelayUDP.Store(v) }

// Relayed paths are shown to AmneziaWG as addresses in this private IPv6
// range: the 80 bits after the prefix are the peer's node ID.
var relayPrefix = netip.MustParsePrefix("fd7a:7a70:72ff::/48")

// RelayEndpoint is the pseudo-address meaning "this node, via the relay".
func RelayEndpoint(node [10]byte) netip.AddrPort {
	var a [16]byte
	p := relayPrefix.Addr().As16()
	copy(a[:6], p[:6])
	copy(a[6:], node[:])
	return netip.AddrPortFrom(netip.AddrFrom16(a), 1)
}

// RelayNode returns the node ID of a relay endpoint.
func RelayNode(ap netip.AddrPort) ([10]byte, bool) {
	var n [10]byte
	if !relayPrefix.Contains(ap.Addr()) {
		return n, false
	}
	a := ap.Addr().As16()
	copy(n[:], a[6:])
	return n, true
}

// IsRelay reports whether the address is a relay endpoint.
func IsRelay(ap netip.AddrPort) bool { return relayPrefix.Contains(ap.Addr()) }

type relayHook struct {
	addr   netip.AddrPort
	handle func(pkt []byte)
	send   func(dst [10]byte, payload []byte) error
}

// SetRelay routes datagrams from the relay address to handle, and sends to
// relay endpoints through send. nil handle removes the relay.
func (c *Conn) SetRelay(addr netip.AddrPort, handle func([]byte), send func([10]byte, []byte) error) {
	if handle == nil {
		c.relay.Store(nil)
		return
	}
	c.relay.Store(&relayHook{addr: addr, handle: handle, send: send})
}

// Receive injects a packet that arrived through the relay from the node.
func (c *Conn) Receive(pkt []byte, node [10]byte) {
	c.dispatch(pkt, RelayEndpoint(node))
}

// write sends to a real address or through the relay.
func (c *Conn) write(b []byte, to netip.AddrPort) error {
	if node, ok := RelayNode(to); ok {
		r := c.relay.Load()
		if r == nil {
			return errors.New("magicsock: no relay")
		}
		return r.send(node, b)
	}
	_, err := c.pc.WriteToUDPAddrPort(b, to)
	return err
}

type discoHandler struct {
	tagger *obfs.Tagger
	fn     func(pkt []byte, from netip.AddrPort)
}

// SetDisco routes packets carrying the node's disco tag to fn. fn gets its
// own copy of the packet and must not block for long.
func (c *Conn) SetDisco(tagKey [16]byte, fn func(pkt []byte, from netip.AddrPort)) {
	c.disco.Store(&discoHandler{tagger: obfs.NewTagger(tagKey), fn: fn})
}

// WriteTo sends a datagram to a real address or a relay endpoint (disco).
func (c *Conn) WriteTo(b []byte, to netip.AddrPort) error { return c.write(b, to) }

// WriteDirect sends a datagram on the socket, never through the relay
// (used by the relay client itself).
func (c *Conn) WriteDirect(b []byte, to netip.AddrPort) error {
	_, err := c.pc.WriteToUDPAddrPort(b, to)
	return err
}

type stunWait struct {
	server netip.AddrPort
	reply  chan netip.AddrPort
}

// STUN asks a STUN server how it sees this socket. Requests are repeated
// every 500 ms until an answer comes or ctx ends. Answers are accepted only
// from the server the request went to and with the right transaction ID.
func (c *Conn) STUN(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	id := stun.NewTxID()
	w := stunWait{server: server, reply: make(chan netip.AddrPort, 1)}
	c.stunMu.Lock()
	c.stunPending[id] = w
	c.stunMu.Unlock()
	defer func() {
		c.stunMu.Lock()
		delete(c.stunPending, id)
		c.stunMu.Unlock()
	}()
	req := stun.Request(id)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := c.pc.WriteToUDPAddrPort(req, server); err != nil {
			return netip.AddrPort{}, err
		}
		select {
		case mapped := <-w.reply:
			return mapped, nil
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case <-c.done:
			return netip.AddrPort{}, net.ErrClosed
		case <-tick.C:
		}
	}
}

func (c *Conn) handleSTUN(pkt []byte, from netip.AddrPort) {
	id, mapped, err := stun.ParseResponse(pkt)
	if err != nil {
		return
	}
	c.stunMu.Lock()
	w, ok := c.stunPending[id]
	c.stunMu.Unlock()
	if !ok || w.server != from {
		return
	}
	select {
	case w.reply <- mapped:
	default:
	}
}

type packet struct {
	buf *[]byte
	n   int
	ep  *Endpoint
}

type bindState struct {
	queue chan packet
	done  chan struct{}
}

// roomBind implements conn.Bind for one room on top of the shared socket.
type roomBind struct {
	c      *Conn
	key    [16]byte
	tagger *obfs.Tagger

	mu    sync.Mutex // serialises Open/Close
	state atomic.Pointer[bindState]
}

var _ conn.Bind = (*roomBind)(nil)

func (b *roomBind) deliver(payload []byte, from netip.AddrPort) {
	st := b.state.Load()
	if st == nil {
		return
	}
	bp := bufPool.Get().(*[]byte)
	n := copy(*bp, payload)
	select {
	case st.queue <- packet{buf: bp, n: n, ep: &Endpoint{AddrPort: from}}:
	default:
		bufPool.Put(bp) // queue full: drop, like a busy NIC
	}
}

func (b *roomBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Load() != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	select {
	case <-b.c.done:
		return nil, 0, net.ErrClosed
	default:
	}
	st := &bindState{queue: make(chan packet, queueLen), done: make(chan struct{})}
	b.state.Store(st)
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		var p packet
		select {
		case p = <-st.queue:
		case <-st.done:
			return 0, net.ErrClosed
		}
		count := 0
		for {
			sizes[count] = copy(packets[count], (*p.buf)[:p.n])
			eps[count] = p.ep
			bufPool.Put(p.buf)
			count++
			if count == len(packets) {
				return count, nil
			}
			select {
			case p = <-st.queue:
			default:
				return count, nil
			}
		}
	}
	return []conn.ReceiveFunc{recv}, b.c.port, nil
}

func (b *roomBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if st := b.state.Swap(nil); st != nil {
		close(st.done)
	}
	return nil
}

// SetMark is a no-op for now; fwmark routing arrives with exit nodes.
func (b *roomBind) SetMark(uint32) error { return nil }

func (b *roomBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.state.Load() == nil {
		return net.ErrClosed
	}
	e, ok := ep.(*Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	out := *bp
	for _, pkt := range bufs {
		if len(pkt)+obfs.TagLen > len(out) {
			return fmt.Errorf("magicsock: packet too large (%d bytes)", len(pkt))
		}
		b.tagger.Put(out)
		n := copy(out[obfs.TagLen:], pkt)
		if err := b.c.write(out[:obfs.TagLen+n], e.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (b *roomBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		ua, rerr := net.ResolveUDPAddr("udp", s)
		if rerr != nil {
			return nil, fmt.Errorf("endpoint %q: %w", s, rerr)
		}
		ap = ua.AddrPort()
	}
	return &Endpoint{AddrPort: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

func (b *roomBind) BatchSize() int { return batchSize }

// Endpoint is a peer UDP address.
type Endpoint struct {
	AddrPort netip.AddrPort
}

var _ conn.Endpoint = (*Endpoint)(nil)

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) DstToString() string { return e.AddrPort.String() }
func (e *Endpoint) DstIP() netip.Addr   { return e.AddrPort.Addr() }
func (e *Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *Endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}
