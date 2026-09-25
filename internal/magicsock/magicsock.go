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
package magicsock

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/conn"

	"github.com/Chistovik92/zeropentime/internal/obfs"
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

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// Listen opens the shared UDP socket on port (0 = random), dual-stack.
func Listen(port int, log *slog.Logger) (*Conn, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("listen udp :%d: %w", port, err)
	}
	c := &Conn{
		pc:   pc,
		port: uint16(pc.LocalAddr().(*net.UDPAddr).Port),
		log:  log,
		done: make(chan struct{}),
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
		for _, b := range *c.rooms.Load() {
			if b.tagger.Match(pkt) {
				b.deliver(pkt[obfs.TagLen:], netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()))
				break
			}
		}
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
		if _, err := b.c.pc.WriteToUDPAddrPort(out[:obfs.TagLen+n], e.AddrPort); err != nil {
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
