// SPDX-License-Identifier: MPL-2.0

// Package tunwrap makes a room behave like a real LAN for broadcast and
// multicast. WireGuard routes by destination address, so it drops packets
// to 255.255.255.255, the subnet broadcast or 224.0.0.0/4 (LAN game
// discovery, mDNS, SSDP). The wrapper sits between the OS interface and
// AmneziaWG:
//
//   - outgoing: each such packet is wrapped into a unicast UDP packet to
//     every room member (port Port), which AmneziaWG then encrypts;
//   - incoming: the wrapped packet is unwrapped and the original broadcast
//     is handed to the OS — only if its source is the member it came from,
//     which AmneziaWG has already authenticated, so nobody can inject
//     broadcasts in another member's name.
package tunwrap

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// Port carries wrapped broadcasts inside the room.
const Port = 4797

// Modes of broadcast forwarding in a room.
const (
	ModeOn   = "on"   // all broadcast and multicast
	ModeOff  = "off"  // none
	ModeMDNS = "mdns" // only mDNS (224.0.0.251:5353)
)

// MaxPPS limits forwarded broadcasts per room, so a broadcast storm on one
// member cannot flood the others.
const MaxPPS = 200

var magic = [4]byte{'z', 'p', 't', 'b'}

const (
	ipHdr     = 20
	udpHdr    = 8
	wrapHdr   = ipHdr + udpHdr + len(magic)
	protoUDP  = 17
	protoIGMP = 2
)

var (
	limited   = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	multicast = netip.MustParsePrefix("224.0.0.0/4")
	mdnsAddr  = netip.AddrFrom4([4]byte{224, 0, 0, 251})
)

// Device wraps a TUN device.
type Device struct {
	tun.Device
	self   netip.Addr
	subnet netip.Prefix
	bcast  netip.Addr

	mode  atomic.Value // string
	peers atomic.Pointer[[]netip.Addr]

	// Read is called from one goroutine by AmneziaWG: no lock needed for
	// pending, but keep one for safety against future changes.
	mu      sync.Mutex
	pending [][]byte

	window  time.Time
	counter int

	// Userspace exit node (divert.go).
	divert       atomic.Pointer[divertFunc]
	pumpCh       chan pumped
	pumping      atomic.Bool
	injectClosed atomic.Bool
}

// New wraps dev for a room member with address self (e.g. 10.100.1.5/24).
func New(dev tun.Device, self netip.Prefix, mode string) *Device {
	d := &Device{Device: dev, self: self.Addr(), subnet: self.Masked(), bcast: lastAddr(self)}
	d.SetMode(mode)
	d.peers.Store(&[]netip.Addr{})
	return d
}

// SetMode switches forwarding ("on", "off", "mdns"; empty means on).
func (d *Device) SetMode(m string) {
	if m == "" {
		m = ModeOn
	}
	d.mode.Store(m)
}

// SetPeers sets the room addresses broadcasts are sent to.
func (d *Device) SetPeers(ips []netip.Addr) {
	cp := append([]netip.Addr(nil), ips...)
	d.peers.Store(&cp)
}

func lastAddr(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return netip.Addr{}
	}
	b := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	var o [4]byte
	binary.BigEndian.PutUint32(o[:], v)
	return netip.AddrFrom4(o)
}

// isGroupDst reports whether an IPv4 destination is broadcast/multicast in
// this room.
func (d *Device) isGroupDst(dst netip.Addr) bool {
	return dst == limited || dst == d.bcast || multicast.Contains(dst)
}

// shouldForward decides whether an outgoing packet is a broadcast to share.
func (d *Device) shouldForward(pkt []byte) bool {
	if len(pkt) < ipHdr || pkt[0]>>4 != 4 {
		return false
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if src != d.self || !d.isGroupDst(dst) || pkt[9] == protoIGMP {
		return false
	}
	switch d.mode.Load().(string) {
	case ModeOff:
		return false
	case ModeMDNS:
		ihl := int(pkt[0]&0x0f) * 4
		return dst == mdnsAddr && pkt[9] == protoUDP && len(pkt) >= ihl+udpHdr &&
			binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) == 5353
	}
	return true
}

func (d *Device) allow(now time.Time) bool {
	if now.Sub(d.window) >= time.Second {
		d.window, d.counter = now, 0
	}
	d.counter++
	return d.counter <= MaxPPS
}

// wrap builds a UDP packet from self to peer carrying the original packet.
func (d *Device) wrap(orig []byte, peer netip.Addr) []byte {
	total := wrapHdr + len(orig)
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	binary.BigEndian.PutUint16(p[6:8], 0x4000) // don't fragment
	p[8] = 64
	p[9] = protoUDP
	s, t := d.self.As4(), peer.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], t[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:ipHdr]))
	binary.BigEndian.PutUint16(p[20:22], Port)
	binary.BigEndian.PutUint16(p[22:24], Port)
	binary.BigEndian.PutUint16(p[24:26], uint16(udpHdr+len(magic)+len(orig)))
	// UDP checksum 0: optional over IPv4; AmneziaWG authenticates the packet.
	copy(p[28:32], magic[:])
	copy(p[32:], orig)
	return p
}

// unwrap returns the original broadcast from a wrapped packet addressed to
// us, or nil if the packet is not one (or not acceptable).
func (d *Device) unwrap(pkt []byte) (inner []byte, isWrap bool) {
	if len(pkt) < wrapHdr || pkt[0] != 0x45 || pkt[9] != protoUDP {
		return nil, false
	}
	if netip.AddrFrom4([4]byte(pkt[16:20])) != d.self ||
		binary.BigEndian.Uint16(pkt[22:24]) != Port || [4]byte(pkt[28:32]) != magic {
		return nil, false
	}
	// It is a wrapped broadcast; from here on, a bad one is dropped.
	outerSrc := netip.AddrFrom4([4]byte(pkt[12:16]))
	inner = pkt[wrapHdr:]
	if len(inner) < ipHdr || inner[0]>>4 != 4 || d.mode.Load().(string) == ModeOff {
		return nil, true
	}
	if netip.AddrFrom4([4]byte(inner[12:16])) != outerSrc || !d.subnet.Contains(outerSrc) {
		return nil, true // spoofed source
	}
	if !d.isGroupDst(netip.AddrFrom4([4]byte(inner[16:20]))) {
		return nil, true // only broadcasts may travel this way
	}
	if int(binary.BigEndian.Uint16(inner[2:4])) != len(inner) {
		return nil, true
	}
	return inner, true
}

// Read gives AmneziaWG outgoing packets, turning broadcasts into unicasts.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.pumping.Load() {
		return d.readPumped(bufs, sizes, offset)
	}
	d.mu.Lock()
	if len(d.pending) > 0 {
		n := d.drainLocked(bufs, sizes, offset, 0)
		d.mu.Unlock()
		return n, nil
	}
	d.mu.Unlock()

	n, err := d.Device.Read(bufs, sizes, offset)
	out := 0
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range n {
		pkt := bufs[i][offset : offset+sizes[i]]
		if d.shouldForward(pkt) {
			if d.allow(now) {
				for _, peer := range *d.peers.Load() {
					d.pending = append(d.pending, d.wrap(pkt, peer))
				}
			}
			continue
		}
		if out != i {
			copy(bufs[out][offset:], pkt)
		}
		sizes[out] = len(pkt)
		out++
	}
	return d.drainLocked(bufs, sizes, offset, out), err
}

func (d *Device) drainLocked(bufs [][]byte, sizes []int, offset, n int) int {
	for n < len(bufs) && len(d.pending) > 0 {
		p := d.pending[0]
		d.pending = d.pending[1:]
		if offset+len(p) > len(bufs[n]) {
			continue // cannot happen with AmneziaWG's buffers; drop defensively
		}
		sizes[n] = copy(bufs[n][offset:], p)
		n++
	}
	if len(d.pending) == 0 {
		d.pending = nil
	}
	return n
}

// Write hands incoming packets to the OS, unwrapping broadcasts.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	keep := bufs[:0:0]
	divert := d.divert.Load()
	for _, b := range bufs {
		if divert != nil && (*divert)(b[offset:]) {
			continue
		}
		inner, isWrap := d.unwrap(b[offset:])
		switch {
		case !isWrap:
			keep = append(keep, b)
		case inner != nil:
			n := copy(b[offset:], inner)
			keep = append(keep, b[:offset+n])
		}
	}
	if len(keep) == 0 {
		return len(bufs), nil
	}
	_, err := d.Device.Write(keep, offset)
	return len(bufs), err
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
