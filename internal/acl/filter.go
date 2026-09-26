// SPDX-License-Identifier: MPL-2.0

package acl

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Filter applies a policy to the packets a node receives from a room.
// Packets this node sends are remembered, so the replies pass whatever
// the rules say ("stateful" like a home router).
type Filter struct {
	pol  *Policy
	self netip.Addr

	mu    sync.Mutex
	flows map[flow]time.Time
	swept time.Time
}

type flow struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
}

const (
	flowTTL  = 5 * time.Minute
	maxFlows = 65536
)

// NewFilter filters for a member with address self.
func NewFilter(pol *Policy, self netip.Addr) *Filter {
	return &Filter{pol: pol, self: self, flows: map[flow]time.Time{}}
}

type header struct {
	ok           bool
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
	first        bool // not a later fragment
}

func parse(pkt []byte) header {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return header{}
	}
	ihl := int(pkt[0]&0x0f) * 4
	h := header{ok: true, proto: pkt[9], src: netip.AddrFrom4([4]byte(pkt[12:16])), dst: netip.AddrFrom4([4]byte(pkt[16:20]))}
	h.first = binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0
	if h.first && (h.proto == TCP || h.proto == UDP) && len(pkt) >= ihl+4 {
		h.sport = binary.BigEndian.Uint16(pkt[ihl:])
		h.dport = binary.BigEndian.Uint16(pkt[ihl+2:])
	}
	return h
}

// Outbound remembers a packet this node sends into the room.
func (f *Filter) Outbound(pkt []byte) {
	h := parse(pkt)
	if !h.ok {
		return
	}
	f.mu.Lock()
	f.rememberLocked(flow{h.proto, h.src, h.dst, h.sport, h.dport}, time.Now())
	f.mu.Unlock()
}

func (f *Filter) rememberLocked(k flow, now time.Time) {
	if len(f.flows) >= maxFlows && now.Sub(f.swept) > time.Second {
		for x, t := range f.flows {
			if now.Sub(t) > flowTTL {
				delete(f.flows, x)
			}
		}
		f.swept = now
	}
	if len(f.flows) < maxFlows {
		f.flows[k] = now
	}
}

// Inbound reports whether a packet from the room may pass.
func (f *Filter) Inbound(pkt []byte) bool {
	h := parse(pkt)
	if !h.ok {
		return true // not IPv4: rooms carry IPv4 only
	}
	if !h.first {
		return true // later fragments carry no ports; the first one was checked
	}
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := flow{h.proto, h.dst, h.src, h.dport, h.sport}
	if t, ok := f.flows[reply]; ok && now.Sub(t) < flowTTL {
		f.flows[reply] = now
		return true
	}
	if h.proto == ICMP {
		// Echo replies and errors to our pings match by addresses only.
		for k, t := range f.flows {
			if k.proto == ICMP && k.src == h.dst && k.dst == h.src && now.Sub(t) < flowTTL {
				return true
			}
		}
	}
	dst := h.dst
	if dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || f.pol.Subnet.IsValid() && dst == lastAddr(f.pol.Subnet) {
		dst = f.self // a broadcast reaches this member
	}
	ok, _ := f.pol.Allowed(h.src, dst, int(h.proto), h.dport)
	if ok {
		f.rememberLocked(flow{h.proto, h.src, h.dst, h.sport, h.dport}, now)
	}
	return ok
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	var o [4]byte
	binary.BigEndian.PutUint32(o[:], v)
	return netip.AddrFrom4(o)
}
