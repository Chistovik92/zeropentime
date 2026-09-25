// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Chistovik92/zeropentime/internal/identity"
)

// Authorizer decides who may use the relay.
type Authorizer interface {
	// Node returns the node ID owning this disco key, if the node may use
	// the relay (is an active member of some room).
	Node(discoKey identity.Key) (nodeID string, ok bool)
	// CanSend reports whether src may send to dst (they share a room).
	CanSend(src, dst string) bool
}

const (
	sessionIdle = 2 * time.Minute
	// Per-session limit; generous for relayed game and file traffic, but
	// stops one node from flooding the relay.
	maxPPS = 20000
)

type serverSession struct {
	Session
	nodeID  string
	raw     [NodeIDLen]byte
	addr    netip.AddrPort
	last    time.Time
	window  time.Time
	packets int
}

// Server is a UDP relay.
type Server struct {
	priv, pub identity.Key
	auth      Authorizer
	log       *slog.Logger
	now       func() time.Time

	mu     sync.Mutex
	byID   map[[sessLen]byte]*serverSession
	byNode map[string]*serverSession

	permMu sync.Mutex
	perm   map[[2]string]permEntry

	outMu   sync.Mutex
	pc      *net.UDPConn
	streams map[netip.AddrPort]func([]byte) error
	nextID  uint64
}

type permEntry struct {
	ok bool
	at time.Time
}

// NewServer creates a relay with the given X25519 key pair.
func NewServer(priv, pub identity.Key, auth Authorizer, log *slog.Logger) *Server {
	return &Server{
		priv: priv, pub: pub, auth: auth, log: log, now: time.Now,
		byID: map[[sessLen]byte]*serverSession{}, byNode: map[string]*serverSession{},
		perm: map[[2]string]permEntry{}, streams: map[netip.AddrPort]func([]byte) error{},
	}
}

// PublicKey is the relay's public key, given to nodes with its address.
func (s *Server) PublicKey() identity.Key { return s.pub }

// ServeUDP runs the relay on addr until ctx ends.
func (s *Server) ServeUDP(ctx context.Context, addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	s.log.Info("relay listening", "addr", pc.LocalAddr().String())
	s.outMu.Lock()
	s.pc = pc
	s.outMu.Unlock()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go s.expireLoop(ctx)
	buf := make([]byte, maxFrame)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		s.send(s.Handle(buf[:n], from))
	}
}

// Streams (VLESS sessions) get pseudo addresses from this range, so the
// relay core treats them like any other node address.
var streamPrefix = netip.MustParsePrefix("fd7a:7a70:7273::/48")

// ServeStream relays packets of one stream (a VLESS UDP session) until
// read fails. Nodes behind blocked UDP reach the relay this way.
func (s *Server) ServeStream(read func([]byte) (int, error), write func([]byte) error) {
	s.outMu.Lock()
	s.nextID++
	a := streamPrefix.Addr().As16()
	binary.BigEndian.PutUint64(a[8:], s.nextID)
	addr := netip.AddrPortFrom(netip.AddrFrom16(a), 1)
	s.streams[addr] = write
	s.outMu.Unlock()
	defer func() {
		s.outMu.Lock()
		delete(s.streams, addr)
		s.outMu.Unlock()
	}()
	buf := make([]byte, maxFrame)
	for {
		n, err := read(buf)
		if err != nil {
			return
		}
		s.send(s.Handle(buf[:n], addr))
	}
}

// send delivers frames to UDP addresses or to streams.
func (s *Server) send(outs []Out) {
	for _, o := range outs {
		s.outMu.Lock()
		w, isStream := s.streams[o.To]
		pc := s.pc
		s.outMu.Unlock()
		switch {
		case isStream:
			w(o.Data)
		case pc != nil && !streamPrefix.Contains(o.To.Addr()):
			pc.WriteToUDPAddrPort(o.Data, o.To)
		}
	}
}

// Out is a datagram to send.
type Out struct {
	Data []byte
	To   netip.AddrPort
}

// Handle processes one datagram and returns what to send in reply. It is
// transport-independent so streams (VLESS) can reuse it.
func (s *Server) Handle(pkt []byte, from netip.AddrPort) []Out {
	if IsHello(pkt, s.pub) {
		return s.hello(pkt, from)
	}
	id, ok := SessionID(pkt, s.pub)
	if !ok {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	src := s.byID[id]
	if src == nil {
		s.mu.Unlock()
		return nil
	}
	if now.Sub(src.window) >= time.Second {
		src.window, src.packets = now, 0
	}
	src.packets++
	if src.packets > maxPPS {
		s.mu.Unlock()
		return nil
	}
	sess := src.Session
	s.mu.Unlock()

	typ, node, payload, err := Open(&sess, pkt)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	src.addr, src.last = from, now // follows NAT rebinding
	srcRaw := src.raw
	srcID := src.nodeID
	s.mu.Unlock()

	switch typ {
	case TypePing:
		f, err := Seal(&sess, s.pub, TypePing, [NodeIDLen]byte{}, nil)
		if err != nil {
			return nil
		}
		return []Out{{f, from}}
	case TypeSend:
		dstID := NodeIDString(node)
		if !s.allowed(srcID, dstID) {
			return nil
		}
		s.mu.Lock()
		dst := s.byNode[dstID]
		var dstSess Session
		var dstAddr netip.AddrPort
		if dst != nil {
			dstSess, dstAddr = dst.Session, dst.addr
		}
		s.mu.Unlock()
		if dst == nil {
			return nil
		}
		f, err := Seal(&dstSess, s.pub, TypeRecv, srcRaw, payload)
		if err != nil {
			return nil
		}
		return []Out{{f, dstAddr}}
	}
	return nil
}

func (s *Server) hello(pkt []byte, from netip.AddrPort) []Out {
	key, err := OpenHello(pkt, s.priv, s.pub)
	if err != nil {
		return nil
	}
	nodeID, ok := s.auth.Node(key)
	if !ok {
		return nil
	}
	raw, err := NodeIDBytes(nodeID)
	if err != nil {
		return nil
	}
	sess, err := NewSession()
	if err != nil {
		return nil
	}
	w, err := Welcome(sess, s.priv, key)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	if old := s.byNode[nodeID]; old != nil {
		delete(s.byID, old.ID)
	}
	ss := &serverSession{Session: *sess, nodeID: nodeID, raw: raw, addr: from, last: s.now()}
	s.byID[sess.ID] = ss
	s.byNode[nodeID] = ss
	s.mu.Unlock()
	s.log.Debug("relay session", "node", nodeID, "from", from)
	return []Out{{w, from}}
}

// allowed caches the controller's answer for a minute.
func (s *Server) allowed(src, dst string) bool {
	k := [2]string{src, dst}
	now := s.now()
	s.permMu.Lock()
	e, ok := s.perm[k]
	s.permMu.Unlock()
	if ok && now.Sub(e.at) < time.Minute {
		return e.ok
	}
	allow := s.auth.CanSend(src, dst)
	s.permMu.Lock()
	s.perm[k] = permEntry{allow, now}
	s.permMu.Unlock()
	return allow
}

func (s *Server) expireLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := s.now()
			s.mu.Lock()
			for id, ss := range s.byID {
				if now.Sub(ss.last) > sessionIdle {
					delete(s.byID, id)
					if s.byNode[ss.nodeID] == ss {
						delete(s.byNode, ss.nodeID)
					}
				}
			}
			s.mu.Unlock()
			s.permMu.Lock()
			for k, e := range s.perm {
				if now.Sub(e.at) > time.Minute {
					delete(s.perm, k)
				}
			}
			s.permMu.Unlock()
		}
	}
}
