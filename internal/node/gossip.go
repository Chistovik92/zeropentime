// SPDX-License-Identifier: MPL-2.0

package node

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/acl"
	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/pki"
	"github.com/Chistovik92/zeropentime/internal/room"
)

// Gossip: members pass each other the newest signed room config, so a
// change — a kicked member (revocation), a new member, new rules —
// reaches everybody even when some cannot reach the controller. It runs
// inside the room (port acl.GossipPort on the room addresses):
//
//   - UDP: "zptg1 ROOM_ID VERSION" announces, every gossipEvery and at
//     once when the version changes;
//   - TCP: "GET ROOM_ID\n" answers with the signed config (JSON).
//
// A config from a peer goes through the same checks as one from the
// controller: the signature of the pinned room key and no rollback.

const (
	gossipEvery   = 20 * time.Second
	gossipRepeat  = 2 * time.Second
	gossipMaxSize = 4 << 20
)

type gossipRoom struct {
	cancel context.CancelFunc
	kick   chan struct{}
	pc     net.PacketConn
	ln     net.Listener
}

// startGossipLocked runs gossip for a controller room.
func (n *Node) startGossipLocked(roomID string, r *room.Room) {
	if n.gossip == nil {
		n.gossip = map[string]*gossipRoom{}
	}
	if _, ok := n.gossip[roomID]; ok {
		return
	}
	ctx, cancel := context.WithCancel(n.ctx)
	g := &gossipRoom{cancel: cancel, kick: make(chan struct{}, 1)}
	n.gossip[roomID] = g
	pc, err := r.ListenUDP(acl.GossipPort)
	if err != nil {
		n.log.Warn("gossip: cannot listen in the room", "room", r.Name, "err", err)
		return
	}
	ln, err := r.ListenTCP(acl.GossipPort)
	if err != nil {
		pc.Close()
		n.log.Warn("gossip: cannot listen in the room", "room", r.Name, "err", err)
		return
	}
	g.pc, g.ln = pc, ln
	go n.gossipServe(ctx, roomID, ln)
	go n.gossipListen(ctx, roomID, r, pc)
	go n.gossipAnnounce(ctx, roomID, pc, g.kick)
}

func (n *Node) stopGossipLocked(roomID string) {
	if g, ok := n.gossip[roomID]; ok {
		g.cancel()
		// Closed here, before the room: sockets of a closing in-process
		// network stack must not outlive it.
		if g.pc != nil {
			g.pc.Close()
			g.ln.Close()
		}
		delete(n.gossip, roomID)
	}
}

// kickGossipLocked announces a new version of a room config at once.
func (n *Node) kickGossipLocked(roomID string) {
	if g, ok := n.gossip[roomID]; ok {
		select {
		case g.kick <- struct{}{}:
		default:
		}
	}
}

// peerAddrs are the room addresses of the other members that already
// have a session with us. Sending to a member without one would start a
// handshake from both sides at once when a room comes up, which the
// keepalive stagger of package room exists to avoid (it costs a failed
// handshake and seconds without traffic); such members get the next
// announce.
func (n *Node) peerAddrs(roomID string) []netip.Addr {
	n.mu.Lock()
	r, ok := n.rooms[roomID]
	if !ok {
		n.mu.Unlock()
		return nil
	}
	peers, subnet, rm := r.cfg.Peers, r.cfg.Address.Masked(), r.room
	n.mu.Unlock()
	stats := parseUAPI(rm.Stats())
	var out []netip.Addr
	for _, p := range peers {
		st, ok := stats[p.PublicKey]
		if !ok || st.handshake.IsZero() || time.Since(st.handshake) > 3*time.Minute {
			continue
		}
		for _, a := range p.AllowedIPs {
			if a.Bits() == 32 && subnet.Contains(a.Addr()) {
				out = append(out, a.Addr())
			}
		}
	}
	return out
}

func (n *Node) gossipAnnounce(ctx context.Context, roomID string, pc net.PacketConn, kick <-chan struct{}) {
	t := time.NewTimer(gossipEvery)
	defer t.Stop()
	// A new version is announced a few times in quick succession: a lone
	// UDP packet can be lost (for example, one that crosses a session
	// change of the tunnel), and the next regular announce is far away.
	repeat := 0
	for {
		n.mu.Lock()
		v := n.versions[roomID]
		n.mu.Unlock()
		msg := []byte(fmt.Sprintf("zptg1 %s %d", roomID, v))
		for _, a := range n.peerAddrs(roomID) {
			pc.WriteTo(msg, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, acl.GossipPort)))
		}
		next := gossipEvery
		if repeat > 0 {
			repeat--
			next = gossipRepeat
		}
		t.Reset(next)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
			repeat = 3
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}
	}
}

func (n *Node) gossipListen(ctx context.Context, roomID string, r *room.Room, pc net.PacketConn) {
	buf := make([]byte, 256)
	var fetching bool
	done := make(chan struct{}, 1)
	for {
		k, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		f := strings.Fields(string(buf[:k]))
		if len(f) != 3 || f[0] != "zptg1" || f[1] != roomID {
			continue
		}
		v, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			continue
		}
		n.mu.Lock()
		newer := v > n.versions[roomID]
		n.mu.Unlock()
		select {
		case <-done:
			fetching = false
		default:
		}
		if !newer || fetching {
			continue
		}
		ua, ok := from.(interface{ String() string })
		if !ok {
			continue
		}
		peer, err := netip.ParseAddrPort(ua.String())
		if err != nil {
			continue
		}
		fetching = true
		go func() {
			defer func() { done <- struct{}{} }()
			if err := n.gossipFetch(ctx, roomID, r, peer.Addr()); err != nil {
				n.log.Debug("gossip: fetch failed", "room", r.Name, "peer", peer.Addr(), "err", err)
			}
		}()
	}
}

func (n *Node) gossipFetch(ctx context.Context, roomID string, r *room.Room, peer netip.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := r.DialTCP(ctx, netip.AddrPortFrom(peer, acl.GossipPort))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(c, "GET %s\n", roomID); err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(c, gossipMaxSize))
	if err != nil {
		return err
	}
	var s pki.Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return n.applyGossip(roomID, &s, peer)
}

func (n *Node) gossipServe(ctx context.Context, roomID string, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			line, err := bufio.NewReader(io.LimitReader(c, 256)).ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "GET "+roomID {
				return
			}
			n.mu.Lock()
			s := n.signed[roomID]
			n.mu.Unlock()
			if s != nil {
				json.NewEncoder(c).Encode(s)
			}
		}()
	}
}

// applyGossip applies a signed room config from a peer as if the room's
// controller had sent it.
func (n *Node) applyGossip(roomID string, s *pki.Signed, peer netip.Addr) error {
	n.mu.Lock()
	r, ok := n.rooms[roomID]
	if !ok || r.controller == "" {
		n.mu.Unlock()
		return fmt.Errorf("room %s is not running", roomID)
	}
	url, name := r.controller, r.cfg.Name
	last := n.last[url]
	n.mu.Unlock()
	if last == nil {
		return fmt.Errorf("no netmap for %s", url)
	}
	nm := *last
	nm.Rooms = append([]api.RoomState(nil), last.Rooms...)
	found := false
	for i := range nm.Rooms {
		if nm.Rooms[i].RoomID == roomID {
			nm.Rooms[i].Config, nm.Rooms[i].Status = s, "active"
			found = true
		}
	}
	if !found {
		return fmt.Errorf("room %s is not in the netmap", roomID)
	}
	n.mu.Lock()
	before := n.versions[roomID]
	n.mu.Unlock()
	n.apply(url, &nm)
	n.mu.Lock()
	after := n.versions[roomID]
	n.mu.Unlock()
	if after > before {
		n.log.Info("room config from a peer", "room", name, "peer", peer, "version", after)
		if strings.HasPrefix(url, localPrefix) {
			n.persistLocal(roomID, s)
		}
	}
	return nil
}
