// SPDX-License-Identifier: MPL-2.0

package node

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/Chistovik92/zeropentime/internal/dht"
)

// Peers without the controller: for rooms where a room admin allowed it,
// the node announces its UDP address in the public BitTorrent DHT under a
// key only the room's members can compute (the room secret and the day),
// and looks up the others. Found addresses go to disco as hints; disco
// checks the peers' keys, so nobody can pose as a member.

const dhtEvery = 10 * time.Minute

// dhtKey is the DHT key of a room for a day: without the room secret the
// records cannot be tied to the room, and the key changes daily.
func dhtKey(secret []byte, day int64) dht.ID {
	h := sha1.New()
	h.Write([]byte("zeropentime-dht-v1"))
	h.Write(secret)
	var d [8]byte
	binary.BigEndian.PutUint64(d[:], uint64(day))
	h.Write(d[:])
	var id dht.ID
	copy(id[:], h.Sum(nil))
	return id
}

// dhtRoomsLocked lists the running rooms that use the DHT, with their
// secrets and the node IDs of their members.
func (n *Node) dhtRoomsLocked() map[string]struct {
	secret []byte
	peers  []string
} {
	out := map[string]struct {
		secret []byte
		peers  []string
	}{}
	for key, r := range n.rooms {
		if !r.cfg.DHT || r.controller == "" {
			continue
		}
		var ids []string
		for _, id := range r.cfg.PeerNodes {
			ids = append(ids, id)
		}
		out[key] = struct {
			secret []byte
			peers  []string
		}{append([]byte(nil), r.cfg.Secret[:]...), ids}
	}
	return out
}

// announcePort is the port peers should use: the router's forwarded one,
// the one STUN saw, or the local one.
func (n *Node) announcePort() uint16 {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.portMap.IsValid() {
		return n.portMap.Port()
	}
	for _, r := range n.reports {
		if len(r.Mapped) > 0 {
			return r.Mapped[0].Port()
		}
	}
	return n.sock.Port()
}

// dhtLoop announces and looks up the DHT rooms every dhtEvery.
func (n *Node) dhtLoop(ctx context.Context) {
	var client *dht.Client
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	every, first := dhtEvery, 15*time.Second // let netcheck learn our address first
	if n.opts.DHTEvery > 0 {
		every, first = n.opts.DHTEvery, n.opts.DHTEvery
	}
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		t.Reset(every)
		n.mu.Lock()
		rooms := n.dhtRoomsLocked()
		n.mu.Unlock()
		if len(rooms) == 0 || n.disco == nil {
			continue
		}
		if client == nil {
			c, err := dht.New(n.opts.DHTBootstrap, n.log)
			if err != nil {
				n.log.Warn("dht: cannot start", "err", err)
				continue
			}
			client = c
		}
		port := n.announcePort()
		day := time.Now().UTC().Unix() / 86400
		for roomID, r := range rooms {
			lctx, cancel := context.WithTimeout(ctx, time.Minute)
			var found []netip.AddrPort
			for _, d := range []int64{day, day - 1} {
				key := dhtKey(r.secret, d)
				var peers []netip.AddrPort
				if d == day {
					peers = client.Announce(lctx, key, port)
				} else {
					peers, _ = client.GetPeers(lctx, key)
				}
				for _, p := range peers {
					if !containsAP(found, p) {
						found = append(found, p)
					}
				}
			}
			cancel()
			n.log.Debug("dht: room peers", "room_id", roomID, "found", len(found))
			if len(found) > 0 {
				n.disco.addHints(r.peers, found)
			}
		}
	}
}

func containsAP(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}
