// SPDX-License-Identifier: MPL-2.0

package node

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/disco"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/magicsock"
	"github.com/Chistovik92/zeropentime/internal/relay"
)

const (
	// A confirmed path is re-checked this often and dropped when stale.
	discoRecheck = 20 * time.Second
	discoStale   = 60 * time.Second
	// Without a path, all candidates are pinged this often (this is also
	// what punches holes: both sides do it, so each NAT sees outgoing
	// traffic to the other before the other's packets arrive).
	discoSearch = 2 * time.Second
	// Pings older than this are forgotten.
	discoPingTTL = 5 * time.Second
	// While a peer is only reachable through the relay, a direct path is
	// searched as often as without any path for this long after the peer
	// appeared: the relay usually answers before NAT holes are punched.
	discoEagerDirect = time.Minute
	maxCandidates    = 12
	maxPendingPings  = 64
)

type discoPath struct {
	addr netip.AddrPort
	rtt  time.Duration
	at   time.Time // last confirmation
}

type sentPing struct {
	to netip.AddrPort
	at time.Time
}

type discoPeer struct {
	nodeID     string
	key        identity.Key
	candidates []netip.AddrPort // from controllers
	learned    []netip.AddrPort // addresses pings came from
	best       discoPath
	lastPing   time.Time
	since      time.Time // when we learned about the peer
	sent       map[disco.TxID]sentPing
}

// discoMgr finds a working direct path to every peer.
type discoMgr struct {
	n         *Node
	priv, pub identity.Key
	lan       func() []netip.Prefix

	mu     sync.Mutex
	peers  map[string]*discoPeer // by node ID
	byKey  map[identity.Key]*discoPeer
	byCtrl map[string][]string // controller -> node IDs it told us about
	now    func() time.Time
}

func newDiscoMgr(n *Node) *discoMgr {
	priv, pub := n.ID.DiscoKey()
	return &discoMgr{
		n: n, priv: priv, pub: pub, lan: n.localPrefixes,
		peers: map[string]*discoPeer{}, byKey: map[identity.Key]*discoPeer{}, byCtrl: map[string][]string{},
		now: time.Now,
	}
}

// setPeers records the peers one controller told us about.
func (d *discoMgr) setPeers(ctrl string, peers map[string]api.Peer, active map[string]bool) {
	ourRelay := d.n.relayReadyAddr()
	d.mu.Lock()
	defer d.mu.Unlock()
	var ids []string
	for id, p := range peers {
		if !active[id] || p.DiscoKey.IsZero() {
			continue
		}
		ids = append(ids, id)
		dp, ok := d.peers[id]
		if !ok || dp.key != p.DiscoKey {
			if ok {
				delete(d.byKey, dp.key)
			}
			dp = &discoPeer{nodeID: id, key: p.DiscoKey, sent: map[disco.TxID]sentPing{}, since: d.now()}
			d.peers[id] = dp
			d.byKey[p.DiscoKey] = dp
		}
		dp.candidates = candidates(p)
		// Through the relay, if we both use the same one.
		if ourRelay != "" && p.Relay == ourRelay {
			if raw, err := relay.NodeIDBytes(id); err == nil {
				dp.candidates = append(dp.candidates, magicsock.RelayEndpoint(raw))
			}
		}
	}
	d.byCtrl[ctrl] = ids
	// Forget peers no controller mentions any more.
	still := map[string]bool{}
	for _, list := range d.byCtrl {
		for _, id := range list {
			still[id] = true
		}
	}
	for id, dp := range d.peers {
		if !still[id] {
			delete(d.peers, id)
			delete(d.byKey, dp.key)
		}
	}
}

func candidates(p api.Peer) []netip.AddrPort {
	var out []netip.AddrPort
	add := func(a netip.AddrPort) {
		if a.IsValid() && a.Port() != 0 && !slices.Contains(out, a) && len(out) < maxCandidates {
			out = append(out, a)
		}
	}
	for _, l := range p.Locals {
		add(l)
	}
	add(p.PortMap)
	for _, r := range p.Reflexive {
		add(r)
	}
	if p.PublicIP.IsValid() {
		add(netip.AddrPortFrom(p.PublicIP, p.UDPPort))
	}
	return out
}

// endpoint returns the confirmed path to a peer, or fallback.
func (d *discoMgr) endpoint(nodeID, fallback string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if dp, ok := d.peers[nodeID]; ok && dp.best.addr.IsValid() && d.now().Sub(dp.best.at) < discoStale {
		return dp.best.addr.String()
	}
	return fallback
}

// run pings peers until ctx ends.
func (d *discoMgr) run(ctx context.Context) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.tick()
		}
	}
}

type outgoing struct {
	pkt []byte
	to  netip.AddrPort
}

func (d *discoMgr) tick() {
	now := d.now()
	var out []outgoing
	lost := false
	d.mu.Lock()
	for _, dp := range d.peers {
		for tx, s := range dp.sent {
			if now.Sub(s.at) > discoPingTTL {
				delete(dp.sent, tx)
			}
		}
		if dp.best.addr.IsValid() && now.Sub(dp.best.at) >= discoStale {
			dp.best = discoPath{}
			lost = true
		}
		interval := discoSearch
		targets := append(slices.Clone(dp.candidates), dp.learned...)
		switch {
		case dp.best.addr.IsValid() && magicsock.IsRelay(dp.best.addr):
			// Relayed for now: keep looking for a direct path — eagerly at
			// first, then less often.
			if now.Sub(dp.since) >= discoEagerDirect {
				interval = discoRecheck
			}
		case dp.best.addr.IsValid():
			interval = discoRecheck
			targets = []netip.AddrPort{dp.best.addr}
		}
		if now.Sub(dp.lastPing) < interval {
			continue
		}
		dp.lastPing = now
		out = append(out, d.pingsLocked(dp, targets, now)...)
	}
	d.mu.Unlock()
	d.send(out)
	if lost {
		go d.pathsChanged()
	}
}

// pathsChanged pushes new endpoints to AmneziaWG and tells the controller.
func (d *discoMgr) pathsChanged() {
	d.n.reapplyAll()
	d.n.notifyChanged()
}

func (d *discoMgr) pingsLocked(dp *discoPeer, targets []netip.AddrPort, now time.Time) []outgoing {
	var out []outgoing
	for _, to := range targets {
		if len(dp.sent) >= maxPendingPings {
			break
		}
		tx := disco.NewTxID()
		pkt, err := disco.Seal(disco.Msg{Type: disco.TypePing, Tx: tx}, d.priv, d.pub, dp.key)
		if err != nil {
			continue
		}
		dp.sent[tx] = sentPing{to: to, at: now}
		out = append(out, outgoing{pkt, to})
	}
	return out
}

func (d *discoMgr) send(out []outgoing) {
	for _, o := range out {
		d.n.sock.WriteTo(o.pkt, o.to)
	}
}

// handle processes an incoming disco packet.
func (d *discoMgr) handle(pkt []byte, from netip.AddrPort) {
	sender, m, err := disco.Open(pkt, d.priv, d.pub)
	if err != nil {
		return
	}
	now := d.now()
	var out []outgoing
	changed := false
	d.mu.Lock()
	dp, known := d.byKey[sender]
	if !known {
		d.mu.Unlock()
		return // only peers in our rooms get answers: no reflection for strangers
	}
	switch m.Type {
	case disco.TypePing:
		if pong, err := disco.Seal(disco.Msg{Type: disco.TypePong, Tx: m.Tx, Src: from}, d.priv, d.pub, dp.key); err == nil {
			out = append(out, outgoing{pong, from})
		}
		if !slices.Contains(dp.candidates, from) && !slices.Contains(dp.learned, from) && len(dp.learned) < maxCandidates {
			dp.learned = append(dp.learned, from)
		}
		// The peer is looking for us: answer with our own ping on the path it
		// used, which also opens our NAT towards it.
		if !dp.best.addr.IsValid() {
			out = append(out, d.pingsLocked(dp, []netip.AddrPort{from}, now)...)
		}
	case disco.TypePong:
		s, ok := dp.sent[m.Tx]
		if !ok || s.to != from {
			break // unknown or answered from another address
		}
		delete(dp.sent, m.Tx)
		path := discoPath{addr: from, rtt: now.Sub(s.at), at: now}
		if d.better(path, dp.best, now) {
			changed = path.addr != dp.best.addr
			dp.best = path
		} else if path.addr == dp.best.addr {
			dp.best.at = now
			dp.best.rtt = path.rtt
		}
	}
	d.mu.Unlock()
	d.send(out)
	if changed {
		if magicsock.IsRelay(from) {
			d.n.log.Info("peer reachable through the relay", "peer", dp.nodeID)
		} else {
			d.n.log.Info("direct path found", "peer", dp.nodeID, "addr", from)
		}
		go d.pathsChanged()
	}
}

// stats counts peers by the kind of their current path.
func (d *discoMgr) stats() api.PathStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	var s api.PathStats
	now := d.now()
	for _, dp := range d.peers {
		if !dp.best.addr.IsValid() || now.Sub(dp.best.at) >= discoStale {
			continue
		}
		if magicsock.IsRelay(dp.best.addr) {
			s.Relay++
		} else {
			s.Direct++
		}
	}
	return s
}

// better decides whether a newly confirmed path should replace the current
// one: any path beats none or a stale one; a LAN path beats a remote one;
// otherwise it must be clearly faster, to avoid flapping.
func (d *discoMgr) better(p, cur discoPath, now time.Time) bool {
	if !cur.addr.IsValid() || now.Sub(cur.at) >= discoStale {
		return true
	}
	if p.addr == cur.addr {
		return false
	}
	// Any direct path beats the relay; the relay never replaces a direct one.
	if pr, cr := magicsock.IsRelay(p.addr), magicsock.IsRelay(cur.addr); pr != cr {
		return cr
	}
	pLAN, curLAN := d.isLAN(p.addr), d.isLAN(cur.addr)
	if pLAN != curLAN {
		return pLAN
	}
	return p.rtt*10 < cur.rtt*7 // at least 30% faster
}

func (d *discoMgr) isLAN(a netip.AddrPort) bool {
	for _, p := range d.lan() {
		if p.Contains(a.Addr()) && !a.Addr().IsLoopback() {
			return true
		}
	}
	return false
}
