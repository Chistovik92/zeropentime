// SPDX-License-Identifier: MPL-2.0

package node

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/control"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/magicsock"
)

// syncInfo is how the last poll of a controller went.
type syncInfo struct {
	at  time.Time
	err string
}

func (n *Node) noteSync(url string, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.syncs[url]
	if err != nil {
		s.err = err.Error()
	} else {
		s.at, s.err = time.Now(), ""
	}
	n.syncs[url] = s
}

// Reload makes the node re-read the state file now instead of within a
// second ("zpt exit", "zpt dns" through the control channel).
func (n *Node) Reload() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// Status describes the running node for "zpt status" and "zpt peers".
func (n *Node) Status() control.Status {
	s := control.Status{
		NodeID: n.ID.NodeID(), Version: n.opts.Version, Started: n.started, UDPPort: n.sock.Port(),
	}
	n.relayMu.Lock()
	if n.relay != nil {
		s.Relay, s.RelayReady = n.relayAddr, n.relay.Ready()
		s.RelayVia = "udp"
		if n.vlessConn.Load() != nil {
			s.RelayVia = "vless"
		}
	}
	n.relayMu.Unlock()

	st, _ := LoadState(n.opts.StatePath)
	if st == nil {
		st = &State{}
	}
	s.Exit.Choice = "auto"
	if c := st.Exit; c != nil && c.Off {
		s.Exit.Choice = "off"
	} else if c != nil {
		s.Exit.Choice, s.Exit.AllowLAN = c.Room+" "+c.Member, c.KillSwitch && c.AllowLAN
	}

	n.mu.Lock()
	s.PortMap = n.portMap
	s.KillSwitch = n.ksKey != ""
	for _, c := range st.Controllers {
		cs := control.ControllerStatus{URL: c.URL, LastSync: n.syncs[c.URL].at, Error: n.syncs[c.URL].err}
		if r, ok := n.reports[c.URL]; ok {
			cs.NAT, cs.Mapped = r.NAT, r.Mapped
		}
		s.Controllers = append(s.Controllers, cs)
	}
	type roomRef struct {
		key string
		r   *running
	}
	var rooms []roomRef
	for k, r := range n.rooms {
		rooms = append(rooms, roomRef{k, r})
	}
	n.mu.Unlock()
	sort.Slice(rooms, func(i, j int) bool { return rooms[i].r.cfg.Name < rooms[j].r.cfg.Name })

	for _, ref := range rooms {
		r, cfg := ref.r, ref.r.cfg
		exit, dns := r.room.Exit()
		cr := control.Room{
			Name: cfg.Name, Interface: r.room.Ifname(), Address: cfg.Address, Broadcast: cfg.Broadcast,
			Routes: cfg.Routes, Routing: cfg.Routing, ExitNode: cfg.ExitNode, Exit: exit, DNS: dns,
		}
		if r.controller != "" {
			cr.ID = ref.key
		}
		if exit {
			s.Exit.Active, s.Exit.Room = true, cfg.Name
		}
		if len(dns) > 0 {
			s.DNS, s.DNSRoom = dns, cfg.Name
		}
		stats := parseUAPI(r.room.Stats())
		for _, p := range cfg.Peers {
			cp := control.Peer{Name: p.Name, AllowedIPs: p.AllowedIPs, Path: "none"}
			for _, a := range p.AllowedIPs {
				if a.Bits() == 32 || a.Bits() == 128 {
					cp.IP = a.Addr()
					break
				}
			}
			if id := cfg.PeerNodes[p.PublicKey]; id != "" {
				cp.NodeID = id
				if exit && cfg.ExitPeer == id {
					s.Exit.Member = p.Name
				}
			}
			if ps, ok := stats[p.PublicKey]; ok {
				cp.Endpoint, cp.LastHandshake, cp.RxBytes, cp.TxBytes = ps.endpoint, ps.handshake, ps.rx, ps.tx
			}
			if n.disco != nil && cp.NodeID != "" {
				if addr, rtt, ok := n.disco.path(cp.NodeID); ok {
					cp.RTT, cp.Path = rtt, "direct"
					if magicsock.IsRelay(addr) {
						cp.Path = "relay"
					}
				}
			} else if !cp.LastHandshake.IsZero() && time.Since(cp.LastHandshake) < 3*time.Minute {
				cp.Path = "direct" // static rooms: no relay
			}
			cr.Peers = append(cr.Peers, cp)
		}
		s.Rooms = append(s.Rooms, cr)
	}
	return s
}

type uapiPeer struct {
	endpoint  string
	handshake time.Time
	rx, tx    uint64
}

// parseUAPI reads the AmneziaWG "get" output.
func parseUAPI(text string, _ error) map[identity.Key]uapiPeer {
	out := map[identity.Key]uapiPeer{}
	var cur *identity.Key
	var p uapiPeer
	var sec int64
	flush := func() {
		if cur != nil {
			if sec > 0 {
				p.handshake = time.Unix(sec, 0)
			}
			out[*cur] = p
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			var key identity.Key
			if b, err := hex.DecodeString(v); err == nil && len(b) == len(key) {
				copy(key[:], b)
				cur, p, sec = &key, uapiPeer{}, 0
			} else {
				cur = nil
			}
		case "endpoint":
			p.endpoint = v
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			p.rx, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			p.tx, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	flush()
	return out
}

// path is the confirmed path to a peer, if any.
func (d *discoMgr) path(nodeID string) (netip.AddrPort, time.Duration, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	dp, ok := d.peers[nodeID]
	if !ok || !dp.best.addr.IsValid() || d.now().Sub(dp.best.at) >= discoStale {
		return netip.AddrPort{}, 0, false
	}
	return dp.best.addr, dp.best.rtt, true
}
