// SPDX-License-Identifier: MPL-2.0

// Package dhttest is a tiny in-process DHT network for tests: nodes that
// answer get_peers and store announce_peer.
package dhttest

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/dht"
)

// Network is a set of fake DHT nodes.
type Network struct {
	nodes []*node
}

type node struct {
	id    dht.ID
	conn  *net.UDPConn
	mu    sync.Mutex
	peers map[dht.ID][]netip.AddrPort
	net   *Network
}

// New starts n fake nodes on 127.0.0.1; they stop with the test.
func New(t testing.TB, n int) *Network {
	nw := &Network{}
	for range n {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		f := &node{conn: c, peers: map[dht.ID][]netip.AddrPort{}, net: nw}
		rand.Read(f.id[:])
		nw.nodes = append(nw.nodes, f)
		t.Cleanup(func() { c.Close() })
	}
	for _, f := range nw.nodes {
		go f.serve()
	}
	return nw
}

// Bootstrap is the entry point for clients.
func (nw *Network) Bootstrap() []string { return []string{nw.nodes[0].addr().String()} }

// Announced lists every address announced under any key.
func (nw *Network) Announced() []netip.AddrPort {
	var out []netip.AddrPort
	for _, f := range nw.nodes {
		f.mu.Lock()
		for _, ps := range f.peers {
			for _, p := range ps {
				dup := false
				for _, x := range out {
					dup = dup || x == p
				}
				if !dup {
					out = append(out, p)
				}
			}
		}
		f.mu.Unlock()
	}
	return out
}

func (f *node) addr() netip.AddrPort { return f.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (f *node) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		v, err := dht.Decode(buf[:n])
		if err != nil {
			continue
		}
		m, _ := v.(map[string]any)
		a, _ := m["a"].(map[string]any)
		var ih dht.ID
		s, _ := a["info_hash"].(string)
		copy(ih[:], s)
		r := map[string]any{"id": string(f.id[:])}
		switch m["q"] {
		case "get_peers":
			r["token"] = "tok"
			f.mu.Lock()
			var vals []any
			for _, p := range f.peers[ih] {
				b := p.Addr().As4()
				vals = append(vals, string(append(b[:], byte(p.Port()>>8), byte(p.Port()))))
			}
			f.mu.Unlock()
			if vals != nil {
				r["values"] = vals
			}
			var ns []byte
			for _, o := range f.net.nodes {
				b := o.addr().Addr().As4()
				ns = append(append(append(ns, o.id[:]...), b[:]...), 0, 0)
				binary.BigEndian.PutUint16(ns[len(ns)-2:], o.addr().Port())
			}
			r["nodes"] = string(ns)
		case "announce_peer":
			if a["token"] != "tok" {
				continue
			}
			port, _ := a["port"].(int64)
			p := netip.AddrPortFrom(from.Addr(), uint16(port))
			f.mu.Lock()
			dup := false
			for _, x := range f.peers[ih] {
				dup = dup || x == p
			}
			if !dup {
				f.peers[ih] = append(f.peers[ih], p)
			}
			f.mu.Unlock()
		default:
			continue
		}
		out, _ := dht.Encode(map[string]any{"t": m["t"], "y": "r", "r": r})
		f.conn.WriteToUDPAddrPort(out, from)
	}
}
