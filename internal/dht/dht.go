// SPDX-License-Identifier: MPL-2.0

// Package dht is a small client of the BitTorrent mainline DHT (BEP 5):
// enough to announce "a member of this room is at IP:port" under a key and
// to find the others. It is read-only (BEP 43): it asks, it never stores
// other people's records.
//
// What is found is only a hint: the node pings those addresses with disco,
// which checks the peers' keys, so a wrong or forged record costs a ping.
package dht

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/Chistovik92/zeropentime/internal/netmark"
)

// Bootstrap are well-known entry points of the mainline DHT.
var Bootstrap = []string{
	"router.bittorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"router.utorrent.com:6881",
	"dht.libtorrent.org:25401",
}

const (
	alpha        = 3
	k            = 8
	queryTimeout = 3 * time.Second
	maxRounds    = 12
)

// ID is a 160-bit DHT key (node ID or info hash).
type ID [20]byte

// Client talks to the DHT from one UDP socket.
type Client struct {
	conn      *net.UDPConn
	self      ID
	bootstrap []string
	log       *slog.Logger

	mu      sync.Mutex
	pending map[string]chan map[string]any
	seq     uint16
	closed  bool
}

// New opens a client; bootstrap nil means Bootstrap.
func New(bootstrap []string, log *slog.Logger) (*Client, error) {
	lc := net.ListenConfig{Control: netmark.Control}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return nil, err
	}
	if bootstrap == nil {
		bootstrap = Bootstrap
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := &Client{conn: pc.(*net.UDPConn), bootstrap: bootstrap, log: log, pending: map[string]chan map[string]any{}}
	rand.Read(c.self[:])
	go c.read()
	return c, nil
}

// Close stops the client.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.conn.Close()
}

func (c *Client) read() {
	buf := make([]byte, 2048)
	for {
		n, _, err := c.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		v, err := Decode(buf[:n])
		if err != nil {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		t, _ := m["t"].(string)
		if y, _ := m["y"].(string); y != "r" && y != "e" {
			continue // queries to us: we are read-only
		}
		c.mu.Lock()
		ch := c.pending[t]
		delete(c.pending, t)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

// query sends one KRPC query and waits for the answer's "r" dictionary.
func (c *Client) query(ctx context.Context, to netip.AddrPort, q string, args map[string]any) (map[string]any, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	c.seq++
	t := string([]byte{byte(c.seq >> 8), byte(c.seq)})
	ch := make(chan map[string]any, 1)
	c.pending[t] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, t)
		c.mu.Unlock()
	}()
	args["id"] = string(c.self[:])
	m := map[string]any{"t": t, "y": "q", "q": q, "a": args}
	if q != "announce_peer" {
		m["ro"] = 1 // BEP 43; some nodes drop announces marked read-only
	}
	msg, err := Encode(m)
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.WriteToUDPAddrPort(msg, to); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	select {
	case m := <-ch:
		if r, ok := m["r"].(map[string]any); ok {
			return r, nil
		}
		return nil, errors.New("dht: error answer")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type contact struct {
	id    ID
	addr  netip.AddrPort
	token string
	asked bool
}

func distance(a, b ID) ID {
	var d ID
	for i := range a {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// nodes parses the compact node info list (26 bytes each, IPv4).
func nodes(s string) []contact {
	var out []contact
	for len(s) >= 26 {
		var c contact
		copy(c.id[:], s[:20])
		c.addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte([]byte(s[20:24]))), binary.BigEndian.Uint16([]byte(s[24:26])))
		if c.addr.Port() != 0 && !c.addr.Addr().IsUnspecified() {
			out = append(out, c)
		}
		s = s[26:]
	}
	return out
}

func (c *Client) resolveBootstrap(ctx context.Context) []netip.AddrPort {
	var out []netip.AddrPort
	for _, h := range c.bootstrap {
		if ap, err := netip.ParseAddrPort(h); err == nil {
			out = append(out, ap)
			continue
		}
		host, port, err := net.SplitHostPort(h)
		if err != nil {
			continue
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			continue
		}
		p, _ := net.LookupPort("udp", port)
		for _, ip := range ips {
			out = append(out, netip.AddrPortFrom(ip.Unmap(), uint16(p)))
		}
	}
	return out
}

// GetPeers looks up an info hash: the peers announced under it and the
// closest nodes (with the tokens needed to announce).
func (c *Client) GetPeers(ctx context.Context, ih ID) ([]netip.AddrPort, []contact) {
	var (
		mu     sync.Mutex
		peers  []netip.AddrPort
		seen   = map[netip.AddrPort]bool{}
		closer []*contact
	)
	add := func(ct contact) {
		if seen[ct.addr] {
			return
		}
		seen[ct.addr] = true
		cp := ct
		closer = append(closer, &cp)
	}
	for _, a := range c.resolveBootstrap(ctx) {
		add(contact{addr: a, id: ih}) // unknown ids: ask them first
	}
	for round := 0; round < maxRounds && ctx.Err() == nil; round++ {
		mu.Lock()
		sort.Slice(closer, func(i, j int) bool {
			di, dj := distance(closer[i].id, ih), distance(closer[j].id, ih)
			return bytes.Compare(di[:], dj[:]) < 0
		})
		var batch []*contact
		for _, ct := range closer[:min(len(closer), k)] {
			if !ct.asked && len(batch) < alpha {
				ct.asked = true
				batch = append(batch, ct)
			}
		}
		mu.Unlock()
		if len(batch) == 0 {
			break
		}
		var wg sync.WaitGroup
		for _, ct := range batch {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := c.query(ctx, ct.addr, "get_peers", map[string]any{"info_hash": string(ih[:])})
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if id, ok := r["id"].(string); ok && len(id) == 20 {
					copy(ct.id[:], id)
				}
				ct.token, _ = r["token"].(string)
				if vals, ok := r["values"].([]any); ok {
					for _, v := range vals {
						if s, ok := v.(string); ok && len(s) == 6 {
							ap := netip.AddrPortFrom(netip.AddrFrom4([4]byte([]byte(s[:4]))), binary.BigEndian.Uint16([]byte(s[4:])))
							if !contains(peers, ap) {
								peers = append(peers, ap)
							}
						}
					}
				}
				if ns, ok := r["nodes"].(string); ok {
					for _, n := range nodes(ns) {
						add(n)
					}
				}
			}()
		}
		wg.Wait()
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Slice(closer, func(i, j int) bool {
		di, dj := distance(closer[i].id, ih), distance(closer[j].id, ih)
		return bytes.Compare(di[:], dj[:]) < 0
	})
	var best []contact
	for _, ct := range closer {
		if ct.token != "" && len(best) < k {
			best = append(best, *ct)
		}
	}
	return peers, best
}

// Announce publishes port under the info hash on the closest nodes and
// returns the peers already there.
func (c *Client) Announce(ctx context.Context, ih ID, port uint16) []netip.AddrPort {
	peers, closest := c.GetPeers(ctx, ih)
	var wg sync.WaitGroup
	for _, ct := range closest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.query(ctx, ct.addr, "announce_peer", map[string]any{
				"info_hash": string(ih[:]), "port": int(port), "token": ct.token, "implied_port": 0,
			})
		}()
	}
	wg.Wait()
	return peers
}

func contains(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}
