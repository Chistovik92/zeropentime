// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestBencodeRoundTrip(t *testing.T) {
	in := map[string]any{"a": map[string]any{"id": "abc", "port": 4790}, "l": []any{"x", 1}, "y": "q"}
	b, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "d1:ad2:id3:abc4:porti4790ee1:ll1:xi1ee1:y1:qe" {
		t.Fatalf("encoded %q", b)
	}
	v, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["y"] != "q" || m["a"].(map[string]any)["port"] != int64(4790) {
		t.Fatalf("decoded %v", m)
	}
	for _, bad := range []string{"", "i12", "5:abc", "d1:ae", "l", "di1ei2ee"} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// fakeNode is a DHT node that stores announces and knows the others.
type fakeNode struct {
	id    ID
	conn  *net.UDPConn
	mu    sync.Mutex
	peers map[ID][]netip.AddrPort
	all   *[]*fakeNode
}

func (f *fakeNode) addr() netip.AddrPort { return f.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (f *fakeNode) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		v, err := Decode(buf[:n])
		if err != nil {
			continue
		}
		m := v.(map[string]any)
		a, _ := m["a"].(map[string]any)
		var ih ID
		copy(ih[:], a["info_hash"].(string))
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
			for _, o := range *f.all {
				b := o.addr().Addr().As4()
				ns = append(append(append(ns, o.id[:]...), b[:]...), 0, 0)
				binary.BigEndian.PutUint16(ns[len(ns)-2:], o.addr().Port())
			}
			r["nodes"] = string(ns)
		case "announce_peer":
			if a["token"] != "tok" {
				continue
			}
			port := a["port"].(int64)
			f.mu.Lock()
			f.peers[ih] = append(f.peers[ih], netip.AddrPortFrom(from.Addr(), uint16(port)))
			f.mu.Unlock()
		}
		out, _ := Encode(map[string]any{"t": m["t"], "y": "r", "r": r})
		f.conn.WriteToUDPAddrPort(out, from)
	}
}

func TestAnnounceAndFind(t *testing.T) {
	var all []*fakeNode
	for range 5 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeNode{conn: c, peers: map[ID][]netip.AddrPort{}, all: &all}
		rand.Read(f.id[:])
		all = append(all, f)
		t.Cleanup(func() { c.Close() })
	}
	for _, f := range all {
		go f.serve()
	}
	boot := []string{all[0].addr().String()}
	a, err := New(boot, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(boot, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var ih ID
	rand.Read(ih[:])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if got := a.Announce(ctx, ih, 4790); len(got) != 0 {
		t.Fatalf("peers before anyone announced: %v", got)
	}
	peers, _ := b.GetPeers(ctx, ih)
	want := netip.MustParseAddrPort("127.0.0.1:4790")
	if !contains(peers, want) {
		t.Fatalf("peers %v, want %v", peers, want)
	}
}
