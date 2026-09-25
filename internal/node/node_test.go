// SPDX-License-Identifier: MPL-2.0

package node

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

var testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// sniffer sits between two nodes, forwards datagrams and records them,
// like an ISP or a DPI box would see them.
type sniffer struct {
	towardA, towardB *net.UDPConn // socket A talks to, socket B talks to
	a, b             netip.AddrPort

	mu   sync.Mutex
	seen [][]byte
}

func newSniffer(t *testing.T) *sniffer {
	t.Helper()
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	return &sniffer{towardA: listen(), towardB: listen()}
}

func (s *sniffer) addr(c *net.UDPConn) string { return c.LocalAddr().String() }

func (s *sniffer) start(a, b netip.AddrPort) {
	s.a, s.b = a, b
	pipe := func(from, to *net.UDPConn, dst netip.AddrPort) {
		buf := make([]byte, 65535)
		for {
			n, _, err := from.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.seen = append(s.seen, bytes.Clone(buf[:n]))
			s.mu.Unlock()
			to.WriteToUDPAddrPort(buf[:n], dst)
		}
	}
	go pipe(s.towardA, s.towardB, b) // A -> B
	go pipe(s.towardB, s.towardA, a) // B -> A
}

func (s *sniffer) packets() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.seen...)
}

type testNode struct {
	id   *identity.Identity
	cfg  *config.Config
	node *Node
}

func zeroPort() *int { p := 0; return &p }

func newIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func pub(t *testing.T, id *identity.Identity, s obfs.Secret) identity.Key {
	t.Helper()
	k, err := id.RoomKey(s.RoomID())
	if err != nil {
		t.Fatal(err)
	}
	return k.Public()
}

func secret(t *testing.T) obfs.Secret {
	t.Helper()
	s, err := obfs.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// echo serves a TCP echo in a room of n and returns its address.
func echo(t *testing.T, n *Node, roomName string) netip.AddrPort {
	t.Helper()
	r, err := n.Room(roomName)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := r.Net.ListenTCP(&net.TCPAddr{IP: r.Address.Addr().AsSlice(), Port: 7000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return netip.AddrPortFrom(r.Address.Addr(), 7000)
}

func roundTrip(n *Node, roomName string, dst netip.AddrPort, msg []byte, timeout time.Duration) error {
	r, err := n.Room(roomName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := r.Net.DialContextTCPAddrPort(ctx, dst)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func start(t *testing.T, id *identity.Identity, rooms []config.Room) *Node {
	t.Helper()
	cfg := &config.Config{ListenPort: zeroPort(), Userspace: true, Rooms: rooms}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	n, err := Start(Options{Config: cfg, Identity: id, Log: testLog})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func loopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

// Two nodes share two rooms over one socket each. Traffic must flow in both
// rooms, and an on-path observer must see neither plaintext nor any stable
// protocol signature.
func TestTwoRoomsEncryptedAndObfuscated(t *testing.T) {
	idA, idB := newIdentity(t), newIdentity(t)
	game, work := secret(t), secret(t)
	sn := newSniffer(t)

	pfx := netip.MustParsePrefix
	nodeA := start(t, idA, []config.Room{
		{Name: "game", Secret: game, Address: pfx("10.100.1.1/24"), Peers: []config.Peer{
			{Name: "b", PublicKey: pub(t, idB, game), Endpoint: sn.addr(sn.towardA), AllowedIPs: []netip.Prefix{pfx("10.100.1.2/32")}},
		}},
		{Name: "work", Secret: work, Address: pfx("10.100.2.1/24"), Peers: []config.Peer{
			{Name: "b", PublicKey: pub(t, idB, work), Endpoint: sn.addr(sn.towardA), AllowedIPs: []netip.Prefix{pfx("10.100.2.2/32")}},
		}},
	})
	nodeB := start(t, idB, []config.Room{
		{Name: "game", Secret: game, Address: pfx("10.100.1.2/24"), Peers: []config.Peer{
			{Name: "a", PublicKey: pub(t, idA, game), Endpoint: sn.addr(sn.towardB), AllowedIPs: []netip.Prefix{pfx("10.100.1.1/32")}},
		}},
		{Name: "work", Secret: work, Address: pfx("10.100.2.2/24"), Peers: []config.Peer{
			{Name: "a", PublicKey: pub(t, idA, work), Endpoint: sn.addr(sn.towardB), AllowedIPs: []netip.Prefix{pfx("10.100.2.1/32")}},
		}},
	})
	sn.start(loopback(nodeA.Port()), loopback(nodeB.Port()))

	gameSrv := echo(t, nodeA, "game")
	workSrv := echo(t, nodeA, "work")

	marker := bytes.Repeat([]byte("ZEROPENTIME-PLAINTEXT-MARKER;"), 30)
	for _, tc := range []struct {
		room string
		dst  netip.AddrPort
	}{{"game", gameSrv}, {"work", workSrv}} {
		if err := roundTrip(nodeB, tc.room, tc.dst, marker, 10*time.Second); err != nil {
			t.Fatalf("room %s: %v", tc.room, err)
		}
	}

	// Rooms are isolated: work cannot reach the game subnet.
	if err := roundTrip(nodeB, "work", gameSrv, []byte("x"), time.Second); err == nil {
		t.Fatal("room work reached a service in room game")
	}

	pkts := sn.packets()
	if len(pkts) < 6 {
		t.Fatalf("sniffer saw only %d packets", len(pkts))
	}
	t.Logf("observer captured %d datagrams", len(pkts))
	prefixes := map[string]int{}
	for _, p := range pkts {
		if bytes.Contains(p, []byte("PLAINTEXT-MARKER")) {
			t.Fatal("plaintext visible on the wire")
		}
		prefixes[string(p[:4])]++
	}
	// Neither our framing nor the AmneziaWG headers may form a fixed prefix.
	for pre, count := range prefixes {
		if count > 2 {
			t.Fatalf("prefix %x repeats in %d of %d packets: looks like a signature", pre, count, len(pkts))
		}
	}
}

// A node that knows the room secret but is not a configured peer, and a node
// with the right peer key but the wrong secret, must both be unable to talk.
func TestUnauthorizedPeersRejected(t *testing.T) {
	idA, idIntruder := newIdentity(t), newIdentity(t)
	game, wrong := secret(t), secret(t)
	pfx := netip.MustParsePrefix

	nodeA := start(t, idA, []config.Room{
		{Name: "game", Secret: game, Address: pfx("10.100.1.1/24"), Peers: []config.Peer{
			{Name: "someone-else", PublicKey: pub(t, newIdentity(t), game), AllowedIPs: []netip.Prefix{pfx("10.100.1.2/32")}},
		}},
	})
	srv := echo(t, nodeA, "game")

	// Knows the secret, not in A's peer list: handshake is rejected.
	intruder := start(t, idIntruder, []config.Room{
		{Name: "game", Secret: game, Address: pfx("10.100.1.2/24"), Peers: []config.Peer{
			{Name: "a", PublicKey: pub(t, idA, game), Endpoint: loopback(nodeA.Port()).String(), AllowedIPs: []netip.Prefix{pfx("10.100.1.1/32")}},
		}},
	})
	if err := roundTrip(intruder, "game", srv, []byte("hello"), 2*time.Second); err == nil {
		t.Fatal("unknown peer got through")
	}

	// A is configured to accept this key, but the node has the wrong room
	// secret: its packets carry the wrong tag and the wrong PSK.
	idC := newIdentity(t)
	nodeA2 := start(t, idA, []config.Room{
		{Name: "game", Secret: game, Address: pfx("10.100.1.1/24"), Peers: []config.Peer{
			{Name: "c", PublicKey: pub(t, idC, game), AllowedIPs: []netip.Prefix{pfx("10.100.1.3/32")}},
		}},
	})
	srv2 := echo(t, nodeA2, "game")
	nodeC := start(t, idC, []config.Room{
		{Name: "game", Secret: wrong, Address: pfx("10.100.1.3/24"), Peers: []config.Peer{
			{Name: "a", PublicKey: pub(t, idA, game), Endpoint: loopback(nodeA2.Port()).String(), AllowedIPs: []netip.Prefix{pfx("10.100.1.1/32")}},
		}},
	})
	if err := roundTrip(nodeC, "game", srv2, []byte("hello"), 2*time.Second); err == nil {
		t.Fatal("peer with the wrong room secret got through")
	}
}
