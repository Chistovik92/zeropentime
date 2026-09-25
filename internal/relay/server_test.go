// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/identity"
)

type fakeAuth struct {
	nodes map[identity.Key]string
	pairs map[[2]string]bool
}

func (f fakeAuth) Node(k identity.Key) (string, bool) { id, ok := f.nodes[k]; return id, ok }
func (f fakeAuth) CanSend(a, b string) bool           { return f.pairs[[2]string{a, b}] }

type member struct {
	id        *identity.Identity
	priv, pub identity.Key
	addr      netip.AddrPort
	sess      *Session
}

func newMember(t *testing.T, port uint16) *member {
	id, _ := identity.Generate()
	priv, pub := id.DiscoKey()
	return &member{id: id, priv: priv, pub: pub, addr: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
}

func (m *member) raw(t *testing.T) [NodeIDLen]byte {
	b, err := NodeIDBytes(m.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func register(t *testing.T, s *Server, m *member) {
	t.Helper()
	h, _ := Hello(m.priv, m.pub, s.pub)
	out := s.Handle(h, m.addr)
	if len(out) != 1 || out[0].To != m.addr {
		t.Fatalf("no welcome for %s", m.id.NodeID())
	}
	sess, err := OpenWelcome(out[0].Data, m.priv, s.pub)
	if err != nil {
		t.Fatal(err)
	}
	m.sess = sess
}

func TestServerForwardsOnlyBetweenRoomMates(t *testing.T) {
	rPriv, rPub := func() (identity.Key, identity.Key) { id, _ := identity.Generate(); return id.DiscoKey() }()
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	outsider := newMember(t, 4)
	auth := fakeAuth{
		nodes: map[identity.Key]string{a.pub: a.id.NodeID(), b.pub: b.id.NodeID(), c.pub: c.id.NodeID()},
		pairs: map[[2]string]bool{{a.id.NodeID(), b.id.NodeID()}: true},
	}
	s := NewServer(rPriv, rPub, auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
	register(t, s, a)
	register(t, s, b)
	register(t, s, c)

	h, _ := Hello(outsider.priv, outsider.pub, rPub)
	if out := s.Handle(h, outsider.addr); len(out) != 0 {
		t.Fatal("relay welcomed a node the controller does not know")
	}

	f, _ := Seal(a.sess, rPub, TypeSend, b.raw(t), []byte("to b"))
	out := s.Handle(f, a.addr)
	if len(out) != 1 || out[0].To != b.addr {
		t.Fatalf("frame a->b not forwarded to b: %v", out)
	}
	typ, src, payload, err := Open(b.sess, out[0].Data)
	if err != nil || typ != TypeRecv || src != a.raw(t) || !bytes.Equal(payload, []byte("to b")) {
		t.Fatalf("b got %v %v %q", err, typ, payload)
	}

	f, _ = Seal(a.sess, rPub, TypeSend, c.raw(t), []byte("to c"))
	if out := s.Handle(f, a.addr); len(out) != 0 {
		t.Fatal("relay forwarded between nodes without a shared room")
	}

	// A frame sealed with a guessed session key is ignored.
	fake, _ := NewSession()
	fake.ID = a.sess.ID
	f, _ = Seal(fake, rPub, TypeSend, b.raw(t), []byte("forged"))
	if out := s.Handle(f, outsider.addr); len(out) != 0 {
		t.Fatal("relay accepted a frame with the wrong session key")
	}

	// NAT rebinding: a's address changes, b's answer goes to the new one.
	a.addr = netip.AddrPortFrom(a.addr.Addr(), 9999)
	ping, _ := Seal(a.sess, rPub, TypePing, [NodeIDLen]byte{}, nil)
	s.Handle(ping, a.addr)
	f, _ = Seal(b.sess, rPub, TypeSend, a.raw(t), []byte("back"))
	auth.pairs[[2]string{b.id.NodeID(), a.id.NodeID()}] = true
	if out := s.Handle(f, b.addr); len(out) != 1 || out[0].To != a.addr {
		t.Fatalf("answer not sent to a's new address: %v", out)
	}
}
