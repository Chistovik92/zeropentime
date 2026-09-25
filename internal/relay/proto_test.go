// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"bytes"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/identity"
)

func discoKeys(t testing.TB) (priv, pub identity.Key) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id.DiscoKey()
}

func TestHandshake(t *testing.T) {
	rPriv, rPub := discoKeys(t)
	nPriv, nPub := discoKeys(t)
	_, otherPub := discoKeys(t)

	hello, err := Hello(nPriv, nPub, rPub)
	if err != nil {
		t.Fatal(err)
	}
	if !IsHello(hello, rPub) {
		t.Fatal("hello not recognised")
	}
	if IsHello(hello, otherPub) {
		t.Fatal("hello recognised by another relay")
	}
	got, err := OpenHello(hello, rPriv, rPub)
	if err != nil || got != nPub {
		t.Fatalf("open hello: %v", err)
	}

	s, _ := NewSession()
	w, err := Welcome(s, rPriv, nPub)
	if err != nil {
		t.Fatal(err)
	}
	if !IsWelcome(w, nPub) || IsWelcome(w, otherPub) {
		t.Fatal("welcome tag wrong")
	}
	back, err := OpenWelcome(w, nPriv, rPub)
	if err != nil || *back != *s {
		t.Fatalf("open welcome: %v", err)
	}
}

func TestHelloForgery(t *testing.T) {
	rPriv, rPub := discoKeys(t)
	_, victimPub := discoKeys(t)
	attackerPriv, _ := discoKeys(t)
	// The attacker names the victim's key but can only box with its own.
	forged, err := Hello(attackerPriv, victimPub, rPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHello(forged, rPriv, rPub); err == nil {
		t.Fatal("forged hello accepted")
	}
}

func TestFrames(t *testing.T) {
	_, rPub := discoKeys(t)
	s, _ := NewSession()
	other, _ := NewSession()
	node, _ := NodeIDBytes("abcdefghijklmnop")
	payload := []byte("awg packet")

	f1, err := Seal(s, rPub, TypeSend, node, payload)
	if err != nil {
		t.Fatal(err)
	}
	f2, _ := Seal(s, rPub, TypeSend, node, payload)
	if bytes.Equal(f1[:24], f2[:24]) {
		t.Fatal("frame headers repeat: session id visible on the wire")
	}
	id, ok := SessionID(f1, rPub)
	if !ok || id != s.ID {
		t.Fatal("session id not recovered")
	}
	typ, gotNode, got, err := Open(s, f1)
	if err != nil || typ != TypeSend || gotNode != node || !bytes.Equal(got, payload) {
		t.Fatalf("open: %v", err)
	}
	if _, _, _, err := Open(other, f1); err == nil {
		t.Fatal("frame opened with another session key")
	}
	bad := bytes.Clone(f1)
	bad[len(bad)-1] ^= 1
	if _, _, _, err := Open(s, bad); err == nil {
		t.Fatal("tampered frame accepted")
	}
}

func TestNodeIDRoundTrip(t *testing.T) {
	id, _ := identity.Generate()
	b, err := NodeIDBytes(id.NodeID())
	if err != nil || NodeIDString(b) != id.NodeID() {
		t.Fatalf("round trip: %v %q %q", err, NodeIDString(b), id.NodeID())
	}
	if _, err := NodeIDBytes("not-an-id"); err == nil {
		t.Fatal("bad id accepted")
	}
}

func FuzzOpen(f *testing.F) {
	_, rPub := discoKeys(f)
	rPriv, _ := discoKeys(f)
	s, _ := NewSession()
	node, _ := NodeIDBytes("abcdefghijklmnop")
	fr, _ := Seal(s, rPub, TypeSend, node, []byte("x"))
	f.Add(fr)
	f.Fuzz(func(t *testing.T, b []byte) {
		Open(s, b)
		SessionID(b, rPub)
		OpenHello(b, rPriv, rPub)
		OpenWelcome(b, rPriv, rPub)
	})
}
