package pki

import (
	"crypto/ed25519"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

func testConfig(t *testing.T) *RoomConfig {
	s, _ := obfs.NewSecret()
	id, _ := identity.Generate()
	k, _ := id.RoomKey(s.RoomID())
	return &RoomConfig{
		RoomID: s.RoomID(), Name: "game", Subnet: netip.MustParsePrefix("10.100.1.0/24"), Secret: s, Version: 3,
		Members: []Member{{NodeID: id.NodeID(), Name: "a", WGKey: k.Public(), IP: netip.MustParseAddr("10.100.1.1")}},
	}
}

func TestRoomConfigSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	c := testConfig(t)
	s, err := SignRoomConfig(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyRoomConfig(pub, s)
	if err != nil || got.Version != 3 || got.Members[0].IP != c.Members[0].IP {
		t.Fatalf("verify: %v %+v", err, got)
	}
	if _, err := VerifyRoomConfig(otherPub, s); err == nil {
		t.Fatal("accepted config signed by another key")
	}
	tampered := *s
	tampered.Payload = append([]byte(nil), s.Payload...)
	tampered.Payload[len(tampered.Payload)-3] ^= 1
	if _, err := VerifyRoomConfig(pub, &tampered); err == nil {
		t.Fatal("accepted tampered config")
	}

	bad := testConfig(t)
	bad.Members[0].IP = netip.MustParseAddr("10.200.0.1")
	s, _ = SignRoomConfig(priv, bad)
	if _, err := VerifyRoomConfig(pub, s); err == nil {
		t.Fatal("accepted member outside subnet")
	}
}

func TestRequestSignature(t *testing.T) {
	id, _ := identity.Generate()
	now := time.Now()
	body := []byte(`{"x":1}`)
	h := http.Header{}
	for k, v := range RequestHeaders(id, "POST", "/api/v1/join", body, now) {
		h.Set(k, v)
	}
	pub, err := VerifyRequest(h.Get, "POST", "/api/v1/join", body, now)
	if err != nil || identity.NodeIDFromPublic(pub) != id.NodeID() {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyRequest(h.Get, "POST", "/api/v1/join", []byte(`{"x":2}`), now); err == nil {
		t.Fatal("accepted modified body")
	}
	if _, err := VerifyRequest(h.Get, "POST", "/api/v1/other", body, now); err == nil {
		t.Fatal("accepted other path")
	}
	if _, err := VerifyRequest(h.Get, "POST", "/api/v1/join", body, now.Add(10*time.Minute)); err == nil {
		t.Fatal("accepted stale request")
	}
}

func TestSealOpen(t *testing.T) {
	id, _ := identity.Generate()
	other, _ := identity.Generate()
	priv, pub := id.BoxKey()
	sealed, err := Seal([]byte("room secret"), pub)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Open(sealed, priv, pub)
	if err != nil || string(msg) != "room secret" {
		t.Fatalf("open: %v %q", err, msg)
	}
	opriv, opub := other.BoxKey()
	if _, err := Open(sealed, opriv, opub); err == nil {
		t.Fatal("another node decrypted the message")
	}
}
