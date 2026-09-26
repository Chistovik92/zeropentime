// SPDX-License-Identifier: MPL-2.0

package node

import (
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/identity"
)

func TestPeerCardVerify(t *testing.T) {
	id, _ := identity.Generate()
	other, _ := identity.Generate()
	_, disc := id.DiscoKey()
	now := time.Now()
	sign := func(c peerCard, by *identity.Identity) *peerCard {
		c.Sig = base64.StdEncoding.EncodeToString(by.Sign(c.signedPart()))
		return &c
	}
	good := peerCard{RoomID: "r1", NodeID: id.NodeID(), EdKey: base64.StdEncoding.EncodeToString(id.PublicKey()),
		Disco: disc, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}, Issued: now.Unix()}
	if err := sign(good, id).verify("r1", now); err != nil {
		t.Fatalf("good card: %v", err)
	}
	if sign(good, id).verify("r2", now) == nil {
		t.Error("card accepted for another room")
	}
	if sign(good, other).verify("r1", now) == nil {
		t.Error("card signed by another node accepted")
	}
	c := sign(good, id)
	c.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:1")}
	if c.verify("r1", now) == nil {
		t.Error("changed addresses accepted")
	}
	stolen := good
	stolen.EdKey = base64.StdEncoding.EncodeToString(other.PublicKey())
	if sign(stolen, other).verify("r1", now) == nil {
		t.Error("card for someone else's node ID accepted")
	}
	old := good
	old.Issued = now.Add(-3 * time.Hour).Unix()
	if sign(old, id).verify("r1", now) == nil {
		t.Error("stale card accepted")
	}
}
