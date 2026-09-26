// SPDX-License-Identifier: MPL-2.0

package acl

import (
	"net/netip"
	"testing"
)

var (
	game  = netip.MustParseAddr("10.1.1.10")
	guest = netip.MustParseAddr("10.1.1.20")
	admin = netip.MustParseAddr("10.1.1.30")
)

func policy(t *testing.T, text string) *Policy {
	t.Helper()
	rules, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return &Policy{Rules: rules, Subnet: netip.MustParsePrefix("10.1.1.0/24"), Members: []Member{
		{Name: "game-server", IP: game, Tags: []string{"game"}},
		{Name: "guest-pc", IP: guest, Tags: []string{"guest"}},
		{Name: "admin", IP: admin},
	}}
}

func TestGuestsOnlyGameServer(t *testing.T) {
	p := policy(t, `
# гости — только на игровой сервер
allow tag:guest -> tag:game tcp:27015 udp:27015-27030
allow admin -> *
`)
	cases := []struct {
		src, dst netip.Addr
		proto    int
		port     uint16
		want     bool
	}{
		{guest, game, UDP, 27020, true},
		{guest, game, TCP, 27015, true},
		{guest, game, TCP, 22, false},
		{guest, admin, TCP, 445, false},
		{guest, netip.MustParseAddr("8.8.8.8"), UDP, 53, false},
		{admin, guest, TCP, 3389, true},
		{admin, netip.MustParseAddr("1.1.1.1"), ICMP, 0, true},
		{game, guest, UDP, 27015, false},
	}
	for _, c := range cases {
		if got, _ := p.Allowed(c.src, c.dst, c.proto, c.port); got != c.want {
			t.Errorf("%s -> %s proto %d port %d: %v, want %v", c.src, c.dst, c.proto, c.port, got, c.want)
		}
	}
}

func TestInternetAndNetworks(t *testing.T) {
	p := policy(t, "allow tag:guest -> internet\nallow * -> 192.168.1.0/24 icmp")
	if ok, _ := p.Allowed(guest, netip.MustParseAddr("93.184.216.34"), TCP, 443); !ok {
		t.Error("guest to the internet")
	}
	if ok, _ := p.Allowed(guest, game, TCP, 443); ok {
		t.Error("internet must not include room members")
	}
	if ok, _ := p.Allowed(admin, netip.MustParseAddr("192.168.1.1"), ICMP, 0); !ok {
		t.Error("ping to the LAN")
	}
	if ok, _ := p.Allowed(admin, netip.MustParseAddr("192.168.1.1"), TCP, 80); ok {
		t.Error("only icmp to the LAN")
	}
}

func TestNoRulesAllowsAll(t *testing.T) {
	if ok, _ := (&Policy{}).Allowed(guest, game, TCP, 1); !ok {
		t.Fatal("no rules must allow all")
	}
}

func TestParseErrorsAndRoundTrip(t *testing.T) {
	for _, bad := range []string{"deny a -> b", "allow a b", "allow internet -> a", "allow a -> b tcp:99999", "allow a -> b sctp:1", "allow a -> 10.0.0.0/33"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	text := "allow tag:guest,bob -> tag:game tcp:27015 udp:27015-27030 icmp\nallow * -> internet tcp:*\n"
	rules, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if got := String(rules); got != text {
		t.Fatalf("round trip:\n%s\nwant\n%s", got, text)
	}
}

// ipv4 builds a minimal IPv4 packet with TCP/UDP ports.
func ipv4(proto uint8, src, dst netip.Addr, sport, dport uint16) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[9] = proto
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	p[20], p[21] = byte(sport>>8), byte(sport)
	p[22], p[23] = byte(dport>>8), byte(dport)
	return p
}

func TestFilterStateful(t *testing.T) {
	p := policy(t, "allow tag:guest -> tag:game udp:27015")
	f := NewFilter(p, admin) // admin: nothing may reach it by the rules
	if f.Inbound(ipv4(TCP, guest, admin, 40000, 22)) {
		t.Fatal("guest reached admin")
	}
	// admin connects to the guest: the reply passes.
	f.Outbound(ipv4(TCP, admin, guest, 50000, 80))
	if !f.Inbound(ipv4(TCP, guest, admin, 80, 50000)) {
		t.Fatal("reply to our own connection dropped")
	}
	if f.Inbound(ipv4(TCP, guest, admin, 80, 50001)) {
		t.Fatal("unrelated packet passed as a reply")
	}
	g := NewFilter(p, game)
	if !g.Inbound(ipv4(UDP, guest, game, 40000, 27015)) {
		t.Fatal("allowed game traffic dropped")
	}
	// A broadcast from the guest reaches the game server if the rule allows it there.
	if !g.Inbound(ipv4(UDP, guest, netip.MustParseAddr("255.255.255.255"), 40000, 27015)) {
		t.Fatal("LAN game discovery dropped")
	}
}
