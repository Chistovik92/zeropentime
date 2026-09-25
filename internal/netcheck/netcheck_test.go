// SPDX-License-Identifier: MPL-2.0

package netcheck

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/magicsock"
	"github.com/Chistovik92/zeropentime/internal/stun"
)

// fakeNAT answers like a NAT would: mapping decides the external address
// for a given destination; nil means the packet is lost.
type fakeNAT func(server netip.AddrPort) *netip.AddrPort

func (f fakeNAT) STUN(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	if m := f(server); m != nil {
		return *m, nil
	}
	<-ctx.Done()
	return netip.AddrPort{}, errors.New("timeout")
}

var (
	srvA  = netip.MustParseAddrPort("198.51.100.1:3478")
	srvA2 = netip.MustParseAddrPort("198.51.100.1:3479")
	srvB  = netip.MustParseAddrPort("198.51.100.2:3478")
	ext   = netip.MustParseAddr("203.0.113.9")
)

func ptr(a netip.AddrPort) *netip.AddrPort { return &a }

func TestClassification(t *testing.T) {
	defer func(d time.Duration) { Timeout = d }(Timeout)
	Timeout = 300 * time.Millisecond
	local := []netip.Addr{netip.MustParseAddr("192.168.1.10")}
	cases := []struct {
		name    string
		nat     fakeNAT
		servers []netip.AddrPort
		want    string
	}{
		{"cone", func(netip.AddrPort) *netip.AddrPort { return ptr(netip.AddrPortFrom(ext, 40000)) }, []netip.AddrPort{srvA, srvA2}, NATCone},
		{"symmetric", func(s netip.AddrPort) *netip.AddrPort { return ptr(netip.AddrPortFrom(ext, 40000+s.Port())) }, []netip.AddrPort{srvA, srvA2}, NATSymmetric},
		{"blocked", func(netip.AddrPort) *netip.AddrPort { return nil }, []netip.AddrPort{srvA, srvB}, NATBlocked},
		{"one answer", func(s netip.AddrPort) *netip.AddrPort {
			if s == srvA {
				return ptr(netip.AddrPortFrom(ext, 40000))
			}
			return nil
		}, []netip.AddrPort{srvA, srvB}, NATUnknown},
		{"public ip", func(netip.AddrPort) *netip.AddrPort { return ptr(netip.MustParseAddrPort("192.168.1.10:4790")) }, []netip.AddrPort{srvA, srvA2}, NATNone},
		{"no servers", nil, nil, NATUnknown},
	}
	for _, c := range cases {
		r := Check(context.Background(), c.nat, c.servers, 4790, local)
		if r.NAT != c.want {
			t.Errorf("%s: NAT %q, want %q (mapped %v)", c.name, r.NAT, c.want, r.Mapped)
		}
	}
}

// End to end: a real STUN server on two ports and the node socket.
func TestCheckThroughMagicsock(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var addrs []string
	for range 2 {
		c, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		addrs = append(addrs, c.LocalAddr().String())
		c.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go stun.Serve(ctx, addrs, log)

	sock, err := magicsock.Listen(0, log)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	servers := Resolve(ctx, addrs)
	r := Check(ctx, sock, servers, sock.Port(), append(LocalAddrs(), netip.MustParseAddr("127.0.0.1")))
	if r.NAT != NATNone || len(r.Mapped) != 1 || r.Mapped[0].Port() != sock.Port() {
		t.Fatalf("report %+v, want NAT none at port %d", r, sock.Port())
	}
}

func TestSpoofedAnswerIgnored(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sock, err := magicsock.Listen(0, log)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	// A "server" that never answers, and an attacker who answers every
	// transaction ID it can guess from another address: we cannot guess
	// the random ID, so send a well-formed response with a fresh ID.
	silent, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer silent.Close()
	attacker, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer attacker.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500e6)
	defer cancel()
	go func() {
		// Relay the real request's transaction ID, but answer from the wrong address.
		buf := make([]byte, 512)
		n, _, err := silent.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		id, _ := stun.ParseRequest(buf[:n])
		attacker.WriteToUDPAddrPort(stun.Response(id, netip.MustParseAddrPort("6.6.6.6:666")),
			netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), sock.Port()))
	}()
	if m, err := sock.STUN(ctx, silent.LocalAddr().(*net.UDPAddr).AddrPort()); err == nil {
		t.Fatalf("accepted an answer from the wrong address: %v", m)
	}
}
