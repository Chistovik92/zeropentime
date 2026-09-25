// SPDX-License-Identifier: MPL-2.0

package stun

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	for _, s := range []string{"203.0.113.7:40000", "[2001:db8::42]:1"} {
		addr := netip.MustParseAddrPort(s)
		id := NewTxID()
		req := Request(id)
		if !Is(req) {
			t.Fatal("request not recognised")
		}
		gotID, err := ParseRequest(req)
		if err != nil || gotID != id {
			t.Fatalf("parse request: %v", err)
		}
		respID, mapped, err := ParseResponse(Response(id, addr))
		if err != nil || respID != id || mapped != addr {
			t.Fatalf("%s: got %v %v %v", s, respID == id, mapped, err)
		}
	}
}

// A captured response from a well-known public STUN server (RFC 5769 test
// vector 2.2: IPv4 XOR-MAPPED-ADDRESS 192.0.2.1:32853).
func TestRFC5769Vector(t *testing.T) {
	msg := []byte{
		0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
		0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
		0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
		0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9,
		0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
	}
	_, mapped, err := ParseResponse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("192.0.2.1:32853"); mapped != want {
		t.Fatalf("mapped %v, want %v", mapped, want)
	}
}

func TestIsRejectsTunnelTraffic(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 19), append([]byte{'z'}, make([]byte, 40)...), make([]byte, 40)} {
		if Is(b) {
			t.Errorf("%x recognised as STUN", b)
		}
	}
	bad := Request(NewTxID())
	bad[3] = 200 // length beyond the packet
	if Is(bad) {
		t.Error("truncated message recognised")
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add(Response(NewTxID(), netip.MustParseAddrPort("1.2.3.4:5")))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseResponse(b)
		ParseRequest(b)
	})
}

func TestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	go Serve(ctx, []string{addr}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv := netip.MustParseAddrPort(addr)
	id := NewTxID()
	buf := make([]byte, MaxMessage)
	for i := 0; i < 20; i++ { // the server may not be listening yet
		c.WriteToUDPAddrPort(Request(id), srv)
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			continue
		}
		gotID, mapped, err := ParseResponse(buf[:n])
		if err != nil || gotID != id {
			t.Fatalf("bad response: %v", err)
		}
		if mapped != c.LocalAddr().(*net.UDPAddr).AddrPort() {
			t.Fatalf("mapped %v, want %v", mapped, c.LocalAddr())
		}
		return
	}
	t.Fatal("no response from server")
}

func itoa(i int) string {
	return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(i)).String()[len("0.0.0.0:"):]
}
