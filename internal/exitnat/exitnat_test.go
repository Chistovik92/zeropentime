// SPDX-License-Identifier: MPL-2.0

package exitnat

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// lab wires a client network stack (a room member) to a NAT whose Dial
// reaches local test servers instead of the internet.
func lab(t *testing.T, o Options, tcpSrv, udpSrv string) *netstack.Net {
	t.Helper()
	dev, cnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	o.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		if network == "tcp4" {
			return d.DialContext(ctx, "tcp", tcpSrv)
		}
		return d.DialContext(ctx, "udp", udpSrv)
	}
	nat, err := New(func(pkt []byte) { dev.Write([][]byte{pkt}, 0) }, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nat.Close(); dev.Close() })
	go func() {
		bufs := [][]byte{make([]byte, 2000)}
		sizes := []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				nat.Inbound(bufs[0][:sizes[0]])
			}
		}
	}()
	return cnet
}

func echoServers(t *testing.T) (string, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); pc.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	go func() {
		buf := make([]byte, 2000)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], a)
		}
	}()
	return ln.Addr().String(), pc.LocalAddr().String()
}

func TestTCPAndUDP(t *testing.T) {
	tcpSrv, udpSrv := echoServers(t)
	cnet := lab(t, Options{Allow: func(a netip.Addr) bool { return a != netip.MustParseAddr("192.168.1.1") }}, tcpSrv, udpSrv)

	c, err := cnet.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("198.51.100.7:80"))
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("zeropentime "), 5000)
	go c.Write(msg)
	got := make([]byte, len(msg))
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("tcp echo: %v", err)
	}
	c.Close()

	u, err := cnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("198.51.100.7:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(10 * time.Second))
	u.Write([]byte("ping"))
	buf := make([]byte, 100)
	if n, err := u.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("udp echo: %q %v", buf[:n], err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := cnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("192.168.1.1:80")); err == nil {
		c.Close()
		t.Fatal("reached a forbidden destination")
	}
}

func TestRateLimit(t *testing.T) {
	tcpSrv, udpSrv := echoServers(t)
	const limit = 200 << 10 // 200 KiB/s in each direction
	cnet := lab(t, Options{PerClient: limit}, tcpSrv, udpSrv)
	c, err := cnet.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("198.51.100.7:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := make([]byte, 400<<10) // 400 KiB each way at 200 KiB/s
	start := time.Now()
	go c.Write(msg)
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, len(msg))); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 1500*time.Millisecond {
		t.Fatalf("400 KiB took %s: limit not applied", d)
	}
}
