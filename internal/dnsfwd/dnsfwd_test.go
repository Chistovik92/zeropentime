// SPDX-License-Identifier: MPL-2.0

package dnsfwd

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeDNS answers every query with the query plus a marker, over UDP and TCP.
func fakeDNS(t *testing.T) netip.AddrPort {
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := u.LocalAddr().(*net.UDPAddr).Port
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close(); l.Close() })
	go func() {
		buf := make([]byte, 2000)
		for {
			n, src, err := u.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			u.WriteToUDPAddrPort(append(append([]byte(nil), buf[:n]...), "udp"...), src)
		}
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if q, err := readMsg(c); err == nil {
				writeMsg(c, append(q, "tcp"...))
			}
			c.Close()
		}
	}()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

func TestForward(t *testing.T) {
	up := fakeDNS(t)
	// Nothing listens here over TCP: the forwarder moves on to the next upstream.
	dead := netip.MustParseAddrPort("127.0.0.1:1")
	f, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), func() []netip.AddrPort { return []netip.AddrPort{dead, up} }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	q := []byte("\x12\x34query-header-and-question")

	c, err := net.Dial("udp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write(q)
	buf := make([]byte, 2000)
	n, err := c.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], append(q, "udp"...)) {
		t.Fatalf("udp: %q %v", buf[:n], err)
	}

	tc, err := net.Dial("tcp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	writeMsg(tc, q)
	resp, err := readMsg(tc)
	if err != nil || !bytes.Equal(resp, append(q, "tcp"...)) {
		t.Fatalf("tcp: %q %v", resp, err)
	}
}

func TestSystemUpstreams(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(p, []byte("# comment\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nsearch lan\nnameserver bad\n"), 0o644)
	got := SystemUpstreams(p)
	if len(got) != 2 || got[0].String() != "127.0.0.53:53" || got[1].Addr().Zone() != "" {
		t.Fatalf("got %v", got)
	}
}
