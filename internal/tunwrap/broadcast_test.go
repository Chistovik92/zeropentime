// SPDX-License-Identifier: MPL-2.0

package tunwrap

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// fakeTUN feeds packets to Read and records Write.
type fakeTUN struct {
	toRead  [][]byte
	written [][]byte
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1380, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 4 }
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for n < len(bufs) && len(f.toRead) > 0 {
		sizes[n] = copy(bufs[n][offset:], f.toRead[0])
		f.toRead = f.toRead[1:]
		n++
	}
	return n, nil
}
func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, bytes.Clone(b[offset:]))
	}
	return len(bufs), nil
}

// udp builds an IPv4 UDP packet.
func udp(src, dst string, dport uint16, payload string) []byte {
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

const offset = 16

func readAll(t *testing.T, d *Device) [][]byte {
	var out [][]byte
	for range 10 {
		bufs := make([][]byte, 4)
		for i := range bufs {
			bufs[i] = make([]byte, 2048)
		}
		sizes := make([]int, 4)
		n, err := d.Read(bufs, sizes, offset)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		for i := range n {
			out = append(out, bytes.Clone(bufs[i][offset:offset+sizes[i]]))
		}
	}
	return out
}

func room(t *testing.T, self string, mode string, inbound ...[]byte) (*Device, *fakeTUN) {
	f := &fakeTUN{toRead: inbound}
	d := New(f, netip.MustParsePrefix(self), mode)
	d.SetPeers([]netip.Addr{netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("10.9.0.3")})
	return d, f
}

func TestBroadcastRoundTrip(t *testing.T) {
	unicast := udp("10.9.0.1", "10.9.0.2", 80, "plain")
	games := udp("10.9.0.1", "10.9.0.255", 27015, "who is hosting?")
	mdns := udp("10.9.0.1", "224.0.0.251", 5353, "mdns query")
	sender, _ := room(t, "10.9.0.1/24", ModeOn, unicast, games, mdns)

	got := readAll(t, sender)
	// unicast passes as is; each broadcast becomes one packet per peer.
	if len(got) != 1+2+2 || !bytes.Equal(got[0], unicast) {
		t.Fatalf("read %d packets", len(got))
	}
	wrapped := got[1] // games -> 10.9.0.2
	if checksum(wrapped[:20]) != 0 {
		t.Fatal("bad IPv4 header checksum")
	}

	// The receiver (10.9.0.2) gets back exactly the original broadcast.
	receiver, rf := room(t, "10.9.0.2/24", ModeOn)
	receiver.Write([][]byte{append(make([]byte, offset), wrapped...)}, offset)
	if len(rf.written) != 1 || !bytes.Equal(rf.written[0], games) {
		t.Fatalf("receiver got %x", rf.written)
	}
}

func TestSpoofedAndBadWrapsDropped(t *testing.T) {
	sender, _ := room(t, "10.9.0.1/24", ModeOn, udp("10.9.0.1", "255.255.255.255", 9, "x"))
	wrapped := readAll(t, sender)[0]
	receiver, rf := room(t, "10.9.0.2/24", ModeOn)

	spoof := bytes.Clone(wrapped)
	copy(spoof[32+12:32+16], []byte{10, 9, 0, 3}) // inner source: another member
	unicastInside := bytes.Clone(wrapped)
	copy(unicastInside[32+16:32+20], []byte{10, 9, 0, 2}) // inner is not a broadcast
	for _, p := range [][]byte{spoof, unicastInside} {
		receiver.Write([][]byte{append(make([]byte, offset), p...)}, offset)
	}
	if len(rf.written) != 0 {
		t.Fatalf("accepted %d bad wrapped packets", len(rf.written))
	}
}

func TestModesAndRateLimit(t *testing.T) {
	games := udp("10.9.0.1", "10.9.0.255", 27015, "x")
	mdns := udp("10.9.0.1", "224.0.0.251", 5353, "y")

	// Not forwarded packets go to AmneziaWG unchanged, which drops them (no
	// peer owns a broadcast address); count only wrapped ones.
	off, _ := room(t, "10.9.0.1/24", ModeOff, games, mdns)
	if got := wrappedCount(readAll(t, off)); got != 0 {
		t.Fatalf("mode off wrapped %d packets", got)
	}
	onlyMDNS, _ := room(t, "10.9.0.1/24", ModeMDNS, games, mdns)
	if got := wrappedCount(readAll(t, onlyMDNS)); got != 2 { // mdns to 2 peers
		t.Fatalf("mode mdns wrapped %d packets", got)
	}

	var storm [][]byte
	for range MaxPPS * 3 {
		storm = append(storm, games)
	}
	flood, _ := room(t, "10.9.0.1/24", ModeOn, storm...)
	if got := wrappedCount(readAll(t, flood)); got > MaxPPS*2 {
		t.Fatalf("storm not limited: %d packets", got)
	}
}

func wrappedCount(pkts [][]byte) int {
	n := 0
	for _, p := range pkts {
		if len(p) >= wrapHdr && binary.BigEndian.Uint16(p[22:24]) == Port && [4]byte(p[28:32]) == magic {
			n++
		}
	}
	return n
}
