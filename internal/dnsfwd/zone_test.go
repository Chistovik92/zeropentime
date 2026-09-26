// SPDX-License-Identifier: MPL-2.0

package dnsfwd

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func ask(t *testing.T, srv netip.AddrPort, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x7a70, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	c, err := net.Dial("udp", srv.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(q)
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestZone(t *testing.T) {
	f, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), func(netip.Addr) []netip.AddrPort { return nil }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.SetZone(&Zone{Name: "dom.zpt", Records: map[string]netip.Addr{"laptop": netip.MustParseAddr("10.1.1.2")}})

	m := ask(t, f.Addr(), "LapTop.dom.zpt.", dnsmessage.TypeA)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 1, 1, 2} {
		t.Fatalf("laptop: %+v", m)
	}
	if m := ask(t, f.Addr(), "laptop.dom.zpt.", dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("AAAA must be empty: %+v", m)
	}
	if m := ask(t, f.Addr(), "nobody.dom.zpt.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unknown name: %v", m.RCode)
	}
	// Not our zone and no upstreams for this sender: refused, not forwarded.
	if m := ask(t, f.Addr(), "example.com.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("foreign name: %v", m.RCode)
	}
}

func TestLabel(t *testing.T) {
	for in, want := range map[string]string{"Домашний сервер": "domashniy-server", "Laptop_Ivan": "laptop-ivan", "--x--": "x"} {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
}
